"""pydecomp - aliases.

Three families of dressing-up that make Python *look* unlike Python:

* unicode aliases - ``ᐁ = alias`` then a wall of ``ᐁ(...)`` (an IOPCC favourite),
  plus unicode identifiers generally, which no reader can diff or grep;
* indirection through the builtins namespace - ``getattr(__builtins__, 'ev'+'al')``,
  ``vars()['__builtins__']['exec']``, ``__import__('base64').b64decode``;
* self-hosting - ``exec(unparse(fix_missing_locations(eval(__doc__))))`` where the
  real program is the module docstring.

Everything here is a *reading* aid: aliases are resolved to the name they point
at, unicode identifiers are transliterated (a legend is emitted), dynamic
builtin lookups become the plain name, and ``__import__('x').f`` becomes
``x.f``.  None of it changes what the program does.
"""
from __future__ import annotations

import unicodedata

from ..polish.demangle import _ast

_BUILTINS = {
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes", "callable",
    "chr", "classmethod", "compile", "complex", "delattr", "dict", "dir", "divmod",
    "enumerate", "eval", "exec", "filter", "float", "format", "frozenset",
    "getattr", "globals", "hasattr", "hash", "help", "hex", "id", "input", "int",
    "isinstance", "issubclass", "iter", "len", "list", "locals", "map", "max",
    "memoryview", "min", "next", "object", "oct", "open", "ord", "pow", "print",
    "property", "range", "repr", "reversed", "round", "set", "setattr", "slice",
    "sorted", "staticmethod", "str", "sum", "super", "tuple", "type", "vars", "zip",
}


def _is_ascii(name: str) -> bool:
    return all(ord(char) < 128 for char in name)


def _transliterate(name: str) -> str | None:
    """Best-effort ASCII spelling of a unicode identifier."""
    folded = unicodedata.normalize("NFKD", name)
    ascii_chars = "".join(char for char in folded if ord(char) < 128)
    ascii_chars = "".join(char if (char.isalnum() or char == "_") else "_"
                          for char in ascii_chars)
    ascii_chars = ascii_chars.strip("_")
    if not ascii_chars:
        return None
    if ascii_chars[0].isdigit():
        ascii_chars = "v" + ascii_chars
    return ascii_chars


class _AliasPass(_ast.NodeTransformer):
    def __init__(self):
        self.renamed: dict[str, str] = {}
        self.legend: dict[str, str] = {}
        self.changed = 0
        self._blocked: set[str] = set()

    # -- discovery -----------------------------------------------------
    def _collect(self, tree):
        bound_count: dict[str, int] = {}
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                 _ast.ClassDef)):
                bound_count[node.name] = bound_count.get(node.name, 0) + 1
            elif isinstance(node, _ast.Assign):
                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        bound_count[target.id] = bound_count.get(target.id, 0) + 1
            elif isinstance(node, (_ast.AnnAssign, _ast.AugAssign)):
                if isinstance(node.target, _ast.Name):
                    bound_count[node.target.id] = bound_count.get(node.target.id, 0) + 1
            elif isinstance(node, _ast.arg):
                bound_count[node.arg] = bound_count.get(node.arg, 0) + 1
            elif isinstance(node, (_ast.Import, _ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    bound_count[local] = bound_count.get(local, 0) + 1
            elif isinstance(node, (_ast.Global, _ast.Nonlocal)):
                for name in node.names:
                    bound_count[name] = bound_count.get(name, 0) + 1
        return bound_count

    def _simple_aliases(self, tree, bound_count):
        """`x = y` where y is a plain name and x is bound exactly once."""
        for node in _ast.walk(tree):
            if not (isinstance(node, _ast.Assign) and len(node.targets) == 1):
                continue
            target = node.targets[0]
            if not isinstance(target, _ast.Name):
                continue
            if bound_count.get(target.id, 0) != 1:
                continue
            source = node.value
            if isinstance(source, _ast.Name):
                if bound_count.get(source.id, 0) == 1 and not _is_ascii(source.id):
                    continue
                self.renamed[target.id] = source.id
            elif isinstance(source, _ast.Attribute) and isinstance(source.value, _ast.Name):
                dotted = f"{source.value.id}.{source.attr}"
                self.renamed[target.id] = dotted
            elif isinstance(source, _ast.Call) and _is_import_call(source):
                module = source.args[0].value
                self.renamed[target.id] = module

    def _unicode_names(self, tree):
        """Give every remaining non-ASCII identifier a spellable ASCII name."""
        existing = {node.id for node in _ast.walk(tree) if isinstance(node, _ast.Name)}
        existing |= {node.name for node in _ast.walk(tree)
                     if isinstance(node, (_ast.FunctionDef, _ast.ClassDef,
                                          _ast.AsyncFunctionDef))}
        counter = 0
        for node in _ast.walk(tree):
            names = []
            if isinstance(node, _ast.Name):
                names = [node.id]
            elif isinstance(node, _ast.arg):
                names = [node.arg]
            elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                names = [node.name]
            for name in names:
                if name in self.renamed and "." in self.renamed[name]:
                    # an alias for a dotted name: keep the binding, spell the
                    # identifier in ASCII so it can be read and grepped
                    candidate = _transliterate(name) or f"alias_{len(self.legend) + 1}"
                    while candidate in existing:
                        candidate += "_"
                    existing.add(candidate)
                    self.renamed[name] = candidate
                    self.legend[name] = candidate
                    continue
                if _is_ascii(name) or name in self.renamed:
                    continue
                candidate = _transliterate(name)
                if not candidate or candidate in existing:
                    counter += 1
                    candidate = f"name_{counter}"
                while candidate in existing:
                    counter += 1
                    candidate = f"{_transliterate(name) or 'name'}_{counter}"
                existing.add(candidate)
                self.renamed[name] = candidate
                self.legend[name] = candidate

    # -- rewriting -----------------------------------------------------
    def visit_Assign(self, node):                          # noqa: N802
        node = self.generic_visit(node)
        # `alias = alias` is what an alias resolution leaves behind
        if len(node.targets) == 1 and isinstance(node.targets[0], _ast.Name) \
                and isinstance(node.value, _ast.Name) \
                and node.targets[0].id == node.value.id:
            self.changed += 1
            return None
        return node

    def visit_Name(self, node):                            # noqa: N802
        replacement = self.renamed.get(node.id)
        if replacement and "." not in replacement:
            self.changed += 1
            return _ast.copy_location(_ast.Name(id=replacement, ctx=node.ctx), node)
        return node

    def visit_arg(self, node):                             # noqa: N802
        replacement = self.renamed.get(node.arg)
        if replacement and "." not in replacement:
            node.arg = replacement
            self.changed += 1
        return node

    def visit_FunctionDef(self, node):                     # noqa: N802
        replacement = self.renamed.get(node.name)
        if replacement and "." not in replacement:
            node.name = replacement
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):                        # noqa: N802
        replacement = self.renamed.get(node.name)
        if replacement and "." not in replacement:
            node.name = replacement
        return self.generic_visit(node)

    def visit_Attribute(self, node):                       # noqa: N802
        node = self.generic_visit(node)
        if _is_import_call(node.value):
            module = node.value.args[0].value.split(".")[0]
            base = _ast.copy_location(_ast.Name(id=module, ctx=_ast.Load()), node.value)
            self.changed += 1
            return _ast.copy_location(_ast.Attribute(value=base, attr=node.attr,
                                                     ctx=node.ctx), node)
        return node

    def visit_Call(self, node):                            # noqa: N802
        node = self.generic_visit(node)
        # getattr(__builtins__, 'eval')  ->  eval
        if isinstance(node.func, _ast.Name) and node.func.id == "getattr" \
                and len(node.args) == 2 and isinstance(node.args[0], _ast.Name) \
                and node.args[0].id in ("__builtins__", "builtins") \
                and isinstance(node.args[1], _ast.Constant) \
                and isinstance(node.args[1].value, str) \
                and node.args[1].value in _BUILTINS:
            self.changed += 1
            return _ast.copy_location(_ast.Name(id=node.args[1].value, ctx=_ast.Load()),
                                      node)
        if isinstance(node.func, _ast.Attribute) and _is_import_call(node.func.value):
            module = node.func.value.args[0].value.split(".")[0]
            base = _ast.copy_location(_ast.Name(id=module, ctx=_ast.Load()),
                                      node.func.value)
            func = _ast.copy_location(_ast.Attribute(value=base, attr=node.func.attr,
                                                     ctx=_ast.Load()), node.func)
            self.changed += 1
            return _ast.copy_location(_ast.Call(func=func, args=node.args,
                                                keywords=node.keywords), node)
        return node


def _is_import_call(node) -> bool:
    return (isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name)
            and node.func.id == "__import__" and len(node.args) == 1
            and isinstance(node.args[0], _ast.Constant)
            and isinstance(node.args[0].value, str))


def _lookup_builtins(node):
    """`vars()['__builtins__']['exec']` -> 'exec' (the name only)."""
    if not isinstance(node, _ast.Subscript):
        return None
    key = node.slice
    if not (isinstance(key, _ast.Constant) and isinstance(key.value, str)):
        return None
    if key.value in _BUILTINS and isinstance(node.value, _ast.Subscript):
        inner = node.value
        if isinstance(inner.value, _ast.Call) and isinstance(inner.value.func, _ast.Name) \
                and inner.value.func.id == "vars":
            return key.value
        if isinstance(inner.value, _ast.Name) and inner.value.id == "__builtins__":
            return key.value
    return None


def normalize_aliases(tree) -> tuple[int, dict[str, str]]:
    """Resolve aliases and unicode identifiers.  Returns (changes, legend)."""
    try:
        if not isinstance(tree, _ast.Module):
            return 0, {}
        pass_ = _AliasPass()
        bound = pass_._collect(tree)
        pass_._simple_aliases(tree, bound)
        pass_._unicode_names(tree)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Subscript):
                builtin = _lookup_builtins(node)
                if builtin:
                    node.__class__ = _ast.Name
                    node.__dict__.clear()
                    node.__dict__.update(_ast.Name(id=builtin, ctx=_ast.Load()).__dict__)
                    pass_.changed += 1
        rebuilt = []
        for stmt in tree.body:
            result = pass_.visit(stmt)
            if result is None:
                continue
            if isinstance(result, list):
                rebuilt.extend(part for part in result if part is not None)
            else:
                rebuilt.append(result)
        tree.body = rebuilt
        return pass_.changed, pass_.legend
    except Exception:                                      # noqa: BLE001 - cosmetic
        return 0, {}


def selfdoc_payload(tree) -> list:
    """``exec(unparse(fix_missing_locations(eval(__doc__))))`` - the docstring *is*
    the program.  Returns the statements of the hidden program, or []."""
    try:
        doc = _ast.get_docstring(tree, clean=False)
        if not doc or len(doc) > 2_000_000:
            return []
        body = [stmt for stmt in tree.body
                if not (isinstance(stmt, _ast.Expr)
                        and isinstance(stmt.value, _ast.Constant)
                        and isinstance(stmt.value.value, str))]
        if not body or len(body) > 8:
            return []
        text = "\n".join(_ast.unparse(stmt) for stmt in body)
        if "__doc__" not in text:
            return []
        try:
            inner = _ast.parse(doc)
        except SyntaxError:
            return []
        if not inner.body or len(inner.body) > 20_000:
            return []
        return inner.body
    except Exception:                                      # noqa: BLE001 - cosmetic
        return []
