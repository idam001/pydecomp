"""pydecomp - folding."""
from __future__ import annotations

from dataclasses import dataclass, field
import ast
import base64
import binascii
import bz2
import codecs
import hashlib
import json
import lzma
import zlib

from ..terminal.color import step

class FoldLimit(Exception):
    """Raised when a node cannot be reduced to a constant."""

FOLD_BUILTINS = {
    "chr": chr, "ord": ord, "str": str, "int": int, "float": float, "bool": bool,
    "bytes": bytes, "bytearray": bytearray, "list": list, "tuple": tuple,
    "dict": dict, "set": set, "len": len, "abs": abs, "sum": sum, "min": min,
    "max": max, "sorted": sorted, "repr": repr, "hex": hex, "bin": bin, "oct": oct,
    "round": round, "any": any, "all": all, "divmod": divmod, "reversed": list,
    "enumerate": list, "range": list, "zip": list, "format": format, "ascii": ascii,
    "frozenset": frozenset, "complex": complex, "pow": pow,
    "map": map, "filter": filter, "zip": zip, "enumerate": enumerate,
}

FOLD_METHODS = {
    "join", "replace", "split", "rsplit", "strip", "lstrip", "rstrip", "lower",
    "upper", "title", "capitalize", "casefold", "swapcase", "encode", "decode",
    "zfill", "startswith", "endswith", "find", "rfind", "count", "index",
    "ljust", "rjust", "center", "splitlines", "partition", "rpartition", "format",
    "removeprefix", "removesuffix", "expandtabs", "isdigit", "isalpha", "isalnum",
    "hexdigest", "digest", "fromhex", "hexlify", "unhexlify", "to_bytes",
    "items", "keys", "values", "get", "copy", "reverse", "translate",
}

FOLD_MODULES = {
    "base64": {"b64decode", "b64encode", "b32decode", "b16decode", "a85decode",
               "urlsafe_b64decode", "urlsafe_b64encode", "b85decode"},
    "binascii": {"unhexlify", "hexlify", "a2b_base64", "b2a_base64", "crc32",
                 "a2b_hex", "b2a_hex"},
    "zlib": {"decompress", "compress", "crc32"},
    "lzma": {"decompress", "compress"},
    "bz2": {"decompress", "compress"},
    "codecs": {"decode", "encode"},
    "json": {"loads", "dumps"},
    "hashlib": {"sha256", "sha1", "sha224", "sha384", "sha512", "md5", "blake2b",
                "new"},
    "urllib": {"unquote", "quote", "unquote_plus", "quote_plus"},
    "binascii2": set(),
    "struct": set(),
    "re": set(),
}

FOLD_METHOD_MAX = 4_000_000

class Folder:
    """Evaluates the pure, side-effect-free part of a decompiled module.

    Only whitelisted builtins, whitelisted module functions and methods on
    basic values are allowed, each call is bounded, and nothing touches the
    filesystem, the network or the interpreter state of the sample.
    """

    def __init__(self, tree):
        self.tree = tree
        self.env = {}
        self.inline = {}
        self.steps = 0
        self.collect()

    # ------------------------------------------------------------- discovery
    def collect(self):
        funcs = {}
        # a name that is written more than once is a *variable*: substituting it
        # into a test or an expression would change what the program does
        writes = {}
        stack = [self.tree]
        while stack:
            node = stack.pop()
            if not isinstance(node, ast.AST):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                writes[node.id] = writes.get(node.id, 0) + 1
            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    stack.extend(item for item in value if isinstance(item, ast.AST))
                elif isinstance(value, ast.AST):
                    stack.append(value)
        self.mutable = {name for name, count in writes.items() if count != 1}
        for stmt in self.tree.body:
            if isinstance(stmt, ast.FunctionDef) and not stmt.decorator_list:
                funcs[stmt.name] = stmt
        self.functions = funcs
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Assign) and stmt.targets \
                    and isinstance(stmt.targets[0], ast.Name) \
                    and stmt.targets[0].id in getattr(self, "mutable", ()):
                continue
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    root = alias.name.split(".")[0]
                    if root in FOLD_MODULES:
                        self.env[alias.asname or root] = root
            elif isinstance(stmt, ast.ImportFrom) and stmt.module:
                root = stmt.module.split(".")[0]
                if root in FOLD_MODULES:
                    for alias in stmt.names:
                        self.env[alias.asname or alias.name] = f"{root}.{alias.name}"
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name):
                try:
                    self.env[stmt.targets[0].id] = self.evaluate(stmt.value, {})
                except (FoldLimit, Exception):       # noqa: BLE001 - optional
                    continue
            elif isinstance(stmt, ast.FunctionDef) and not stmt.args.args[1:] \
                    and not stmt.decorator_list:
                funcs[stmt.name] = stmt
        self.functions = funcs

    # ------------------------------------------------------------ evaluation
    def evaluate(self, node, env, depth=0):
        self.steps += 1
        if self.steps > 200_000 or depth > 24:
            raise FoldLimit("budget")
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if isinstance(env.get(node.id), str):
                return env[node.id]
            if node.id in env:
                return env[node.id]
            if node.id in self.env:
                return self.env[node.id]
            if node.id in FOLD_BUILTINS:
                return FOLD_BUILTINS[node.id]
            raise FoldLimit(node.id)
        if isinstance(node, ast.UnaryOp):
            value = self.evaluate(node.operand, env, depth + 1)
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return +value
            if isinstance(node.op, ast.Not):
                return not value
            if isinstance(node.op, ast.Invert):
                return ~value
            raise FoldLimit("unary")
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left, env, depth + 1)
            right = self.evaluate(node.right, env, depth + 1)
            table = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
                     ast.Mult: lambda a, b: a * b, ast.Div: lambda a, b: a / b,
                     ast.FloorDiv: lambda a, b: a // b, ast.Mod: lambda a, b: a % b,
                     ast.Pow: lambda a, b: a ** b, ast.LShift: lambda a, b: a << b,
                     ast.RShift: lambda a, b: a >> b, ast.BitOr: lambda a, b: a | b,
                     ast.BitXor: lambda a, b: a ^ b, ast.BitAnd: lambda a, b: a & b}
            for klass, fn in table.items():
                if isinstance(node.op, klass):
                    if klass is ast.Pow and abs(right) > 128:
                        raise FoldLimit("pow")
                    if klass is ast.Mult and isinstance(left, (str, bytes, list)) \
                            and len(left) * max(int(right), 0) > FOLD_METHOD_MAX:
                        raise FoldLimit("repeat")
                    return fn(left, right)
            raise FoldLimit("binop")
        if isinstance(node, ast.BoolOp):
            values = [self.evaluate(value, env, depth + 1) for value in node.values]
            if isinstance(node.op, ast.And):
                result = values[0]
                for value in values[1:]:
                    result = value if result else result
                return result
            result = values[0]
            for value in values[1:]:
                result = result if result else value
            return result
        if isinstance(node, ast.Compare):
            left = self.evaluate(node.left, env, depth + 1)
            for op, comparator in zip(node.ops, node.comparators):
                right = self.evaluate(comparator, env, depth + 1)
                if not _apply_compare(op, left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return (self.evaluate(node.body, env, depth + 1)
                    if self.evaluate(node.test, env, depth + 1)
                    else self.evaluate(node.orelse, env, depth + 1))
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    parts.append(str(self.evaluate(value.value, env, depth + 1)))
                else:
                    raise FoldLimit("fstring")
            return "".join(parts)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.evaluate(element, env, depth + 1) for element in node.elts]
            if isinstance(node, ast.List):
                return values
            if isinstance(node, ast.Tuple):
                return tuple(values)
            return set(values)
        if isinstance(node, ast.Dict):
            return {self.evaluate(key, env, depth + 1) if key is not None else None:
                    self.evaluate(value, env, depth + 1)
                    for key, value in zip(node.keys, node.values)}
        if isinstance(node, ast.Subscript):
            target = self.evaluate(node.value, env, depth + 1)
            key = node.slice
            if isinstance(key, ast.Slice):
                low = self.evaluate(key.lower, env, depth + 1) if key.lower else None
                high = self.evaluate(key.upper, env, depth + 1) if key.upper else None
                step = self.evaluate(key.step, env, depth + 1) if key.step else None
                return target[low:high:step]
            return target[self.evaluate(key, env, depth + 1)]
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension(node, env, depth)
        if isinstance(node, ast.Attribute):
            base = self.evaluate(node.value, env, depth + 1)
            if isinstance(base, str) and node.attr == "upper":
                return base.upper
            raise FoldLimit(f"attr {node.attr}")
        if isinstance(node, ast.Call):
            return self._call(node, env, depth)
        raise FoldLimit(type(node).__name__)

    def _comprehension(self, node, env, depth):
        results = []
        scope = dict(env)

        def walk(index, scope):
            if index >= len(node.generators):
                results.append(self.evaluate(node.elt, scope, depth + 1))
                return
            generator = node.generators[index]
            sequence = self.evaluate(generator.iter, scope, depth + 1)
            if not isinstance(sequence, (list, tuple, str, bytes, set, dict, range)):
                raise FoldLimit("iterable")
            items = list(sequence)[:20000]
            for item in items:
                inner = dict(scope)
                if not _bind(generator.target, item, inner):
                    raise FoldLimit("target")
                if all(self.evaluate(cond, inner, depth + 1) for cond in generator.ifs):
                    walk(index + 1, inner)

        walk(0, scope)
        if isinstance(node, ast.SetComp):
            return set(results)
        return results

    def _call(self, node, env, depth):
        args = [self.evaluate(arg, env, depth + 1) for arg in node.args]
        kwargs = {kw.arg: self.evaluate(kw.value, env, depth + 1)
                  for kw in node.keywords if kw.arg}
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self.functions:
                return self._inline(self.functions[func.id], args, kwargs, depth)
            marker = env.get(func.id) if isinstance(env.get(func.id), str) else \
                self.env.get(func.id) if isinstance(self.env.get(func.id), str) else None
            if marker and "." in marker:
                module_name, _, attribute = marker.partition(".")
                module = _pure_module(module_name)
                if module is not None and hasattr(module, attribute):
                    return _safe_call(getattr(module, attribute), args, kwargs)
            target = FOLD_BUILTINS.get(func.id)
            if target is not None:
                return _safe_call(target, args, kwargs)
            raise FoldLimit(func.id)
        if isinstance(func, ast.Attribute):
            base = self.evaluate(func.value, env, depth + 1)
            if isinstance(base, str) and func.attr in FOLD_MODULES.get(base, ()):
                module = _pure_module(base)
                if module is None:
                    raise FoldLimit(base)
                return _safe_call(getattr(module, func.attr), args, kwargs)
            if func.attr in FOLD_METHODS:
                method = getattr(base, func.attr, None)
                if method is not None:
                    return _safe_call(method, args, kwargs)
            raise FoldLimit(f"{type(base).__name__}.{func.attr}")
        raise FoldLimit("call")

    def _inline(self, func, args, kwargs, depth):
        """Run a tiny, straight-line local function on constant arguments."""
        if len(func.args.args) < len(args):
            raise FoldLimit("arity")
        scope = {}
        for index, argument in enumerate(func.args.args):
            if index < len(args):
                scope[argument.arg] = args[index]
            elif argument.arg in kwargs:
                scope[argument.arg] = kwargs[argument.arg]
            elif index - len(func.args.args) < len(func.args.defaults):
                scope[argument.arg] = self.evaluate(
                    func.args.defaults[index - len(func.args.args)], {}, depth + 1)
            else:
                raise FoldLimit("missing argument")
        for stmt in func.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                scope[stmt.targets[0].id] = self.evaluate(stmt.value, scope, depth + 1)
            elif isinstance(stmt, ast.Return):
                return self.evaluate(stmt.value, scope, depth + 1) \
                    if stmt.value is not None else None
            elif isinstance(stmt, ast.Expr):
                self.evaluate(stmt.value, scope, depth + 1)
            elif isinstance(stmt, ast.If):
                branch = stmt.body if self.evaluate(stmt.test, scope, depth + 1) \
                    else stmt.orelse
                for inner in branch:
                    if isinstance(inner, ast.Return):
                        return self.evaluate(inner.value, scope, depth + 1) \
                            if inner.value is not None else None
                    if isinstance(inner, ast.Assign) and isinstance(inner.targets[0],
                                                                    ast.Name):
                        scope[inner.targets[0].id] = self.evaluate(inner.value, scope,
                                                                   depth + 1)
            else:
                raise FoldLimit("statement")
        raise FoldLimit("no return")

def _bind(target, value, scope) -> bool:
    if isinstance(target, ast.Name):
        scope[target.id] = value
        return True
    if isinstance(target, ast.Tuple) and isinstance(value, (list, tuple, str, bytes)):
        if len(target.elts) != len(value):
            return False
        return all(_bind(element, item, scope)
                   for element, item in zip(target.elts, value))
    return False

def _apply_compare(op, left, right) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.Is):
        return left is right
    if isinstance(op, ast.IsNot):
        return left is not right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    raise FoldLimit("compare")

def _safe_call(fn, args, kwargs):
    try:
        result = fn(*args, **kwargs)
    except Exception:                                # noqa: BLE001 - not foldable
        raise FoldLimit("call failed") from None
    if isinstance(result, (str, bytes, bytearray)) and len(result) > FOLD_METHOD_MAX:
        raise FoldLimit("size")
    if isinstance(result, (list, tuple, set, dict)) and len(result) > 200_000:
        raise FoldLimit("size")
    return result

def _pure_module(name):
    return {"base64": base64, "binascii": binascii, "zlib": zlib, "lzma": lzma,
            "bz2": bz2, "codecs": codecs, "json": json, "hashlib": hashlib,
            "urllib": None}.get(name) if name != "urllib" else None

def _mangled_identifier(name: str) -> bool:
    """Heuristic: is this identifier a name an obfuscator invented?"""
    if not name or not name.isidentifier():
        return False
    if name.startswith("__") and name.endswith("__"):
        return False                                 # dunder, not mangling
    if name.startswith("_"):
        return True
    if len(name) == 1:
        return name in ("l", "O", "I", "o")          # ``l``, ``O``, ``I``
    if name.isupper() and len(name) > 3:
        return True                                  # ``NBXOR2``
    if any(char.isdigit() for char in name) \
            and not any(char in "aeiouAEIOU" for char in name):
        return True                                  # ``x0r``-style names

def looks_obfuscated(tree) -> bool:
    """Clean code keeps its literals; obfuscated code gets folded flat."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and _mangled_identifier(node.id):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("exec", "eval", "compile", "__import__"):
            return True
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and _mangled_identifier(node.name):
            return True
    return False

def fold_tree(tree: ast.Module, rounds: int = 3, aggressive: bool = None) -> ast.Module:
    """Replace every foldable expression in the tree with its value."""
    if aggressive is None:
        aggressive = looks_obfuscated(tree)
    folder = Folder(tree)
    for _ in range(rounds):
        changed = False

        def visit(node):
            nonlocal changed
            for field, value in ast.iter_fields(node):
                if field in ("targets", "target", "annotation", "returns"):
                    continue
                if isinstance(node, ast.Expr) and field == "value" \
                        and isinstance(value, ast.Call):
                    visit(value)
                    continue
                if isinstance(value, list):
                    for index, item in enumerate(value):
                        if isinstance(item, ast.AST):
                            if isinstance(item, ast.expr):
                                replacement = simplify(item)
                                if replacement is not item:
                                    value[index] = replacement
                                    changed = True
                                    continue
                            visit(item)
                elif isinstance(value, ast.AST):
                    if isinstance(value, ast.expr):
                        replacement = simplify(value)
                        if replacement is not value:
                            setattr(node, field, replacement)
                            changed = True
                            continue
                    visit(value)

        FOLDABLE = (ast.Call, ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp,
                    ast.IfExp, ast.JoinedStr, ast.Subscript, ast.ListComp,
                    ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.List,
                    ast.Tuple, ast.Set, ast.Dict)

        def has_computation(node):
            """Only fold something that actually *computes* a value.

            Plain literals and arithmetic are not obfuscation; folding them
            rewrites working code for no gain and costs instruction identity.
            """
            def readable(ident):
                """A plain lowercase identifier is somebody's real code."""
                return bool(ident) and ident.isidentifier() and ident.islower() \
                    and not ident.startswith("_")

            def mangled_call(call):
                target = call.func
                while isinstance(target, ast.Attribute):
                    if not readable(target.attr):
                        return True
                    target = target.value
                if isinstance(target, ast.Name):
                    return not readable(target.id)
                return False        # ``f()(...)``: judged by the inner calls only

            for child in ast.walk(node):
                if aggressive and isinstance(child, (ast.Call, ast.ListComp, ast.SetComp,
                                                     ast.DictComp, ast.GeneratorExp,
                                                     ast.JoinedStr)):
                    return True
                if isinstance(child, ast.Call):
                    if mangled_call(child):
                        return True
                elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp,
                                        ast.GeneratorExp, ast.JoinedStr)):
                    return True
            return False

        def simplify(node):
            if not isinstance(node, FOLDABLE):
                return node            # never erase a bare name or attribute
            if not has_computation(node):
                return node
            if isinstance(getattr(node, "ctx", ast.Load()), ast.Store):
                return node        # never touch assignment targets
            local = Folder.__new__(Folder)
            local.__dict__.update(folder.__dict__)
            local.steps = 0
            try:
                value = local.evaluate(node, {})
            except (FoldLimit, RecursionError, MemoryError, ValueError, TypeError,
                    IndexError, KeyError, OverflowError, ZeroDivisionError):
                return node
            except Exception:                        # noqa: BLE001 - never break a run
                return node
            if isinstance(value, ast.AST):
                return value
            if isinstance(value, (str, bytes, int, float, complex, bool, type(None))):
                return ast.Constant(value=value)
            if isinstance(value, (list, tuple, set, frozenset)):
                if len(value) > 5000:
                    return node
                try:
                    return ast.parse(repr(value), mode="eval").body
                except (SyntaxError, ValueError):
                    return node
            if isinstance(value, dict):
                try:
                    return ast.parse(repr(value), mode="eval").body
                except (SyntaxError, ValueError):
                    return node
            return node

        visit(tree)
        if not changed:
            break
    return ast.fix_missing_locations(tree)

def d6_expr_fixups(tree):
    """Repair expression shapes that only make sense to the peephole stage.

    * 3.13 leaves a bare ``FormattedValue`` where the source had an f-string;
      ``ast.unparse`` only renders it inside a ``JoinedStr``.
    * ``assert x, m`` compiles to ``if not x: raise AssertionError(m)``.
    """
    assert_ok = (ast.Assert,)

    class _Fix(ast.NodeTransformer):
        def _wrap(self, node):
            if isinstance(node, ast.FormattedValue):
                return ast.JoinedStr(values=[node])
            return node

        def _names(self, node):
            fixed = []
            for item in node.names:
                if isinstance(item, ast.Expr):
                    item = item.value
                if isinstance(item, ast.Constant):
                    fixed.append(str(item.value))
                elif isinstance(item, ast.Name):
                    fixed.append(item.id)
                else:
                    fixed.append(str(item))
            node.names = fixed
            return node

        def visit_Global(self, node):
            return self._names(node)

        def visit_Nonlocal(self, node):
            return self._names(node)

        def visit_FormattedValue(self, node):
            self.generic_visit(node)
            inner = node.value
            while isinstance(inner, ast.FormattedValue):
                # ``FORMAT_SIMPLE`` applied to an already-formatted part: the
                # nesting is a decompiler artifact, hoist the real value out
                if node.conversion == -1:
                    node.conversion = inner.conversion
                if node.format_spec is None:
                    node.format_spec = inner.format_spec
                node.value = inner.value
                inner = node.value
            return node

        def visit_JoinedStr(self, node):
            self.generic_visit(node)
            return node

        def visit_Return(self, node):
            self.generic_visit(node)
            node.value = self._wrap(node.value)
            return node

        def visit_Expr(self, node):
            self.generic_visit(node)
            node.value = self._wrap(node.value)
            return node

        def visit_Assign(self, node):
            self.generic_visit(node)
            node.value = self._wrap(node.value)
            return node

        def visit_If(self, node):
            self.generic_visit(node)
            if node.orelse or len(node.body) != 1:
                return node
            raise_node = node.body[0]
            if not isinstance(raise_node, ast.Raise) or raise_node.cause is not None:
                return node
            exc = raise_node.exc
            if not (isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name)
                    and exc.func.id == "AssertionError" and not exc.keywords
                    and len(exc.args) <= 1):
                return node
            test = node.test
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                test = test.operand
            else:
                test = ast.UnaryOp(op=ast.Not(), operand=test)
            message = exc.args[0] if exc.args else None
            if message is not None and isinstance(message, ast.Constant) \
                    and message.value is None:
                message = None
            fixed = ast.Assert(test=test, msg=message)
            return ast.copy_location(fixed, node)

    return _Fix().visit(tree)
