"""pydecomp - inline.

Constant propagation and inlining, the two passes that turn a decoder *defined by
the sample* back into the string it decodes.

Obfuscators rarely call `base64.b64decode` directly.  They write their own:

    def _d(s):
        return base64.b64decode(s[::-1]).decode()

    _q = '==QZ...'
    print(_d(_q))

A name-mangling or indirection layer like that defeats regex matching, and it is
the main reason single-pattern tools report "unknown obfuscation" on samples
whose plaintext is one evaluation away.  pydecomp walks it in three steps:

1. **propagate** - a name bound once to a literal becomes that literal;
2. **inline** - a function whose body is a *pure* expression is interpreted with
   `polish.evaluate`, so `_d(_q)` collapses to `'print(...)'`;
3. fold (in ``evaluate.fold_expressions``) - the resulting expression tree is
   evaluated whole.

Only functions whose body the interpreter can prove pure are inlined: one
`return`, no assignments, no loops, no attribute access outside the allowlist.
Everything else is left exactly as it was found.
"""
from __future__ import annotations

from ..polish.demangle import _ast
from ..polish.evaluate import (Unevaluable, _Budget, _NamedFunction, evaluate,
                               _invoke, _literal_node)

_SKIP = (_ast.ClassDef,)
_SCOPE: dict = {}


def _bound_names(tree) -> dict[str, int]:
    """How many times each name is bound somewhere in the tree."""
    counts: dict[str, int] = {}

    def bump(name):
        counts[name] = counts.get(name, 0) + 1

    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            bump(node.name)
        elif isinstance(node, _ast.Assign):
            for target in node.targets:
                for sub in _ast.walk(target):
                    if isinstance(sub, _ast.Name):
                        bump(sub.id)
        elif isinstance(node, (_ast.AnnAssign, _ast.AugAssign, _ast.NamedExpr)):
            if isinstance(node.target, _ast.Name):
                bump(node.target.id)
        elif isinstance(node, (_ast.For, _ast.AsyncFor)):
            for sub in _ast.walk(node.target):
                if isinstance(sub, _ast.Name):
                    bump(sub.id)
        elif isinstance(node, (_ast.With, _ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for sub in _ast.walk(item.optional_vars):
                        if isinstance(sub, _ast.Name):
                            bump(sub.id)
        elif isinstance(node, _ast.arg):
            bump(node.arg)
        elif isinstance(node, (_ast.Global, _ast.Nonlocal)):
            for name in node.names:
                bump(name)
        elif isinstance(node, (_ast.Import, _ast.ImportFrom)):
            for alias in node.names:
                bump(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, _ast.ExceptHandler) and node.name:
            bump(node.name)
    return counts


def _immutable(value) -> bool:
    """Can this value be substituted at every use without changing meaning?

    A literal ``[]`` is not a constant: ``results = []; results.append(x)``
    means something different from ``[].append(x)``, and a dict or set behaves
    the same way.  Only immutable scalars (and tuples of them) are propagated.
    """
    if isinstance(value, (str, bytes, int, float, bool, type(None), complex)):
        return True
    if isinstance(value, (tuple, frozenset)):
        return all(_immutable(item) for item in value)
    return False


def _scope_counts(body) -> dict[str, int]:
    """How many times each name is *bound* in one scope (nested scopes excluded)."""
    counts: dict[str, int] = {}

    def bump(name):
        counts[name] = counts.get(name, 0) + 1

    def walk(node):
        for child in _ast.iter_child_nodes(node):
            if isinstance(child, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                  _ast.ClassDef, _ast.Lambda)):
                if isinstance(child, _ast.ClassDef):
                    bump(child.name)
                continue
            if isinstance(child, _ast.Name) and isinstance(child.ctx, _ast.Store):
                bump(child.id)
            walk(child)

    for stmt in body:
        if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            bump(stmt.name)
            continue
        if isinstance(stmt, _ast.Name) and isinstance(stmt.ctx, _ast.Store):
            bump(stmt.id)
        walk(stmt)
    return counts


def _scope_bindings(body):
    """Direct assignments in one scope: name -> value node (literal-able only)."""
    found: dict[str, object] = {}
    duplicated: set[str] = set()
    for stmt in body:
        if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], _ast.Name):
            name = stmt.targets[0].id
            if name in found:
                duplicated.add(name)
            found[name] = stmt.value
        elif isinstance(stmt, (_ast.AnnAssign, _ast.AugAssign, _ast.NamedExpr)):
            target = getattr(stmt, "target", None)
            if isinstance(target, _ast.Name):
                duplicated.add(target.id)
    for name in duplicated:
        found.pop(name, None)
    return found


class _ScopeSub(_ast.NodeTransformer):
    """Substitute literal bindings, but never inside a nested scope."""

    def __init__(self, env):
        self.env = env
        self.replaced = 0

    def visit_Name(self, node):                            # noqa: N802
        if isinstance(node.ctx, _ast.Load) and node.id in self.env:
            literal = _literal_node(self.env[node.id])
            if literal is not None:
                self.replaced += 1
                return _ast.copy_location(literal, node)
        return node

    def visit_FunctionDef(self, node):                     # noqa: N802
        return node

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef


def propagate_constants(tree) -> tuple[int, dict]:
    """Substitute names bound once to a literal, per scope.  Returns (count, env)."""
    try:
        counts = _bound_names(tree)
        global_env: dict = {}
        replaced = 0

        def scope(body, inherited, is_module=False):
            nonlocal replaced
            bindings = _scope_bindings(body)
            local_counts = _scope_counts(body)
            env = dict(inherited)
            for name, value in bindings.items():
                if local_counts.get(name, 0) != 1:
                    continue
                if is_module and counts.get(name, 0) != 1:
                    # module scope: a name rebound anywhere is not a constant
                    continue
                try:
                    resolved = evaluate(value, dict(env), _Budget(10_000))
                except (Unevaluable, RecursionError):
                    continue
                if not _immutable(resolved):
                    continue          # mutable: aliasing and mutation matter
                env[name] = resolved
            if env:
                sub = _ScopeSub(env)
                for index, stmt in enumerate(body):
                    if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                        _ast.ClassDef)):
                        continue
                    body[index] = sub.visit(stmt)
                replaced += sub.replaced
            return env

        global_env = scope(tree.body, {}, is_module=True)
        # descend, but do not lose the globals each nested scope can see
        def descend(body, inherited):
            for stmt in body:
                inner = getattr(stmt, "body", None)
                if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    local = dict(inherited)
                    shadow = {arg.arg for arg in stmt.args.args} | \
                             {arg.arg for arg in stmt.args.kwonlyargs}
                    for name in shadow:
                        local.pop(name, None)
                    scope(stmt.body, local)
                    descend(stmt.body, inherited)
                elif isinstance(stmt, (_ast.If, _ast.For, _ast.While, _ast.With,
                                       _ast.Try)):
                    for field in ("body", "orelse", "finalbody"):
                        block = getattr(stmt, field, None)
                        if isinstance(block, list) and block \
                                and isinstance(block[0], _ast.AST):
                            descend(block, inherited)
                    for handler in getattr(stmt, "handlers", []) or []:
                        descend(handler.body, inherited)

        descend(tree.body, global_env)
        return replaced, global_env
    except RecursionError:
        return 0, {}
    except Exception:                                  # noqa: BLE001 - cosmetic pass
        return 0, {}


def _inlinable_function(node) -> _NamedFunction | None:
    """A function we can interpret: pure expression body, no decorators."""
    if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
        return None
    if node.decorator_list or getattr(node, "is_async", 0):
        return None
    if node.args.vararg or node.args.kwarg or node.args.posonlyargs:
        return None
    body = [stmt for stmt in node.body
            if not (isinstance(stmt, _ast.Expr) and isinstance(stmt.value, _ast.Constant))]
    if len(body) != 1 or not isinstance(body[0], _ast.Return):
        return None
    if body[0].value is None:
        return None
    try:
        defaults = [evaluate(d, {}) for d in node.args.defaults]
    except (Unevaluable, RecursionError):
        return None
    params = [arg.arg for arg in node.args.args]
    return _NamedFunction(params, defaults, body[0].value, node.name)


def inline_pure_functions(tree, rounds: int = 3) -> int:
    """Replace `helper(literal, …)` with the literal the helper returns."""
    try:
        functions: dict[str, _NamedFunction] = {}
        for stmt in tree.body:
            function = _inlinable_function(stmt)
            if function is not None:
                functions[function.name] = function
            elif isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], _ast.Name) \
                    and isinstance(stmt.value, _ast.Lambda):
                try:
                    functions[stmt.targets[0].id] = _NamedFunction(
                        [arg.arg for arg in stmt.value.args.args],
                        [evaluate(d, {}) for d in stmt.value.args.defaults],
                        stmt.value.body, stmt.targets[0].id)
                except (Unevaluable, RecursionError):
                    continue
        if not functions:
            return 0
        # names that are rebound somewhere cannot be assumed to be our function
        counts = _bound_names(tree)
        for name in list(functions):
            if counts.get(name, 0) > 1:
                functions.pop(name, None)
        if not functions:
            return 0
        for function in functions.values():
            function.globals = functions
        total = 0
        for _ in range(max(rounds, 1)):
            pass_total = 0

            class _Inline(_ast.NodeTransformer):
                def visit_Call(self, node):                # noqa: N802
                    nonlocal pass_total
                    node = self.generic_visit(node)
                    if not isinstance(node.func, _ast.Name):
                        return node
                    function = functions.get(node.func.id)
                    if function is None:
                        return node
                    if node.keywords and any(kw.arg is None for kw in node.keywords):
                        return node
                    try:
                        args = [evaluate(a, {}) for a in node.args]
                        kwargs = {kw.arg: evaluate(kw.value, {}) for kw in node.keywords}
                    except (Unevaluable, RecursionError):
                        return node
                    try:
                        value = _invoke(function, args, kwargs, _Budget(20_000))
                    except (Unevaluable, RecursionError, TypeError):
                        return node
                    if isinstance(value, (bytes, bytearray)):
                        value = bytes(value)
                    literal = _literal_node(value)
                    if literal is None:
                        return node
                    pass_total += 1
                    return _ast.copy_location(literal, node)

                def visit_ClassDef(self, node):            # noqa: N802
                    return node

            inliner = _Inline()
            tree.body = [inliner.visit(stmt) for stmt in tree.body]
            total += pass_total
            if not pass_total:
                break
        return total
    except RecursionError:
        return 0
    except Exception:                                  # noqa: BLE001 - cosmetic pass
        return 0
