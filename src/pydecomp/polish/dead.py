"""pydecomp - dead."""
from __future__ import annotations

from ..polish.demangle import _ast

_TERMINATORS = (_ast.Return, _ast.Raise, _ast.Break, _ast.Continue)


def _drop_unreachable(body: list) -> int:
    """Statements after `return`/`raise`/`break`/`continue` never run."""
    removed = 0
    out = []
    terminated = False
    for stmt in body:
        if terminated:
            if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                _ast.ClassDef)):
                out.append(stmt)          # a later definition is still importable
                continue
            removed += 1
            continue
        out.append(stmt)
        if isinstance(stmt, _TERMINATORS):
            terminated = True
    body[:] = out
    return removed


_DYNAMIC = {"globals", "vars", "locals", "eval", "exec", "getattr", "setattr"}


def _module_is_dynamic(tree) -> bool:
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name) \
                and node.func.id in _DYNAMIC:
            return True
        if isinstance(node, _ast.Name) and node.id in ("__all__",):
            return True
    return False


def _names_touched(stmt) -> set:
    """Every name a statement reads or writes - cheap enough to precompute."""
    names = set()
    for sub in _ast.walk(stmt):
        if isinstance(sub, _ast.Name):
            names.add(sub.id)
    return names


def _drop_duplicate_assignments(tree) -> int:
    """`_acc = 0` straight after the same `_acc = 0` is a rewrite artefact.

    A flattened block can re-emit the initialisers that already ran before the
    dispatcher.  An assignment is only dropped when an identical one ran earlier
    in the same block and nothing in between touched the name.
    """
    removed = 0

    def sweep(body):
        nonlocal removed
        targets = [stmt.targets[0].id for stmt in body
                   if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1
                   and isinstance(stmt.targets[0], _ast.Name)]
        if len(targets) == len(set(targets)):
            pass                                   # nothing repeats: just recurse
        else:
            touched = [_names_touched(stmt) for stmt in body]
            removed_here = set()
            for index, stmt in enumerate(body):
                if not isinstance(stmt, _ast.Assign):
                    continue
                if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], _ast.Name):
                    continue
                name = stmt.targets[0].id
                dump = _ast.dump(stmt.value)
                for earlier in range(index - 1, -1, -1):
                    if earlier in removed_here:
                        continue
                    other = body[earlier]
                    if isinstance(other, _ast.Assign) and len(other.targets) == 1 \
                            and isinstance(other.targets[0], _ast.Name) \
                            and other.targets[0].id == name \
                            and _ast.dump(other.value) == dump:
                        removed_here.add(index)
                        removed += 1
                        break
                    if name in touched[earlier]:
                        break
            if removed_here:
                body[:] = [stmt for index, stmt in enumerate(body)
                           if index not in removed_here]
        for stmt in body:
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    sweep(inner)
            for handler in getattr(stmt, "handlers", []) or []:
                sweep(handler.body)

    sweep(tree.body)
    return removed


def _drop_bare_constants(tree) -> int:
    """A statement that is just `None` / `0` / `True` does nothing at runtime."""
    removed = 0

    def sweep(body):
        nonlocal removed
        out = []
        for index, stmt in enumerate(body):
            if isinstance(stmt, _ast.Expr) and isinstance(stmt.value, _ast.Constant) \
                    and not (index == 0 and isinstance(stmt.value.value, str)):
                removed += 1
                continue
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    sweep(inner)
            for handler in getattr(stmt, "handlers", []) or []:
                sweep(handler.body)
            out.append(stmt)
        body[:] = out

    sweep(tree.body)
    return removed


def _drop_unused_literals(tree) -> int:
    """A literal nobody reads any more is only noise - and a rename target."""
    loads = {node.id for node in _ast.walk(tree)
             if isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Load)}
    removed = 0

    def sweep(body):
        nonlocal removed
        out = []
        for stmt in body:
            if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], _ast.Name) \
                    and stmt.targets[0].id not in loads \
                    and isinstance(stmt.value, (_ast.Constant, _ast.Tuple, _ast.List,
                                                _ast.Dict, _ast.Set)):
                removed += 1
                continue
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    sweep(inner)
            for handler in getattr(stmt, "handlers", []) or []:
                sweep(handler.body)
            out.append(stmt)
        body[:] = out

    # module-level names are the program's own API: keep the definition even
    # when every read has been folded.  Function-local temporaries are noise.
    if not _module_is_dynamic(tree):
        for stmt in tree.body:
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    sweep(inner)
            for handler in getattr(stmt, "handlers", []) or []:
                sweep(handler.body)
    return removed


def _strip_dead(tree) -> int:
    """Remove statements that can never run, plus writes nobody ever reads."""
    removed = 0

    def truth(node):
        if not isinstance(node, _ast.Constant):
            return None
        return bool(node.value)

    def prune_block(body):
        nonlocal removed
        out = []
        for stmt in body:
            if isinstance(stmt, _ast.If) and truth(stmt.test) is not None:
                keep = stmt.body if truth(stmt.test) else stmt.orelse
                pruned = prune_block(keep)
                out.extend(pruned)
                removed += 1
                continue
            if isinstance(stmt, _ast.While) and isinstance(stmt.test, _ast.Constant) \
                    and not stmt.test.value and not stmt.orelse:
                removed += 1
                continue
            if isinstance(stmt, _ast.Pass):
                continue
            for field_name in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field_name, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    setattr(stmt, field_name, prune_block(inner))
            for handler in getattr(stmt, "handlers", []) or []:
                handler.body = prune_block(handler.body)
            out.append(stmt)
        return out

    def sweep(body):
        nonlocal removed
        removed += _drop_unreachable(body)
        for stmt in body:
            for field_name in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field_name, None)
                if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                    sweep(inner)
            for handler in getattr(stmt, "handlers", []) or []:
                sweep(handler.body)

    tree.body = prune_block(tree.body)
    sweep(tree.body)
    removed += _drop_unused_literals(tree)
    removed += _drop_bare_constants(tree)
    removed += _drop_duplicate_assignments(tree)
    return removed
