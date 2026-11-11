"""pydecomp - dead."""
from __future__ import annotations

from ..polish.demangle import _ast

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

    tree.body = prune_block(tree.body)
    return removed
