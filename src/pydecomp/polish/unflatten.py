"""pydecomp - unflatten."""
from __future__ import annotations

from ..polish.demangle import _ast

def _unflatten(tree) -> int:
    """`while True: if s == 3: ...; s = 7` - the classic dispatcher loop."""
    undone = 0
    for node in _ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for index, stmt in enumerate(list(body)):
            if not isinstance(stmt, _ast.While):
                continue
            if not (isinstance(stmt.test, _ast.Constant) and stmt.test.value):
                continue
            if len(stmt.body) != 1 or not isinstance(stmt.body[0], _ast.If):
                continue
            guard = stmt.body[0]
            if not isinstance(guard.test, _ast.Compare):
                continue
            if not isinstance(guard.test.left, _ast.Name):
                continue
            state = guard.test.left.id
            branches = [guard] + list(guard.orelse)
            by_value = {}
            for branch in branches:
                if not isinstance(branch, _ast.If):
                    break
                test = branch.test
                if not (isinstance(test, _ast.Compare) and len(test.ops) == 1
                        and isinstance(test.ops[0], _ast.Eq)
                        and isinstance(test.comparators[0], _ast.Constant)):
                    break
                by_value[test.comparators[0].value] = branch.body
            else:
                by_value[None] = branches[-1].body if isinstance(
                    branches[-1], _ast.If) else []
                # walk the chain from the initial state
                start = None
                for probe in _ast.walk(stmt):
                    if isinstance(probe, _ast.Assign) and any(
                            isinstance(t, _ast.Name) and t.id == state
                            for t in probe.targets):
                        if isinstance(probe.value, _ast.Constant):
                            start = probe.value.value
                if start is None or start not in by_value:
                    continue
                flat = []
                seen_states = set()
                cursor = start
                while cursor in by_value and cursor not in seen_states:
                    seen_states.add(cursor)
                    block = by_value[cursor]
                    nxt = None
                    for inner in block:
                        if isinstance(inner, _ast.Assign) and any(
                                isinstance(t, _ast.Name) and t.id == state
                                for t in inner.targets) \
                                and isinstance(inner.value, _ast.Constant):
                            nxt = inner.value.value
                            continue
                        flat.append(inner)
                    if nxt is None:
                        break
                    cursor = nxt
                if flat and cursor not in by_value:
                    body[index:index + 1] = flat
                    undone += 1
    return undone
