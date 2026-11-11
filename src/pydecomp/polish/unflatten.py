"""Control-flow flattening, reconstructed rather than patched.

Jawbreaker and friends compile a function body into a dispatcher:

    _state = 4
    while True:
        if _state == 0:
            _acc = 0
            _state = 1
        elif _state == 1:
            if _index < len(items):
                _state = 2
            else:
                _state = 3
        elif _state == 2:
            _acc += items[_index] * 2
            _index += 1
            _state = 1
        elif _state == 3:
            return _acc

Reading that by hand is the whole point of the obfuscation.  This pass treats
it for what it is - a graph - and rebuilds the structure the compiler destroyed:

* blocks are the branch bodies, keyed by the state constant that reaches them;
* transitions are the trailing ``_state = <const>`` of each block, or an ``if``
  whose two arms assign the state;
* an arm that returns to the dispatching state is a loop, so the blocks on that
  path become the body of a ``while`` with the arm's condition as its test;
* an opaque condition (`if 7 * 7 == 49:`) is settled by the predicate prover and
  never becomes a branch in the output.

The result for the sample above is the function it was compiled from:

    _acc = 0
    _index = 0
    while _index < len(items):
        _acc += items[_index] * 2
        _index += 1
    return _acc

Everything is guarded: if the shape is not a pure dispatcher - a state read
inside a block, a block that does not end in a transition, an arm we cannot
follow - the pass leaves the tree exactly as it found it and reports nothing.
No sample code is executed to find out what a transition "would have done".
"""
from __future__ import annotations

from ..polish.demangle import _ast

_TERMINATORS = (_ast.Return, _ast.Raise, _ast.Break, _ast.Continue)
_ELSE = ("__else__",)
_MAX_STATES = 128
_MAX_DEPTH = 24


class _GiveUp(Exception):
    """The shape is not a dispatcher we can reconstruct with confidence."""


# ---------------------------------------------------------------------------
# reading a dispatcher
# ---------------------------------------------------------------------------
def _const_assign(node, state: str):
    """The constant this statement stores in the state variable, or None."""
    if isinstance(node, _ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], _ast.Name) \
            and node.targets[0].id == state \
            and isinstance(node.value, _ast.Constant) \
            and isinstance(node.value.value, (int, str, bytes)):
        return node.value.value
    return None


def _chain(branch, state: str) -> dict | None:
    """`if s == 0: … elif s == 1: …` flattened into {state: [statements]}."""
    blocks: dict = {}
    node = branch
    while isinstance(node, _ast.If):
        test = node.test
        if not (isinstance(test, _ast.Compare) and len(test.ops) == 1
                and isinstance(test.ops[0], _ast.Eq)
                and isinstance(test.left, _ast.Name) and test.left.id == state
                and isinstance(test.comparators[0], _ast.Constant)):
            return None
        blocks[test.comparators[0].value] = list(node.body)
        if not node.orelse:
            return blocks
        if len(node.orelse) == 1 and isinstance(node.orelse[0], _ast.If):
            node = node.orelse[0]
            continue
        # `else: _state = 3` - reachable only from an unlisted state, so it is
        # kept under a sentinel and never followed unless a transition asks.
        blocks[_ELSE] = list(node.orelse)
        return blocks
    return None


def _transition(block: list, state: str):
    """('goto', S) | ('branch', test, A, B) | ('end',) for one block."""
    if not block:
        raise _GiveUp("empty block")
    last = block[-1]
    if isinstance(last, _TERMINATORS):
        return ("end",)
    value = _const_assign(last, state)
    if value is not None:
        return ("goto", value)
    if isinstance(last, _ast.If):
        first = _const_assign(last.body[-1], state) if len(last.body) == 1 else None
        second = _const_assign(last.orelse[-1], state) if len(last.orelse) == 1 else None
        if first is not None and second is not None:
            return ("branch", last.test, first, second)
    raise _GiveUp("block does not end in a transition")


def _body_without_transition(block: list, state: str) -> list:
    last = block[-1] if block else None
    if isinstance(last, _ast.If) and len(last.body) == 1 \
            and _const_assign(last.body[-1], state) is not None:
        return block[:-1]
    if last is not None and _const_assign(last, state) is not None:
        return block[:-1]
    return block


def _provable(test, verdict: bool) -> bool:
    """Could the opaque-predicate prover settle this branch?  If so, use it."""
    try:
        from .opaque import prove
        return prove(test) is verdict
    except Exception:                                  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# rebuilding the structure
# ---------------------------------------------------------------------------
def _reaches(blocks: dict, state: str, start, target, depth: int = 0,
             seen: set | None = None) -> bool:
    """Can `start` get to `target` at all (following gotos and branch arms)?"""
    if depth > _MAX_DEPTH:
        return False
    seen = set() if seen is None else set(seen)
    todo = [start]
    steps = 0
    while todo:
        steps += 1
        if steps > _MAX_STATES:
            return False
        cursor = todo.pop()
        if cursor == target:
            return True
        if cursor in seen:
            continue
        seen.add(cursor)
        block = blocks.get(cursor)
        if block is None:
            continue
        try:
            kind = _transition(block, state)
        except _GiveUp:
            continue
        if kind[0] == "goto":
            todo.append(kind[1])
        elif kind[0] == "branch":
            todo.append(kind[2])
            todo.append(kind[3])
    return False


def _goto_path(blocks: dict, state: str, start, stop: set) -> bool:
    """Follow goto-only transitions from `start`; does it land in `stop`?"""
    cursor = start
    seen = set()
    while True:
        if cursor in stop:
            return True
        if cursor in seen or len(seen) > _MAX_STATES:
            return False
        seen.add(cursor)
        block = blocks.get(cursor)
        if block is None:
            return False
        kind = _transition(block, state)
        if kind[0] == "goto":
            cursor = kind[1]
            continue
        return False


def _walk(blocks: dict, state: str, cursor, stop: set, depth: int = 0) -> list:
    """Emit the statements reached from `cursor`, stopping at any state in `stop`."""
    if depth > _MAX_DEPTH:
        raise _GiveUp("dispatcher nesting too deep")
    out: list = []
    visiting: set = set()
    steps = 0
    while True:
        steps += 1
        if steps > _MAX_STATES:
            raise _GiveUp("dispatcher too large")
        if cursor in stop:
            return out
        if cursor in visiting:
            raise _GiveUp("unstructured jump")
        visiting.add(cursor)
        block = blocks.get(cursor)
        if block is None:
            raise _GiveUp("state has no block")
        kind = _transition(block, state)
        body = _body_without_transition(block, state)

        if kind[0] == "end":
            out.extend(block)
            return out
        if kind[0] == "goto":
            out.extend(body)
            cursor = kind[1]
            continue

        _, test, first, second = kind
        if _provable(test, True):
            out.extend(body)
            cursor = first
            continue
        if _provable(test, False):
            out.extend(body)
            cursor = second
            continue

        # A fork: if one arm walks straight back to the state that made the
        # decision, that arm is a loop and this is its condition.
        head = cursor
        inner_stop = stop | {head}
        if _reaches(blocks, state, first, head):
            condition, entry_state, exit_state = test, first, second
        elif _reaches(blocks, state, second, head):
            condition = _ast.UnaryOp(op=_ast.Not(), operand=test)
            entry_state, exit_state = second, first
        else:
            # neither arm loops: this is an ordinary if/else over the graph
            left = _walk(blocks, state, first, inner_stop, depth + 1)
            right = _walk(blocks, state, second, inner_stop, depth + 1)
            if not left or not right:
                raise _GiveUp("fork arm produced nothing")
            if not (_ends_block(left) and _ends_block(right)):
                raise _GiveUp("if/else arms do not both settle")
            out.append(_ast.If(test=test, body=left, orelse=right))
            return out
        loop_body = _walk(blocks, state, entry_state, inner_stop, depth + 1)
        out.append(_ast.While(test=condition, body=loop_body or [_ast.Pass()], orelse=[]))
        cursor = exit_state


def _ends_block(statements: list) -> bool:
    """Does this arm finish where control cannot fall through into the next arm?"""
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, _TERMINATORS):
        return True
    if isinstance(last, _ast.While):
        return True
    if isinstance(last, _ast.If):
        return _ends_block(last.body) and _ends_block(last.orelse)
    return False


def _dispatcher(statements: list, state: str) -> dict:
    """The {state: block} map of a `while True:` dispatcher."""
    blocks: dict = {}
    for stmt in statements:
        if not isinstance(stmt, _ast.While):
            raise _GiveUp("not a dispatcher loop")
        if not (isinstance(stmt.test, _ast.Constant) and stmt.test.value):
            raise _GiveUp("loop is not `while True`")
        if stmt.orelse:
            raise _GiveUp("dispatcher loop has an else")
        if len(stmt.body) != 1 or not isinstance(stmt.body[0], _ast.If):
            raise _GiveUp("dispatcher body is not a single branch chain")
        found = _chain(stmt.body[0], state)
        if not found:
            raise _GiveUp("branch chain does not dispatch on the state")
        blocks.update(found)
    if len(blocks) < 3:
        raise _GiveUp("too few states to be flattened code")
    for block in blocks.values():
        for node in _ast.walk(_ast.Module(body=list(block), type_ignores=[])):
            if isinstance(node, _ast.Name) and node.id == state \
                    and isinstance(node.ctx, _ast.Load):
                raise _GiveUp("state variable is read inside a block")
    return blocks


def _unflatten(tree) -> int:
    """Rewrite every dispatcher loop in the tree.  Returns how many were rebuilt."""
    rebuilt = 0
    for parent in list(_ast.walk(tree)):
        body = getattr(parent, "body", None)
        if not isinstance(body, list):
            continue
        for index in range(len(body) - 1, -1, -1):
            stmt = body[index]
            if not isinstance(stmt, _ast.While):
                continue
            if not (isinstance(stmt.test, _ast.Constant) and stmt.test.value):
                continue
            if len(stmt.body) != 1 or not isinstance(stmt.body[0], _ast.If):
                continue
            guard = stmt.body[0].test
            if not (isinstance(guard, _ast.Compare) and isinstance(guard.left, _ast.Name)):
                continue
            state = guard.left.id
            entry_at = None
            entry = None
            for back in range(index - 1, max(index - 12, -1), -1):
                probe = _const_assign(body[back], state)
                if probe is not None:
                    entry_at, entry = back, probe
                    break
            if entry is None:
                continue
            try:
                blocks = _dispatcher([stmt], state)
                flattened = _walk(blocks, state, entry, set())
            except _GiveUp:
                continue
            except RecursionError:
                continue
            if not flattened:
                continue
            try:
                # validate inside a function: the block may end in `return`
                wrapper = _ast.parse("def _probe():\n    pass").body[0]
                wrapper.body = flattened
                _ast.fix_missing_locations(wrapper)
                compile(_ast.Module(body=[wrapper], type_ignores=[]),
                        "<unflatten>", "exec", dont_inherit=True)
            except (SyntaxError, ValueError, TypeError):
                continue
            body[index:index + 1] = flattened
            # the entry assignment fed the dispatcher we just removed
            del body[entry_at]
            rebuilt += 1
    return rebuilt
