"""Loop idiom recovery: the `for` the source had, back from the `while` it became.

De-flattening and bytecode lifting both land on the same conservative shape:

    i = 0
    while i < len(items):
        total += items[i] * 2
        i += 1

Every decompiler emits that, and every human reading it has to translate.  The
information needed to put the `for` back is present, and compilers agree on what
it looks like: if the index is used *only* to subscript the same sequence and to
increment - never read for its own value - and the bound is that sequence's
length, the loop was a `for` over the sequence.  If the index is read in the
body (`items[i] + i`), it was an index loop and stays one; it just becomes
`for i in range(...)`.

Two rewrites, both refusable:

* ``for <fresh> in seq:``  when every read of the index is ``seq[index]``
* ``for <index> in range(<bound>):``  when it is not

Both require the initialiser to sit immediately before the loop, the increment to
be the last statement of the body, the index never to be rebound inside the loop,
and the iterated object never to be assigned there.  Anything else is left
exactly as it was - a wrong loop here changes what the program does, and this
pass has no way to test the result by running it.
"""
from __future__ import annotations

from ..polish.demangle import _ast

_MAX_DEPTH = 40


class _No(Exception):
    """This loop is not the idiom we know how to rewrite."""


def _is_index_assign(stmt, name: str, amount: int = 0) -> bool:
    """`i = <start>` (amount == 0) or `i = i + n` / `i += n` with n == amount."""
    if not (isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], _ast.Name)
            and stmt.targets[0].id == name):
        return False
    value = stmt.value
    if not isinstance(value, _ast.Constant):
        return False
    if amount == 0:
        return True
    return value.value == amount if isinstance(value.value, int) else False


def _increment_amount(stmt, name: str) -> int | None:
    """How much `stmt` steps the index by, if that is all it does."""
    if isinstance(stmt, _ast.AugAssign) and isinstance(stmt.target, _ast.Name) \
            and stmt.target.id == name and isinstance(stmt.op, _ast.Add) \
            and isinstance(stmt.value, _ast.Constant) \
            and isinstance(stmt.value.value, int):
        return stmt.value.value
    if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
            and isinstance(stmt.targets[0], _ast.Name) and stmt.targets[0].id == name \
            and isinstance(stmt.value, _ast.BinOp) and isinstance(stmt.value.op, _ast.Add):
        left, right = stmt.value.left, stmt.value.right
        if isinstance(left, _ast.Name) and left.id == name \
                and isinstance(right, _ast.Constant) and isinstance(right.value, int):
            return right.value
        if isinstance(right, _ast.Name) and right.id == name \
                and isinstance(left, _ast.Constant) and isinstance(left.value, int):
            return left.value
    return None


def _loop_index(test) -> str | None:
    if isinstance(test, _ast.Compare) and len(test.ops) == 1 \
            and isinstance(test.ops[0], _ast.Lt) \
            and isinstance(test.left, _ast.Name):
        return test.left.id
    return None


def _bound_expression(test) -> _ast.expr | None:
    """The upper bound as written: `len(items)`, `n`, `limit + 1`..."""
    if isinstance(test, _ast.Compare) and len(test.ops) == 1 \
            and isinstance(test.ops[0], _ast.Lt):
        return test.comparators[0]
    return None


def _iterated_sequence(bound) -> _ast.expr | None:
    """`len(items)` -> `items`, when the bound is exactly a length."""
    if isinstance(bound, _ast.Call) and isinstance(bound.func, _ast.Name) \
            and bound.func.id == "len" and len(bound.args) == 1:
        return bound.args[0]
    return None


def _reads(node, name: str) -> int:
    return sum(1 for sub in _ast.walk(node)
               if isinstance(sub, _ast.Name) and sub.id == name
               and isinstance(sub.ctx, _ast.Load))


def _writes(node, name: str) -> int:
    return sum(1 for sub in _ast.walk(node)
               if isinstance(sub, _ast.Name) and sub.id == name
               and isinstance(sub.ctx, (_ast.Store, _ast.Del)))


def _uses_object(node, name: str) -> bool:
    return any(isinstance(sub, _ast.Name) and sub.id == name for sub in _ast.walk(node))


def _free_name(body: list, base: str = "_item") -> str:
    taken = {sub.id for stmt in body for sub in _ast.walk(stmt)
             if isinstance(sub, _ast.Name)}
    if base not in taken:
        return base
    for index in range(2, 500):
        candidate = f"{base}_{index}"
        if candidate not in taken:
            return candidate
    raise _No("no free name")


class _IndexedToSubscript(_ast.NodeTransformer):
    """`seq[i]` -> `item`, everywhere inside the loop body."""

    def __init__(self, index: str, sequence, item: str) -> None:
        self.index = index
        self.sequence = _ast.dump(sequence)
        self.item = item
        self.replaced = 0

    def visit_Subscript(self, node):
        self.generic_visit(node)
        if _ast.dump(node.value) == self.sequence \
                and isinstance(node.slice, _ast.Name) and node.slice.id == self.index:
            self.replaced += 1
            return _ast.Name(id=self.item, ctx=_ast.Load())
        return node


def _rewrite_loop(init: _ast.stmt, loop: _ast.While) -> list | None:
    """Rewrite one `i = 0; while i < ...` pair, or return None to leave it alone."""
    if not (_ast.Assign and isinstance(init, _ast.Assign) and len(init.targets) == 1
            and isinstance(init.targets[0], _ast.Name)
            and isinstance(init.value, _ast.Constant) and init.value.value == 0):
        return None
    index = init.targets[0].id
    if loop.orelse or not loop.body:
        return None
    bound = _bound_expression(loop.test)
    if bound is None:
        return None
    body = list(loop.body)
    if _increment_amount(body[-1], index) != 1:
        return None
    body = body[:-1]
    if not body:
        return None
    if any(_writes(stmt, index) for stmt in body):
        return None
    # the bound expression must be stable for the whole loop, or `range()` would
    # capture a different value than the `while` re-evaluated each time
    for name in {sub.id for sub in _ast.walk(bound) if isinstance(sub, _ast.Name)}:
        if any(_writes(stmt, name) for stmt in body):
            return None

    sequence = _iterated_sequence(bound)
    total_reads = sum(_reads(stmt, index) for stmt in body)
    subscript_reads = 0
    if sequence is not None:
        for stmt in body:
            for sub in _ast.walk(stmt):
                if isinstance(sub, _ast.Subscript) and isinstance(sub.slice, _ast.Name) \
                        and sub.slice.id == index \
                        and _ast.dump(sub.value) == _ast.dump(sequence):
                    subscript_reads += 1
        if total_reads != subscript_reads:
            sequence = None            # the index is used for its own value

    if sequence is not None and isinstance(sequence, _ast.Name):
        item = _free_name(body)
        rename = _IndexedToSubscript(index, sequence, item)
        new_body = [rename.visit(stmt) for stmt in body]
        if rename.replaced >= 1:
            for stmt in new_body:
                _ast.fix_missing_locations(stmt)
            loop_new = _ast.For(target=_ast.Name(id=item, ctx=_ast.Store()),
                                iter=_ast.Name(id=sequence.id, ctx=_ast.Load()),
                                body=new_body, orelse=[], type_comment=None)
            _ast.fix_missing_locations(loop_new)
            return [loop_new]

    loop_new = _ast.For(target=_ast.Name(id=index, ctx=_ast.Store()),
                        iter=_ast.Call(func=_ast.Name(id="range", ctx=_ast.Load()),
                                       args=[bound], keywords=[]),
                        body=body, orelse=[], type_comment=None)
    _ast.fix_missing_locations(loop_new)
    return [loop_new]


def _find_init(body: list, loop_at: int, index: str) -> int | None:
    """The `i = 0` that initialises this loop, if it is nearby and untouched."""
    for back in range(loop_at - 1, max(loop_at - 12, -1), -1):
        stmt = body[back]
        if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], _ast.Name) \
                and stmt.targets[0].id == index:
            return back if isinstance(stmt.value, _ast.Constant) else None
        if _uses_object(stmt, index):
            return None
    return None


def _rewrite_body(body: list) -> int:
    rewritten = 0
    index = 0
    while index < len(body):
        stmt = body[index]
        if isinstance(stmt, _ast.While):
            name = _loop_index(stmt.test)
            if name is not None:
                init_at = _find_init(body, index, name)
                if init_at is not None:
                    replacement = _rewrite_loop(body[init_at], stmt)
                    if replacement is not None:
                        body[init_at:index + 1] = replacement
                        rewritten += 1
                        for node in replacement:
                            inner_body = getattr(node, "body", None)
                            if isinstance(inner_body, list):
                                rewritten += _rewrite_body(inner_body)
                        index = init_at + 1
                        continue
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, field, None)
            if isinstance(inner, list) and inner and isinstance(inner[0], _ast.AST):
                rewritten += _rewrite_body(inner)
        for handler in getattr(stmt, "handlers", []) or []:
            rewritten += _rewrite_body(handler.body)
        index += 1
    return rewritten


def recover_loops(tree) -> int:
    """Put `for` loops back.  Returns how many were rewritten."""
    try:
        return _rewrite_body(tree.body)
    except RecursionError:
        return 0
