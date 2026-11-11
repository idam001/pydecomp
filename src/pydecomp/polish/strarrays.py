"""pydecomp - strarray.

The obfuscator.io trick, ported to Python by every packer that copies it: pull
every string out of the program into one literal array, hand out an *accessor*
function that indexes the array through an offset, and rotate the array at
import time so reading it top-to-bottom gives the wrong answer.

    _t = ['Kc3', 'm9Q', 'print', ...]
    def _g(i):
        while _n:
            _t.append(_t.pop(0))
        return _b64(_t[i - 0x1F])[::-1].decode()

Nothing here needs to run.  The rotation is arithmetic on a list we already
hold, the offset is a literal, the decoder chain is a fixed list of pure
functions, so the whole thing resolves statically - provided the array is never
touched in a way we cannot model.  When it is, pydecomp leaves the code exactly
as it found it: a wrong string is worse than an unresolved one.
"""
from __future__ import annotations

import base64
import binascii
import zlib

from ..polish.demangle import _ast

_ROTATION_LIMIT = 100_000
_TABLE_LIMIT = 20_000


def _literal_table(node):
    """Return the list of literal values in an array/tuple/dict literal."""
    if isinstance(node, (_ast.List, _ast.Tuple)):
        values = []
        for element in node.elts:
            if not isinstance(element, _ast.Constant):
                return None
            if not isinstance(element.value, (str, bytes)):
                return None
            values.append(element.value)
        return values
    if isinstance(node, _ast.Dict):
        pairs = {}
        for key, value in zip(node.keys, node.values):
            if not (isinstance(key, _ast.Constant) and isinstance(value, _ast.Constant)):
                return None
            if not isinstance(value.value, (str, bytes)):
                return None
            pairs[key.value] = value.value
        return ("dict", pairs)
    return None


def _rotate_left(table, times: int):
    if not table:
        return table
    times %= len(table)
    return table[times:] + table[:times]


def _rotate_right(table, times: int):
    if not table:
        return table
    times %= len(table)
    return table[-times:] + table[:-times] if times else table


def _rotation_of(stmt, names):
    """Recognise one array mutation and return (name, kind, times) or None."""
    target = None
    call = None
    if isinstance(stmt, _ast.Expr) and isinstance(stmt.value, _ast.Call):
        call = stmt.value
    elif isinstance(stmt, _ast.Assign) and isinstance(stmt.value, _ast.Call):
        call = stmt.value
    if call is None:
        return None
    func = call.func
    if not isinstance(func, _ast.Attribute) or not isinstance(func.value, _ast.Name):
        return None
    name = func.value.id
    if name not in names:
        return None
    # arr.append(arr.pop(0))  /  arr.insert(0, arr.pop())
    if func.attr in ("append", "insert"):
        inner = call.args[-1] if call.args else None
        if not (isinstance(inner, _ast.Call) and isinstance(inner.func, _ast.Attribute)
                and isinstance(inner.func.value, _ast.Name) and inner.func.value.id == name):
            return None
        pop_index = 0
        if inner.args and isinstance(inner.args[0], _ast.Constant) \
                and isinstance(inner.args[0].value, int):
            pop_index = inner.args[0].value
        if func.attr == "append":
            if pop_index == 0:
                return (name, "left", 1)
            if pop_index == -1:
                return (name, "right", 1)
            return None
        insert_index = 0
        if call.args and isinstance(call.args[0], _ast.Constant) \
                and isinstance(call.args[0].value, int):
            insert_index = call.args[0].value
        if insert_index == 0 and pop_index == -1:
            return (name, "right", 1)
        return None
    return None


def _slice_rotation(stmt, names):
    """`arr[:] = arr[k:] + arr[:k]` - a one-shot slice rotation."""
    if not isinstance(stmt, _ast.Assign) or len(stmt.targets) != 1:
        return None
    target, value = stmt.targets[0], stmt.value
    if not (isinstance(target, _ast.Subscript) and isinstance(target.value, _ast.Name)):
        return None
    name = target.value.id
    if name not in names:
        return None
    if not isinstance(value, _ast.BinOp) or not isinstance(value.op, _ast.Add):
        return None
    left, right = value.left, value.right
    if not (isinstance(left, _ast.Subscript) and isinstance(right, _ast.Subscript)):
        return None
    head = left.slice
    if not (isinstance(head, _ast.Slice) and head.lower is None
            and isinstance(head.upper, _ast.Constant)
            and isinstance(head.upper.value, int)):
        return None
    return (name, "left", head.upper.value)


def _blocks(stmt):
    """Every statement list a compound statement owns."""
    out = []
    for field in ("body", "orelse", "finalbody"):
        value = getattr(stmt, field, None)
        if isinstance(value, list) and value and isinstance(value[0], _ast.AST):
            out.append(value)
    for handler in getattr(stmt, "handlers", []) or []:
        out.append(handler.body)
    for case in getattr(stmt, "cases", []) or []:
        out.append(case.body)
    return out


def _loop_count(stmt):
    """`while _i < 4: ...rotate...; _i += 1` -> 4."""
    test = stmt.test
    if not (isinstance(test, _ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], (_ast.Lt, _ast.LtE))
            and isinstance(test.left, _ast.Name)
            and isinstance(test.comparators[0], _ast.Constant)
            and isinstance(test.comparators[0].value, int)):
        return None
    counter = test.left.id
    steps = 0
    for sub in stmt.body:
        if isinstance(sub, _ast.AugAssign) and isinstance(sub.target, _ast.Name) \
                and sub.target.id == counter and isinstance(sub.op, _ast.Add):
            steps += 1
        elif isinstance(sub, _ast.Assign) and isinstance(sub.value, _ast.BinOp) \
                and isinstance(sub.value.op, _ast.Add) \
                and any(isinstance(t, _ast.Name) and t.id == counter for t in sub.targets):
            steps += 1
    if steps != 1:
        return None
    bound = test.comparators[0].value
    return bound + 1 if isinstance(test.ops[0], _ast.LtE) else bound


def _loop_rotations(stmt, tables):
    """Rotations performed by one pass of a loop body, or None if opaque."""
    total = {}
    for sub in stmt.body:
        rotation = _rotation_of(sub, tables) or _slice_rotation(sub, tables)
        if rotation is not None:
            total[rotation[0]] = total.get(rotation[0], 0) + rotation[2]
            continue
        if isinstance(sub, (_ast.AugAssign, _ast.Pass)):
            continue
        if isinstance(sub, _ast.Assign) and len(sub.targets) == 1 \
                and isinstance(sub.targets[0], _ast.Name):
            continue                      # loop counter bookkeeping
        return None
    return total or None


def _touches(stmt, tables) -> set:
    hit = set()
    for sub in _ast.walk(stmt):
        if isinstance(sub, _ast.Name) and sub.id in tables:
            hit.add(sub.id)
    return hit


def _scan_rotations(body, tables, rotations, rotation_statements, unreplayable):
    """Replay array mutations; anything unrecognised taints its table."""
    for stmt in body or []:
        rotation = _rotation_of(stmt, tables) or _slice_rotation(stmt, tables)
        if rotation is not None:
            rotations[rotation[0]] = rotations.get(rotation[0], 0) + rotation[2]
            rotation_statements.append(stmt)
            continue

        if isinstance(stmt, (_ast.For, _ast.While)):
            times = None
            if isinstance(stmt, _ast.For) and isinstance(stmt.iter, _ast.Call) \
                    and isinstance(stmt.iter.func, _ast.Name) \
                    and stmt.iter.func.id == "range" and len(stmt.iter.args) == 1 \
                    and isinstance(stmt.iter.args[0], _ast.Constant) \
                    and isinstance(stmt.iter.args[0].value, int):
                times = stmt.iter.args[0].value
            elif isinstance(stmt, _ast.While):
                times = _loop_count(stmt)
            per_pass = _loop_rotations(stmt, tables) if times is not None else None
            if per_pass is not None:
                for name, amount in per_pass.items():
                    rotations[name] = rotations.get(name, 0) + times * amount
                rotation_statements.append(stmt)
                continue
            if _touches(stmt, tables) and not isinstance(stmt, _ast.While) or \
                    (isinstance(stmt, _ast.While) and _touches(stmt, tables)):
                unreplayable |= _touches(stmt, tables)
                continue

        for block in _blocks(stmt):
            _scan_rotations(block, tables, rotations, rotation_statements, unreplayable)


def _is_neg_one(node) -> bool:
    """`-1` parses as UnaryOp(USub, Constant(1)), not Constant(-1)."""
    if isinstance(node, _ast.Constant):
        return node.value == -1
    if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.USub) \
            and isinstance(node.operand, _ast.Constant):
        return node.operand.value == 1
    return False


def _decoder_chain(node):
    """Peel the wrappers an accessor puts around its table lookup."""
    ops = []
    while True:
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Attribute) and func.attr == "decode" \
                    and len(node.args) == 0:
                ops.append("decode")
                node = func.value
                continue
            name = None
            if isinstance(func, _ast.Name):
                name = func.id
            elif isinstance(func, _ast.Attribute):
                name = func.attr
            if name in _DECODERS and len(node.args) == 1:
                ops.append(name)
                node = node.args[0]
                continue
            if name == "join" and isinstance(func, _ast.Attribute):
                ops.append("join")
                node = func.value
                continue
            return None
        if isinstance(node, _ast.Subscript) and isinstance(node.slice, _ast.Slice):
            sl = node.slice
            if _is_neg_one(sl.step):
                ops.append("reverse")
                node = node.value
                continue
            return None
        if isinstance(node, _ast.Subscript) and isinstance(node.slice, _ast.Constant) \
                and isinstance(node.slice.value, int) and ops:
            # arr[i][0] style - not a decode, bail out
            return None
        return ops, node


_DECODERS = {"b64decode", "urlsafe_b64decode", "b32decode", "b16decode",
             "unhexlify", "a85decode", "b85decode", "decompress", "fromhex",
             "b85decode", "hexlify", "zlib_decompress"}


def _apply_ops(value, ops):
    data = value
    for op in reversed(ops):          # collected outermost-first
        if op == "decode":
            if isinstance(data, bytes):
                data = data.decode("utf-8", "replace")
            continue
        if op == "reverse":
            data = data[::-1]
            continue
        if op == "join":
            data = "".join(data) if isinstance(data, (list, tuple)) else data
            continue
        blob = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data
        try:
            if op in ("b64decode", "urlsafe_b64decode"):
                out = base64.b64decode(blob + b"=" * (-len(blob) % 4))
            elif op == "b32decode":
                out = base64.b32decode(blob + b"=" * (-len(blob) % 8))
            elif op in ("b16decode", "unhexlify"):
                compact = bytes(c for c in blob if c not in b" \t\r\n:-_")
                out = binascii.unhexlify(compact)
            elif op == "a85decode":
                out = base64.a85decode(blob)
            elif op in ("b85decode",):
                out = base64.b85decode(blob)
            elif op in ("decompress", "zlib_decompress") or blob[:1] in (b"\x78",):
                out = zlib.decompress(blob)
            elif op == "fromhex":
                out = bytes.fromhex(blob.decode("ascii", "ignore")
                                    if isinstance(blob, bytes) else blob)
            elif op == "hexlify":
                out = binascii.hexlify(blob)
            else:
                return None, False
        except Exception:                                  # noqa: BLE001
            return value, False
        data = out
    return data, True


def _accessor(fn, tables):
    """`def f(i): return arr[i - K]`  ->  (array, offset, ops)."""
    if isinstance(fn, _ast.Lambda):
        body = fn.body
    else:
        statements = [stmt for stmt in fn.body if not isinstance(stmt, _ast.Expr)
                      or not isinstance(stmt.value, _ast.Constant)]
        if len(statements) != 1 or not isinstance(statements[0], _ast.Return):
            return None
        body = statements[0].value
        if body is None:
            return None
    peeled = _decoder_chain(body)
    if peeled is None:
        return None
    ops, inner = peeled
    if not isinstance(inner, _ast.Subscript):
        return None
    if not isinstance(inner.value, _ast.Name) or inner.value.id not in tables:
        return None
    index = inner.slice
    offset = 0
    if isinstance(index, _ast.BinOp) and isinstance(index.op, (_ast.Sub, _ast.Add)):
        if not isinstance(index.right, _ast.Constant) or not isinstance(index.right.value, int):
            return None
        offset = -index.right.value if isinstance(index.op, _ast.Sub) else index.right.value
        index = index.left
    elif isinstance(index, _ast.Constant) and isinstance(index.value, int):
        return ("const", inner.value.id, index.value, ops)
    if not isinstance(index, _ast.Name):
        return None
    return (inner.value.id, offset, ops)


def _index_shape_ok(index) -> bool:
    """Constant indexes and `param +/- constant` indexes are the modelled forms."""
    if isinstance(index, _ast.Constant) and isinstance(index.value, int):
        return True
    if isinstance(index, _ast.Name):
        return True
    if isinstance(index, _ast.BinOp) and isinstance(index.op, (_ast.Add, _ast.Sub)):
        return (isinstance(index.left, _ast.Name)
                and isinstance(index.right, _ast.Constant))
    if isinstance(index, _ast.Slice):
        return True
    return False


def _lookup(table, index):
    if isinstance(table, tuple) and table and table[0] == "dict":
        return table[1].get(index)
    if 0 <= index < len(table):
        return table[index]
    return None


class _Resolver(_ast.NodeTransformer):
    def __init__(self, tables, accessors):
        self.tables = tables
        self.accessors = accessors
        self.resolved = 0

    def _value_for(self, accessor, index, node):
        table = self.tables.get(accessor[0]) if accessor[0] != "const" else None
        if accessor[0] == "const":
            table = self.tables.get(accessor[1])
            index = accessor[2]
            ops = accessor[3]
        else:
            ops = accessor[2]
        if table is None:
            return None
        raw = _lookup(table, index)
        if raw is None:
            return None
        value, ok = _apply_ops(raw, ops)
        if not ok or not isinstance(value, (str, bytes)):
            return None
        if isinstance(value, str) and len(value) > 4096:
            return None
        self.resolved += 1
        return _ast.copy_location(_ast.Constant(value=value), node)

    def visit_Call(self, node):                            # noqa: N802
        node = self.generic_visit(node)
        if not isinstance(node.func, _ast.Name) or node.func.id not in self.accessors:
            return node
        if len(node.args) != 1 or node.keywords:
            return node
        arg = node.args[0]
        if not (isinstance(arg, _ast.Constant) and isinstance(arg.value, int)):
            return node
        accessor = self.accessors[node.func.id]
        if accessor[0] == "const":
            replacement = self._value_for(accessor, None, node)
        else:
            replacement = self._value_for(accessor, arg.value + accessor[1], node)
        return replacement if replacement is not None else node

    def visit_Subscript(self, node):                       # noqa: N802
        node = self.generic_visit(node)
        if not isinstance(node.value, _ast.Name) or node.value.id not in self.tables:
            return node
        if not (isinstance(node.slice, _ast.Constant)
                and isinstance(node.slice.value, int)):
            return node
        raw = _lookup(self.tables[node.value.id], node.slice.value)
        if not isinstance(raw, (str, bytes)):
            return node
        self.resolved += 1
        return _ast.copy_location(_ast.Constant(value=raw), node)


def _names_bound(tree):
    bound = set()
    mutated = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, (_ast.Assign, _ast.AnnAssign, _ast.AugAssign)):
            targets = node.targets if isinstance(node, _ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, _ast.Name):
                    bound.add(target.id)
                elif isinstance(target, _ast.Subscript) and isinstance(target.value, _ast.Name):
                    mutated.add(target.value.id)
        elif isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute) \
                and isinstance(node.func.value, _ast.Name):
            if node.func.attr in ("append", "insert", "pop", "remove", "extend",
                                  "sort", "reverse", "clear", "__setitem__"):
                mutated.add(node.func.value.id)
    return bound, mutated


def resolve_string_arrays(tree) -> int:
    """Inline string-table lookups.  Returns the number of strings recovered."""
    try:
        if not isinstance(tree, _ast.Module):
            return 0
        bound, mutated = _names_bound(tree)

        tables = {}
        table_statements = {}
        for node in tree.body:
            if isinstance(node, _ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], _ast.Name):
                table = _literal_table(node.value)
                if table is None:
                    continue
                name = node.targets[0].id
                if isinstance(table, list) and len(table) > _TABLE_LIMIT:
                    continue
                tables[name] = table
                table_statements[name] = node

        if not tables:
            return 0

        # rotations: replay every mutation we understand, refuse the rest
        rotations = {}
        unreplayable = set()
        rotation_statements = []
        _scan_rotations(tree.body, tables, rotations, rotation_statements,
                        unreplayable)

        for name in unreplayable:
            tables.pop(name, None)

        for name, times in rotations.items():
            if name not in tables:
                continue
            if times > _ROTATION_LIMIT:
                tables.pop(name, None)
                continue
            tables[name] = _rotate_left(tables[name], times)

        # anything else touching a table makes it untrustworthy
        unsafe = set()
        for node in _ast.walk(tree):
            # a table passed to something we do not model (random.shuffle,
            # list(...), a helper function) can be rearranged behind our back
            if isinstance(node, _ast.Call):
                for argument in list(node.args) + [kw.value for kw in node.keywords]:
                    if isinstance(argument, _ast.Name) and argument.id in tables:
                        unsafe.add(argument.id)
                    elif isinstance(argument, _ast.Starred) \
                            and isinstance(argument.value, _ast.Name) \
                            and argument.value.id in tables:
                        unsafe.add(argument.value.id)
            if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute) \
                    and isinstance(node.func.value, _ast.Name) \
                    and node.func.value.id in tables:
                attr = node.func.attr
                if attr not in ("append", "insert", "pop", "decompress"):
                    unsafe.add(node.func.value.id)
            if isinstance(node, _ast.Subscript) and isinstance(node.value, _ast.Name) \
                    and node.value.id in tables \
                    and not _index_shape_ok(node.slice):
                unsafe.add(node.value.id)
        for name in unsafe:
            tables.pop(name, None)
        if not tables:
            return 0

        accessors = {}
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                found = _accessor(node, tables)
                if found:
                    accessors[node.name] = found
            elif isinstance(node, _ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], _ast.Name) \
                    and isinstance(node.value, _ast.Lambda):
                found = _accessor(node.value, tables)
                if found:
                    accessors[node.targets[0].id] = found

        if not accessors and not any(
                isinstance(n, _ast.Subscript) and isinstance(n.value, _ast.Name)
                and n.value.id in tables for n in _ast.walk(tree)):
            return 0

        resolver = _Resolver(tables, accessors)
        tree.body = [resolver.visit(stmt) for stmt in tree.body]
        resolved = resolver.resolved
        if not resolved:
            return 0

        # drop the scaffolding that is now unreferenced.  Two passes: the
        # rotation/counter statements go first so that the table and the
        # accessor really do look unused by the time we judge them.
        def target_name(stmt):
            if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], _ast.Name):
                return stmt.targets[0].id
            if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                return stmt.name
            return None

        def used_names(body):
            return {node.id for stmt in body for node in _ast.walk(stmt)
                    if isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Load)}

        scaffolding = set(tables) | set(accessors)
        kept = [stmt for stmt in tree.body if stmt not in rotation_statements]

        # counters and offset keys whose only reader was the rotation loop
        used = used_names(kept)
        pruned = []
        for stmt in kept:
            name = target_name(stmt)
            if name is not None and name not in scaffolding and name not in used \
                    and isinstance(stmt, _ast.Assign) \
                    and isinstance(stmt.value, _ast.Constant):
                continue
            pruned.append(stmt)
        kept = pruned

        for _round in range(4):
            before = len(kept)
            used = used_names(kept)
            kept = [stmt for stmt in kept
                    if not (target_name(stmt) in scaffolding
                            and target_name(stmt) not in used)]
            if len(kept) == before:
                break
        tree.body = kept
        return resolved
    except Exception:                                      # noqa: BLE001 - cosmetic pass
        return 0
