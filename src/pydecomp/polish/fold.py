"""pydecomp - fold."""
from __future__ import annotations

import base64
import binascii

from ..decoders.hex_loose import _strip_separators
from ..polish.demangle import _ast

def _const_node(value) -> "_ast.AST | None":
    try:
        return _ast.parse(repr(value), mode="eval").body
    except Exception:                                # noqa: BLE001
        return None

def _pure_constant(node) -> bool:
    """True when the expression is made only of literals and operators."""
    if isinstance(node, _ast.Constant):
        return True
    if isinstance(node, _ast.UnaryOp):
        return _pure_constant(node.operand)
    if isinstance(node, _ast.BinOp):
        return _pure_constant(node.left) and _pure_constant(node.right)
    if isinstance(node, _ast.BoolOp):
        return all(_pure_constant(value) for value in node.values)
    if isinstance(node, _ast.Compare):
        return _pure_constant(node.left) and all(_pure_constant(c)
                                                 for c in node.comparators)
    if isinstance(node, (_ast.Tuple, _ast.List, _ast.Set)):
        return all(_pure_constant(item) for item in node.elts)
    if isinstance(node, _ast.Dict):
        return all(_pure_constant(k) and _pure_constant(v)
                   for k, v in zip(node.keys, node.values) if k is not None)
    if isinstance(node, _ast.JoinedStr):
        return all(isinstance(v, _ast.Constant)
                   or (isinstance(v, _ast.FormattedValue) and _pure_constant(v.value))
                   for v in node.values)
    return False

_MAX_FOLD_LENGTH = 200_000

def _eval_const(node):
    """Evaluate a literal-only node, including comparisons literal_eval refuses."""
    if isinstance(node, _ast.Constant):
        return node.value
    if isinstance(node, _ast.UnaryOp):
        value = _eval_const(node.operand)
        return {_ast.USub: lambda v: -v, _ast.UAdd: lambda v: +v,
                _ast.Not: lambda v: not v, _ast.Invert: lambda v: ~v}[
                    type(node.op)](value)
    if isinstance(node, _ast.BinOp):
        left, right = _eval_const(node.left), _eval_const(node.right)
        if isinstance(node.op, _ast.Mult) and isinstance(left, (str, bytes)) \
                and len(left) * max(int(right), 0) > 1_000_000:
            raise ValueError("huge repeat")
        for klass, fn in ((_ast.Add, lambda a, b: a + b),
                          (_ast.Sub, lambda a, b: a - b),
                          (_ast.Mult, lambda a, b: a * b),
                          (_ast.Div, lambda a, b: a / b),
                          (_ast.FloorDiv, lambda a, b: a // b),
                          (_ast.Mod, lambda a, b: a % b),
                          (_ast.Pow, lambda a, b: a ** b),
                          (_ast.BitOr, lambda a, b: a | b),
                          (_ast.BitXor, lambda a, b: a ^ b),
                          (_ast.BitAnd, lambda a, b: a & b),
                          (_ast.LShift, lambda a, b: a << b),
                          (_ast.RShift, lambda a, b: a >> b)):
            if isinstance(node.op, klass):
                return fn(left, right)
        raise ValueError("binop")
    if isinstance(node, _ast.BoolOp):
        values = [_eval_const(v) for v in node.values]
        if isinstance(node.op, _ast.And):
            result = values[0]
            for value in values[1:]:
                result = value if result else result
            return result
        result = values[0]
        for value in values[1:]:
            result = result if result else value
        return result
    if isinstance(node, _ast.Compare):
        left = _eval_const(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval_const(comparator)
            for klass, fn in ((_ast.Eq, lambda a, b: a == b),
                              (_ast.NotEq, lambda a, b: a != b),
                              (_ast.Lt, lambda a, b: a < b),
                              (_ast.LtE, lambda a, b: a <= b),
                              (_ast.Gt, lambda a, b: a > b),
                              (_ast.GtE, lambda a, b: a >= b),
                              (_ast.In, lambda a, b: a in b),
                              (_ast.NotIn, lambda a, b: a not in b)):
                if isinstance(op, klass):
                    if not fn(left, right):
                        return False
                    break
            left = right
        return True
    return _ast.literal_eval(node)

def _fold_constants(tree):
    """Evaluate literal-only expressions once, so the reader sees the value."""
    def visit(node):
        for child in _ast.iter_child_nodes(node):
            visit(child)
        if not isinstance(node, (_ast.BinOp, _ast.UnaryOp, _ast.Compare,
                                 _ast.BoolOp, _ast.JoinedStr)):
            return
        if not _pure_constant(node):
            return
        try:
            value = _eval_const(node)
        except Exception:                            # noqa: BLE001 - not literal
            return
        if isinstance(value, (str, bytes)) and len(value) > _MAX_FOLD_LENGTH:
            return
        replacement = _const_node(value)
        if replacement is None:
            return
        node.__class__ = replacement.__class__
        node.__dict__.clear()
        node.__dict__.update(replacement.__dict__)

    visit(tree)
    return tree

def _fold_literals(tree):
    """Decode literals that are *already* an encoded payload plus its decoder."""
    changed = 0
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        if len(node.args) != 1 or node.keywords:
            continue
        argument = node.args[0]
        if not isinstance(argument, _ast.Constant) or not isinstance(
                argument.value, (str, bytes)):
            continue
        if len(argument.value) < 64:
            continue
        try:
            dotted = "_ast.unparse(node.func)"
        except Exception:                            # noqa: BLE001
            continue
        dotted = dotted.replace(" ", "")
        decoders = {"b64decode", "b64decode", "b32decode", "b16decode", "unhexlify",
                    "a85decode", "b85decode", "urlsafe_b64decode"}
        last = dotted.rsplit(".", 1)[-1]
        if last not in decoders:
            continue
        blob = (argument.value.encode("utf-8", "surrogateescape")
                if isinstance(argument.value, str) else argument.value)
        try:
            if last in ("b64decode", "urlsafe_b64decode"):
                out = base64.b64decode(blob + b"=" * (-len(blob) % 4))
            elif last == "b32decode":
                out = base64.b32decode(blob + b"=" * (-len(blob) % 8))
            elif last == "b16decode":
                out = binascii.unhexlify(_strip_separators(blob))
            elif last == "unhexlify":
                out = binascii.unhexlify(_strip_separators(blob))
            elif last == "a85decode":
                out = base64.a85decode(blob)
            else:
                out = base64.b85decode(blob)
        except Exception:                            # noqa: BLE001
            continue
        if not out:
            continue
        replacement = _const_node(out)
        if replacement is None:
            continue
        node.__class__ = replacement.__class__
        node.__dict__.clear()
        node.__dict__.update(replacement.__dict__)
        changed += 1
    return changed
