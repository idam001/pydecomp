"""pydecomp - opaque.

Opaque predicates are conditions the obfuscator already knows the answer to:
``if x * x >= 0:`` (always true), ``if x * (x + 1) % 2 == 0:`` (product of two
consecutive integers - always even), ``if (x | 1) % 2 == 1:``, ``if (x ^ x):``.
They exist to bury the real branch behind a condition that *looks* dynamic.

pydecomp decides them with a bounded arithmetic interpreter: the predicate is
evaluated over a grid of integers covering zero, small negatives, powers of two
and a large odd value.  If every sample agrees, and the expression only uses
arithmetic/comparison/boolean nodes plus a tiny allowlist of pure builtins, the
condition is treated as decided and the dead side is dropped.

The interpreter only understands integers, constants, compares, booleans, and
``len/abs/ord/int/bool/min/max/sum`` on pure arguments.  It cannot import,
attribute-access, or call anything the file defines, so proving a predicate
never runs the sample.
"""
from __future__ import annotations

import ast

from ..polish.demangle import _ast

_GRID = (-7, -3, -1, 0, 1, 2, 3, 4, 5, 7, 8, 13, 64, 255, 1337)

_ALLOWED_CALLS = {"len", "abs", "ord", "int", "bool", "min", "max", "sum"}

_ARITH = (_ast.Add, _ast.Sub, _ast.Mult, _ast.FloorDiv, _ast.Mod,
          _ast.Pow, _ast.LShift, _ast.RShift, _ast.BitAnd, _ast.BitOr,
          _ast.BitXor)


class _Inconclusive(Exception):
    pass


def _is_pure(node) -> bool:
    """Only shapes the bounded evaluator can reason about."""
    if isinstance(node, _ast.Constant):
        return isinstance(node.value, (int, bool, str, type(None)))
    if isinstance(node, _ast.Name):
        return True
    if isinstance(node, _ast.BinOp):
        if not isinstance(node.op, _ARITH + (_ast.Div,)):
            return False
        return _is_pure(node.left) and _is_pure(node.right)
    if isinstance(node, _ast.UnaryOp):
        if not isinstance(node.op, (_ast.UAdd, _ast.USub, _ast.Invert, _ast.Not)):
            return False
        return _is_pure(node.operand)
    if isinstance(node, _ast.BoolOp):
        return all(_is_pure(v) for v in node.values)
    if isinstance(node, _ast.Compare):
        if not isinstance(node.left, _ast.AST):
            return False
        return _is_pure(node.left) and all(_is_pure(c) for c in node.comparators)
    if isinstance(node, _ast.Call):
        if not isinstance(node.func, _ast.Name) or node.func.id not in _ALLOWED_CALLS:
            return False
        return not node.keywords and all(_is_pure(a) for a in node.args)
    if isinstance(node, (_ast.Tuple, _ast.List)):
        return all(_is_pure(e) for e in node.elts)
    if isinstance(node, _ast.IfExp):
        return _is_pure(node.test) and _is_pure(node.body) and _is_pure(node.orelse)
    return False


def _eval(node, env):
    if isinstance(node, _ast.Constant):
        return node.value
    if isinstance(node, _ast.Name):
        if node.id not in env:
            raise _Inconclusive(node.id)
        return env[node.id]
    if isinstance(node, _ast.BinOp):
        left, right = _eval(node.left, env), _eval(node.right, env)
        try:
            if isinstance(node.op, _ast.Add):
                return left + right
            if isinstance(node.op, _ast.Sub):
                return left - right
            if isinstance(node.op, _ast.Mult):
                return left * right
            if isinstance(node.op, _ast.FloorDiv):
                return left // right
            if isinstance(node.op, _ast.Div):
                return left / right
            if isinstance(node.op, _ast.Mod):
                return left % right
            if isinstance(node.op, _ast.Pow):
                if isinstance(node, _ast.BinOp) and isinstance(node.right, _ast.Constant) \
                        and isinstance(node.right.value, int) and node.right.value > 64:
                    raise _Inconclusive("huge power")
                return left ** right
            if isinstance(node.op, _ast.LShift):
                if right > 64:
                    raise _Inconclusive("huge shift")
                return left << right
            if isinstance(node.op, _ast.RShift):
                return left >> right
            if isinstance(node.op, _ast.BitAnd):
                return left & right
            if isinstance(node.op, _ast.BitOr):
                return left | right
            if isinstance(node.op, _ast.BitXor):
                return left ^ right
        except (_Inconclusive,):
            raise
        except Exception as exc:                          # noqa: BLE001
            raise _Inconclusive(str(exc)) from None
        raise _Inconclusive("operator")
    if isinstance(node, _ast.UnaryOp):
        value = _eval(node.operand, env)
        try:
            if isinstance(node.op, _ast.UAdd):
                return +value
            if isinstance(node.op, _ast.USub):
                return -value
            if isinstance(node.op, _ast.Invert):
                return ~value
            if isinstance(node.op, _ast.Not):
                return not value
        except Exception as exc:                          # noqa: BLE001
            raise _Inconclusive(str(exc)) from None
        raise _Inconclusive("unary")
    if isinstance(node, _ast.BoolOp):
        values = [_eval(v, env) for v in node.values]
        if isinstance(node.op, _ast.And):
            return all(values)
        return any(values)
    if isinstance(node, _ast.Compare):
        left = _eval(node.left, env)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, env)
            try:
                if isinstance(op, _ast.Eq):
                    ok = left == right
                elif isinstance(op, _ast.NotEq):
                    ok = left != right
                elif isinstance(op, _ast.Lt):
                    ok = left < right
                elif isinstance(op, _ast.LtE):
                    ok = left <= right
                elif isinstance(op, _ast.Gt):
                    ok = left > right
                elif isinstance(op, _ast.GtE):
                    ok = left >= right
                elif isinstance(op, _ast.Is):
                    ok = left is right
                elif isinstance(op, _ast.IsNot):
                    ok = left is not right
                elif isinstance(op, _ast.In):
                    ok = left in right
                elif isinstance(op, _ast.NotIn):
                    ok = left not in right
                else:
                    raise _Inconclusive("compare")
            except _Inconclusive:
                raise
            except Exception as exc:                      # noqa: BLE001
                raise _Inconclusive(str(exc)) from None
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, _ast.Call):
        if isinstance(node.func, _ast.Name):
            args = [_eval(a, env) for a in node.args]
            name = node.func.id
            try:
                if name == "len":
                    return len(args[0])
                if name == "abs":
                    return abs(args[0])
                if name == "ord":
                    return ord(args[0])
                if name == "int":
                    return int(*args)
                if name == "bool":
                    return bool(*args)
                if name == "min":
                    return min(args)
                if name == "max":
                    return max(args)
                if name == "sum":
                    return sum(args[0]) if len(args) == 1 else sum(args)
            except _Inconclusive:
                raise
            except Exception as exc:                      # noqa: BLE001
                raise _Inconclusive(str(exc)) from None
        raise _Inconclusive("call")
    if isinstance(node, (_ast.Tuple, _ast.List)):
        return [_eval(e, env) for e in node.elts]
    if isinstance(node, _ast.IfExp):
        return _eval(node.body, env) if _eval(node.test, env) else _eval(node.orelse, env)
    raise _Inconclusive("node")


def _names(node) -> list[str]:
    out = []
    for sub in _ast.walk(node):
        if isinstance(sub, _ast.Name) and sub.id not in _ALLOWED_CALLS:
            if sub.id not in out:
                out.append(sub.id)
    return out


def _numeric_only(node) -> bool:
    """A predicate is only samplable when every literal in it is a number.

    Sampling binds each free name to an int, so ``x == "__main__"`` would look
    provably false while the real binding is a string.  Anything carrying a
    string, bytes, None or f-string constant is therefore left unproved.
    """
    for sub in _ast.walk(node):
        if isinstance(sub, _ast.Constant) and not isinstance(sub.value, (int, bool)):
            return False
        if isinstance(sub, _ast.JoinedStr):
            return False
    return True


def _length_facts(node):
    """``len(x) >= 0`` holds for any object with a length; ``< 0`` never does."""
    if not (isinstance(node, _ast.Compare) and len(node.ops) == 1):
        return None
    left = node.left
    if not (isinstance(left, _ast.Call) and isinstance(left.func, _ast.Name)
            and left.func.id == "len" and len(left.args) == 1):
        return None
    right = node.comparators[0]
    if not (isinstance(right, _ast.Constant) and right.value == 0):
        return None
    op = node.ops[0]
    if isinstance(op, (_ast.GtE, _ast.Gt)):
        return True
    if isinstance(op, (_ast.LtE, _ast.Lt)):
        return False
    if isinstance(op, _ast.NotEq):
        return True
    return None


def prove(node):
    """Return True, False, or None (cannot decide) for a predicate."""
    try:
        decided = _length_facts(node)
        if decided is not None:
            return decided
        if not _is_pure(node):
            return None
        if not _numeric_only(node):
            return None
        free = _names(node)
        if len(free) == 0:
            try:
                return bool(_eval(node, {}))
            except _Inconclusive:
                return None
        if len(free) > 2:
            return None
        if len(free) == 1:
            samples = [{free[0]: v} for v in _GRID]
        else:
            samples = [{free[0]: a, free[1]: b} for a in _GRID for b in _GRID]
        results = set()
        for env in samples:
            try:
                results.add(bool(_eval(node, env)))
            except _Inconclusive:
                continue
        if len(results) == 1:
            return results.pop()
    except RecursionError:
        return None
    except Exception:                                     # noqa: BLE001
        return None
    return None


class _OpaquePruner(_ast.NodeTransformer):
    def __init__(self):
        self.pruned = 0

    def _block(self, body):
        if body is None:
            return []
        out = []
        for stmt in body:
            if stmt is None:
                continue
            result = self.visit(stmt)
            if result is None:
                continue
            if isinstance(result, list):
                out.extend(item for item in result if item is not None)
            else:
                out.append(result)
        return out

    def visit_If(self, node):                             # noqa: N802
        node.test = self.visit(node.test)
        verdict = prove(node.test)
        if verdict is True:
            self.pruned += 1
            return self._block(node.body)
        if verdict is False:
            self.pruned += 1
            return self._block(node.orelse)
        node.body = self._block(node.body)
        node.orelse = self._block(node.orelse)
        return node

    def visit_While(self, node):                          # noqa: N802
        node.test = self.visit(node.test)
        if prove(node.test) is False and not node.orelse:
            self.pruned += 1
            return None
        node.body = self._block(node.body)
        node.orelse = self._block(node.orelse)
        return node

    def visit_IfExp(self, node):                          # noqa: N802
        node.test = self.visit(node.test)
        verdict = prove(node.test)
        if verdict is True:
            self.pruned += 1
            return self.visit(node.body)
        if verdict is False:
            self.pruned += 1
            return self.visit(node.orelse)
        return self.generic_visit(node)

    def generic_visit(self, node):
        for field, value in _ast.iter_fields(node):
            if isinstance(value, list) and value and isinstance(value[0], _ast.AST):
                flat = []
                for item in value:
                    if item is None:
                        continue
                    result = self.visit(item)
                    if result is None:
                        continue
                    if isinstance(result, list):      # a pruned branch expands here
                        flat.extend(part for part in result if part is not None)
                    else:
                        flat.append(result)
                setattr(node, field, flat)
            elif isinstance(value, _ast.AST):
                result = self.visit(value)
                if result is not None:
                    setattr(node, field, result)
        return node


def strip_opaque(tree) -> int:
    """Drop branches guarded by provably constant conditions."""
    try:
        pruner = _OpaquePruner()
        tree.body = pruner._block(tree.body)
        return pruner.pruned
    except Exception:                                     # noqa: BLE001 - cosmetic
        return 0
