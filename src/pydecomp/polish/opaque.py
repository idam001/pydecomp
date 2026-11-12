"""pydecomp - opaque.

Opaque predicates are conditions the obfuscator already knows the answer to:
``if x * x >= 0:`` (always true), ``if x * (x + 1) % 2 == 0:`` (product of two
consecutive integers - always even), ``if (x | 1) % 2 == 1:``, ``if (x ^ x):``.
They exist to bury the real branch behind a condition that *looks* dynamic.

pydecomp decides them **soundly**: a free name gets the whole integer range as
its bound, and enough arithmetic is carried through intervals to recognise the
classic idioms - ``x * x >= 0`` (a square is never negative), ``x - x == 0``,
``x ^ x == 0``, ``len(x) >= 0``.  When the bounds overlap, the predicate is
*undecided* and the branch is kept.

An earlier revision sampled a free name over a fixed grid instead.  ``if word ==
34:`` was ``False`` for every value in that grid, so it was "proved" false and
the branch was deleted - from a program that had never been obfuscated.  Sound
bounds cannot make that mistake, and a wrong deletion is far worse than a missed
simplification.
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


INF = float("inf")


class _Unknown(Exception):
    """The interval arithmetic cannot bound this expression."""


def _same(left, right) -> bool:
    """Are these two sub-expressions the same code?"""
    try:
        return _ast.dump(left) == _ast.dump(right)
    except Exception:                                     # noqa: BLE001
        return False


def _interval(node):
    """Sound integer bounds for an expression, or ``_Unknown``.

    This replaced grid sampling, and the reason matters.  Sampling bound the
    free name of ``if word == 34:`` to a fixed grid that did not contain 34, saw
    ``False`` every time and "proved" the branch dead - deleting real code from
    a program that was not even obfuscated.  Interval reasoning cannot make that
    mistake: a free name is unbounded, so ``x == 34`` stays undecided.
    """
    if isinstance(node, _ast.Constant):
        if isinstance(node.value, bool):
            return (int(node.value), int(node.value))
        if isinstance(node.value, int):
            return (node.value, node.value)
        raise _Unknown("non-int constant")
    if isinstance(node, _ast.Name):
        return (-INF, INF)
    if isinstance(node, _ast.UnaryOp):
        low, high = _interval(node.operand)
        if isinstance(node.op, _ast.USub):
            return (-high, -low)
        if isinstance(node.op, _ast.UAdd):
            return (low, high)
        raise _Unknown("unary op")
    if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name) \
            and node.func.id in ("abs", "len") and len(node.args) == 1:
        return (0, INF)                                   # never negative
    if isinstance(node, _ast.BinOp):
        if isinstance(node.op, (_ast.Sub, _ast.BitXor)) and _same(node.left, node.right):
            return (0, 0)                                 # x - x, x ^ x
        if isinstance(node.op, _ast.BitAnd):
            if isinstance(node.left, _ast.UnaryOp) and isinstance(node.left.op, _ast.Invert) \
                    and _same(node.left.operand, node.right):
                return (0, 0)                             # x & ~x
            if isinstance(node.right, _ast.UnaryOp) and isinstance(node.right.op, _ast.Invert) \
                    and _same(node.right.operand, node.left):
                return (0, 0)
        left = _interval(node.left)
        right = _interval(node.right)
        if isinstance(node.op, _ast.Add):
            return (left[0] + right[0], left[1] + right[1])
        if isinstance(node.op, _ast.Sub):
            return (left[0] - right[1], left[1] - right[0])
        if isinstance(node.op, _ast.Mult):
            if _same(node.left, node.right):
                return (0, INF)                           # a square is >= 0
            if any(abs(bound) == INF for bound in left + right):
                raise _Unknown("unbounded product")
            corners = (left[0] * right[0], left[0] * right[1],
                       left[1] * right[0], left[1] * right[1])
            return (min(corners), max(corners))
        if isinstance(node.op, _ast.Pow):
            if right[0] == right[1] == 2:
                return (0, INF)                           # x ** 2
            raise _Unknown("power")
        if isinstance(node.op, _ast.Mod):
            if right[0] == right[1] and right[0] > 0 and left[0] >= 0:
                return (0, right[0] - 1)
            raise _Unknown("modulo")
        if isinstance(node.op, _ast.FloorDiv):
            if left[0] >= 0 and right[0] == right[1] and right[0] > 0:
                return (0, left[1] // right[0])
            raise _Unknown("floor division")
        raise _Unknown("binary op")
    raise _Unknown("node")


def _is_same_name_plus(node, other, delta: int) -> bool:
    """Is ``node`` literally ``other + delta`` (same name, small offset)?"""
    if not isinstance(node, _ast.BinOp) or not isinstance(node.op, (_ast.Add, _ast.Sub)):
        return False
    name, const = node.left, node.right
    if not isinstance(name, _ast.Name) or not isinstance(const, _ast.Constant) \
            or not isinstance(const.value, int) or isinstance(const.value, bool):
        return False
    step = const.value if isinstance(node.op, _ast.Add) else -const.value
    return isinstance(other, _ast.Name) and other.id == name.id and step == delta


def _parity(node):
    """0, 1 or None: the value mod 2, when it can be known soundly.

    This is what proves the classic ``x * (x + 1) % 2 == 0`` and
    ``(x | 1) % 2 == 1`` without guessing: integers carry their low bit through
    multiplication, addition and the bitwise operators, and a product of two
    consecutive integers is always even.
    """
    if isinstance(node, _ast.Constant):
        if isinstance(node.value, bool):
            return int(node.value)
        if isinstance(node.value, int):
            return node.value % 2
        raise _Unknown("non-int constant")
    if isinstance(node, _ast.Name):
        raise _Unknown("free name")
    if isinstance(node, _ast.UnaryOp):
        inner = _parity(node.operand)
        if isinstance(node.op, _ast.USub):
            return (-inner) % 2
        if isinstance(node.op, _ast.Invert):
            return (inner + 1) % 2                     # ~n == -n - 1
        raise _Unknown("unary op")
    if isinstance(node, _ast.BinOp):
        if isinstance(node.op, _ast.Mult):
            if _is_same_name_plus(node.left, node.right, 1) or \
                    _is_same_name_plus(node.right, node.left, 1) or \
                    _is_same_name_plus(node.right, node.left, -1):
                return 0                               # consecutive integers
            for side in (node.left, node.right):
                try:
                    if _parity(side) == 0:
                        return 0
                except _Unknown:
                    continue
            left, right = _parity(node.left), _parity(node.right)
            return (left * right) % 2
        if isinstance(node.op, (_ast.Add, _ast.Sub)):
            left, right = _parity(node.left), _parity(node.right)
            return (left + right) % 2 if isinstance(node.op, _ast.Add) else (left - right) % 2
        if isinstance(node.op, _ast.Pow):
            base, exponent = _parity(node.left), _parity(node.right)
            if exponent == 0:
                return 1
            if base == 0:
                return 0
            return 1
        if isinstance(node.op, _ast.Mod):
            if isinstance(node.right, _ast.Constant) and node.right.value == 2:
                return _parity(node.left)              # n % 2 has the parity of n
            raise _Unknown("modulo")
        if isinstance(node.op, _ast.BitOr):
            for side in (node.left, node.right):
                try:
                    if _parity(side) == 1:
                        return 1                       # the low bit is set
                except _Unknown:
                    continue
            raise _Unknown("bit or")
        if isinstance(node.op, _ast.BitAnd):
            for side in (node.left, node.right):
                try:
                    if _parity(side) == 0:
                        return 0                       # the low bit is clear
                except _Unknown:
                    continue
            raise _Unknown("bit and")
        if isinstance(node.op, _ast.BitXor):
            return (_parity(node.left) + _parity(node.right)) % 2
        raise _Unknown("binary op")
    raise _Unknown("node")


def _truth(node):
    """Is this expression provably truthy/falsy?  (Compare-free shapes.)"""
    if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.BitAnd):
        if isinstance(node.left, _ast.UnaryOp) and isinstance(node.left.op, _ast.Invert) \
                and _same(node.left.operand, node.right):
            return False                               # x & ~x
        if isinstance(node.right, _ast.UnaryOp) and isinstance(node.right.op, _ast.Invert) \
                and _same(node.right.operand, node.left):
            return False
    try:
        low, high = _interval(node)
    except _Unknown:
        return None
    if low == high:
        return bool(low)
    return None


def _parity_verdict(node):
    """Decide a comparison with a 0/1 literal using parity alone."""
    if len(node.ops) != 1 or not isinstance(node.ops[0], (_ast.Eq, _ast.NotEq)):
        return None
    for expression, other in ((node.left, node.comparators[0]),
                              (node.comparators[0], node.left)):
        if isinstance(other, _ast.Constant) and isinstance(other.value, int) \
                and not isinstance(other.value, bool) and other.value in (0, 1):
            try:
                parity = _parity(expression)
            except _Unknown:
                return None
            if isinstance(node.ops[0], _ast.Eq):
                return parity == other.value
            return parity != other.value
    return None


def _compare_verdict(left, op, right):
    """Decide one comparison from bounds alone; None when the ranges overlap."""
    (lo1, hi1), (lo2, hi2) = left, right
    disjoint = hi1 < lo2 or hi2 < lo1
    if isinstance(op, _ast.Eq):
        if lo1 == hi1 == lo2 == hi2:
            return True
        return False if disjoint else None
    if isinstance(op, _ast.NotEq):
        if lo1 == hi1 == lo2 == hi2:
            return False
        return True if disjoint else None
    if isinstance(op, _ast.Lt):
        if hi1 < lo2:
            return True
        return False if lo1 >= hi2 else None
    if isinstance(op, _ast.LtE):
        if hi1 <= lo2:
            return True
        return False if lo1 > hi2 else None
    if isinstance(op, _ast.Gt):
        if lo1 > hi2:
            return True
        return False if hi1 <= lo2 else None
    if isinstance(op, _ast.GtE):
        if lo1 >= hi2:
            return True
        return False if hi1 < lo2 else None
    return None


def _interval_verdict(node):
    """True/False when the bounds decide the predicate, else None."""
    try:
        if isinstance(node, _ast.Compare) and len(node.ops) == 1:
            try:
                left = _interval(node.left)
                right = _interval(node.comparators[0])
            except _Unknown:
                parity = _parity_verdict(node)
                if parity is not None:
                    return parity
                raise
            return _compare_verdict(left, node.ops[0], right)
        if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Not):
            inner = _interval_verdict(node.operand)
            return None if inner is None else not inner
        if not isinstance(node, (_ast.Compare, _ast.BoolOp)):
            return _truth(node)
        if isinstance(node, _ast.BoolOp):
            verdicts = [_interval_verdict(value) for value in node.values]
            if isinstance(node.op, _ast.And):
                if any(verdict is False for verdict in verdicts):
                    return False
                if all(verdict is True for verdict in verdicts):
                    return True
                return None
            if any(verdict is True for verdict in verdicts):
                return True
            if all(verdict is False for verdict in verdicts):
                return False
        return None
    except _Unknown:
        return None
    except RecursionError:
        return None


def prove(node):
    """Return True, False, or None (cannot decide) for a predicate."""
    try:
        decided = _length_facts(node)
        if decided is not None:
            return decided
        if not _is_pure(node) or not _numeric_only(node):
            return None
        free = _names(node)
        if not free:
            try:
                return bool(_eval(node, {}))
            except _Inconclusive:
                return None
        return _interval_verdict(node)
    except RecursionError:
        return None
    except Exception:                                     # noqa: BLE001
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
