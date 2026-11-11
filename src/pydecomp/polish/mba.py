"""pydecomp - mba.

Mixed-boolean-arithmetic rehearsal: obfuscators hide ``a + b`` as
``(a ^ b) + 2 * (a & b)`` and friends, so the constant table, the loop bound and
the key derivation all become arithmetic puzzles.

Every rule below is *proved* before it is used: pydecomp evaluates the rule's
own two templates over a grid of integers (including negatives and zero) at
import time and only installs a rule whose halves agree on every sample.  The
user's code is never evaluated - the templates are our own source text, and the
rewrite is a pure structural substitution of matched subexpressions.

Rules come from the published MBA identity set:

    x + y = (x ^ y) + 2 * (x & y)
    x + y = (x | y) + (x & y)
    x ^ y = (x | y) - (x & y)
    x & y = (x | y) - (x ^ y)
    x | y = (x & y) + (x ^ y)
    x - y = (x ^ y) - 2 * (~x & y)
"""
from __future__ import annotations

import ast
import itertools

from ..polish.demangle import _ast

# --------------------------------------------------------------------------
# rule tables.  A pattern is a tuple-tree of our own making; "$x"/"$y" are
# metavariables.  Patterns are matched against real AST nodes after being
# normalised through _template().
# --------------------------------------------------------------------------

# ("op", left, right) / ("bitnot", e) / ("mul2", e) / ("$var", name) / int
_METAVARS = ("$x", "$y")

_RULES = [
    # (a ^ b) + 2 * (a & b)   ->  a + b
    (("op", "+", ("op", "^", "$x", "$y"), ("mul2", ("op", "&", "$x", "$y"))),
     ("op", "+", "$x", "$y")),
    # (a ^ b) + 2 * (b & a)   ->  a + b
    (("op", "+", ("op", "^", "$x", "$y"), ("mul2", ("op", "&", "$y", "$x"))),
     ("op", "+", "$x", "$y")),
    # (a | b) + (a & b)       ->  a + b
    (("op", "+", ("op", "|", "$x", "$y"), ("op", "&", "$x", "$y")),
     ("op", "+", "$x", "$y")),
    # (a & b) + (a | b)       ->  a + b
    (("op", "+", ("op", "&", "$x", "$y"), ("op", "|", "$x", "$y")),
     ("op", "+", "$x", "$y")),
    # (a | b) - (a & b)       ->  a ^ b
    (("op", "-", ("op", "|", "$x", "$y"), ("op", "&", "$x", "$y")),
     ("op", "^", "$x", "$y")),
    # (a & b) + (a ^ b)       ->  a | b
    (("op", "+", ("op", "&", "$x", "$y"), ("op", "^", "$x", "$y")),
     ("op", "|", "$x", "$y")),
    # (a | b) - (a ^ b)       ->  a & b
    (("op", "-", ("op", "|", "$x", "$y"), ("op", "^", "$x", "$y")),
     ("op", "&", "$x", "$y")),
    # (a ^ b) - 2 * (~a & b)  ->  a - b
    (("op", "-", ("op", "^", "$x", "$y"), ("mul2", ("op", "&", ("bitnot", "$x"), "$y"))),
     ("op", "-", "$x", "$y")),
    # 2 * (a & b) + (a ^ b)   ->  a + b    (commuted)
    (("op", "+", ("mul2", ("op", "&", "$x", "$y")), ("op", "^", "$x", "$y")),
     ("op", "+", "$x", "$y")),
    # (a & b) << 1 + (a ^ b)  handled as mul2 above only when *; keep simple
]


def _template(node) -> object:
    """Reduce an AST node to a comparable tuple-tree (no side-effect shapes)."""
    if isinstance(node, _ast.Constant) and isinstance(node.value, int) \
            and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, _ast.Name):
        return ("$var", node.id)
    if isinstance(node, _ast.BinOp):
        op = type(node.op)
        left, right = _template(node.left), _template(node.right)
        if left is None or right is None:
            return None
        if op is _ast.Mult:
            # 2 * e and e * 2 both read as mul2
            if left == 2:
                return ("mul2", right)
            if right == 2:
                return ("mul2", left)
            return ("op", "*", left, right)
        table = {_ast.Add: "+", _ast.Sub: "-", _ast.BitXor: "^",
                 _ast.BitAnd: "&", _ast.BitOr: "|"}
        if op in table:
            return ("op", table[op], left, right)
        return None
    if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Invert):
        inner = _template(node.operand)
        return None if inner is None else ("bitnot", inner)
    return None


def _build(template) -> object:
    """Turn a rule template into a fresh AST node (metavars filled later)."""
    return template        # materialised by _instantiate


def _instantiate(template, binds):
    if isinstance(template, tuple) and template and isinstance(template[0], str) \
            and template[0].startswith("$"):
        return binds[template[1]]
    if not isinstance(template, tuple):
        return _ast.Constant(value=template)
    head = template[0]
    if head == "op":
        ops = {"+": _ast.Add, "-": _ast.Sub, "^": _ast.BitXor,
               "&": _ast.BitAnd, "|": _ast.BitOr, "*": _ast.Mult}
        return _ast.BinOp(left=_instantiate(template[2], binds),
                          op=ops[template[1]](),
                          right=_instantiate(template[3], binds))
    if head == "mul2":
        return _ast.BinOp(left=_ast.Constant(value=2), op=_ast.Mult(),
                          right=_instantiate(template[1], binds))
    if head == "bitnot":
        return _ast.UnaryOp(op=_ast.Invert(), operand=_instantiate(template[1], binds))
    return None


def _match(template, shape, binds) -> bool:
    """Unify a rule template with a reduced AST shape (commutative tolerant)."""
    if isinstance(template, str) and template.startswith("$"):
        if template in binds:
            return binds[template] == shape
        binds[template] = shape
        return True
    if not isinstance(template, tuple):
        return template == shape
    if not isinstance(shape, tuple) or len(shape) != len(template):
        return False
    if template[0] != shape[0]:
        # allow commuted + / * / ^ / & / | argument order
        if template[0] == "op" and shape[0] == "op" and template[1] == shape[1] \
                and template[1] in "+*^&|":
            trial = dict(binds)
            if _match(template[2], shape[3], trial) and _match(template[3], shape[2], trial):
                binds.update(trial)
                return True
        return False
    if template[0] == "op":
        if template[1] != shape[1]:
            return False
        if _match(template[2], shape[2], binds) and _match(template[3], shape[3], binds):
            return True
        if template[1] in "+*^&|":
            trial = dict(binds)
            if _match(template[2], shape[3], trial) and _match(template[3], shape[2], trial):
                binds.update(trial)
                return True
        return False
    return all(_match(t, s, binds) for t, s in zip(template[1:], shape[1:]))


# --------------------------------------------------------------------------
# self-proof: evaluate both templates over a grid; keep only the sound ones
# --------------------------------------------------------------------------

_GRID = (-9, -3, -1, 0, 1, 2, 3, 5, 7, 8, 13, 64, 255, 1337)


def _evaluate(template, binds):
    if isinstance(template, str) and template.startswith("$"):
        return binds[template]
    if not isinstance(template, tuple):
        return template
    head = template[0]
    if head == "op":
        a = _evaluate(template[2], binds)
        b = _evaluate(template[3], binds)
        return {"+": a + b, "-": a - b, "*": a * b, "&": a & b,
                "|": a | b, "^": a ^ b}[template[1]]
    if head == "mul2":
        return 2 * _evaluate(template[1], binds)
    if head == "bitnot":
        return ~_evaluate(template[1], binds)
    raise ValueError(template)


def _prove(pattern, replacement) -> bool:
    for x, y in itertools.product(_GRID, repeat=2):
        binds = {"$x": x, "$y": y}
        if _evaluate(pattern, binds) != _evaluate(replacement, binds):
            return False
    return True


SOUND_RULES = tuple((p, r) for p, r in _RULES if _prove(p, r))

# identities with a single operand
_UNARY = [
    # (a ^ a) -> 0 ; (a - a) -> 0 ; (a & a) -> a ; (a | a) -> a
    ("xor-zero", "^"), ("sub-zero", "-"),
]


def _shape_of(node):
    return _template(node)


def _instantiate_from_ast(template, nodes):
    """Rebuild a template expression using the *original* matched AST nodes."""
    if isinstance(template, str) and template.startswith("$"):
        return nodes[template]
    if not isinstance(template, tuple):
        return _ast.Constant(value=template)
    head = template[0]
    if head == "op":
        ops = {"+": _ast.Add, "-": _ast.Sub, "^": _ast.BitXor,
               "&": _ast.BitAnd, "|": _ast.BitOr, "*": _ast.Mult}
        return _ast.BinOp(left=_instantiate_from_ast(template[2], nodes),
                          op=ops[template[1]](),
                          right=_instantiate_from_ast(template[3], nodes))
    if head == "mul2":
        return _ast.BinOp(left=_ast.Constant(value=2), op=_ast.Mult(),
                          right=_instantiate_from_ast(template[1], nodes))
    if head == "bitnot":
        return _ast.UnaryOp(op=_ast.Invert(),
                            operand=_instantiate_from_ast(template[1], nodes))
    return None


def _same(a, b) -> bool:
    try:
        return _ast.dump(a) == _ast.dump(b)
    except Exception:                                     # noqa: BLE001
        return False


class _MBARewriter(_ast.NodeTransformer):
    def __init__(self):
        self.rewrites = 0

    def visit_BinOp(self, node):                          # noqa: N802
        node = self.generic_visit(node)
        shape = _shape_of(node)
        if shape is None:
            return node
        for pattern, replacement in SOUND_RULES:
            binds = {}
            if not _match(pattern, shape, binds):
                continue
            # collect the matched AST nodes for each metavariable
            nodes = self._collect(pattern, node, {})
            if nodes is None or any(name not in nodes for name in _METAVARS):
                continue
            new = _instantiate_from_ast(replacement, nodes)
            if new is None:
                continue
            _ast.copy_location(new, node)
            self.rewrites += 1
            return new
        # x ^ x -> 0 , x - x -> 0
        if isinstance(node.op, (_ast.BitXor, _ast.Sub)) and _same(node.left, node.right) \
                and isinstance(node.left, (_ast.Name, _ast.Constant, _ast.Attribute)):
            self.rewrites += 1
            return _ast.copy_location(_ast.Constant(value=0), node)
        return node

    def _collect(self, template, node, found):
        if isinstance(template, str) and template.startswith("$"):
            existing = found.get(template)
            if existing is None:
                found[template] = node
                return found
            return found if _same(existing, node) else None
        if not isinstance(template, tuple):
            return found
        if not isinstance(node, _ast.AST):
            return None
        head = template[0]
        if head == "op":
            if not isinstance(node, _ast.BinOp):
                return None
            ops = {_ast.Add: "+", _ast.Sub: "-", _ast.BitXor: "^",
                   _ast.BitAnd: "&", _ast.BitOr: "|", _ast.Mult: "*"}
            if ops.get(type(node.op)) != template[1]:
                return None
            trial = dict(found)
            left = self._collect(template[2], node.left, trial)
            right = self._collect(template[3], node.right, trial) if left else None
            if left and right:
                found.clear()
                found.update(trial)
                return found
            trial = dict(found)
            left = self._collect(template[2], node.right, trial)
            right = self._collect(template[3], node.left, trial) if left else None
            if left and right:
                found.clear()
                found.update(trial)
                return found
            return None
        if head == "mul2":
            if not (isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Mult)):
                return None
            for inner in (node.left, node.right):
                if isinstance(inner, _ast.Constant) and inner.value == 2:
                    other = node.right if inner is node.left else node.left
                    return self._collect(template[1], other, found)
            return None
        if head == "bitnot":
            if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Invert):
                return self._collect(template[1], node.operand, found)
            return None
        return None


def simplify_mba(tree) -> int:
    """Rewrite MBA-heavy subexpressions back to their plain arithmetic form."""
    try:
        rewriter = _MBARewriter()
        rewriter.visit(tree)
        return rewriter.rewrites
    except Exception:                                     # noqa: BLE001 - cosmetic pass
        return 0
