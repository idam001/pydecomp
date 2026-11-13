"""pydecomp - the identity library, and the rewriter that uses it.

Mixed boolean-arithmetic obfuscation works by writing a value in a form that is
longer than it needs to be: `a + b` as `(a ^ b) + 2 * (a & b)`, `a - b` as
`(a ^ b) - 2 * (~a & b)`, a shift as a multiply, a mask as a modulo.  The
identities that undo it are older than the obfuscators, and there are only a few
dozen of them.

The important property of this module is not the list, it is the discipline
around it.  **Every rule is proved before it is installed**: at import, both
halves of the rule are evaluated over a grid of integers - negatives, zero, one,
powers of two, byte-sized values - and a rule whose halves disagree on any
sample is dropped.  The user's program is never evaluated; the templates being
compared are this file's own source.  A rewrite is then a structural substitution
of a matched subexpression, which is what makes the pass safe to run on code
whose behaviour nobody has executed.

:data:`IDENTITIES` is the proven set, and ``len(IDENTITIES)`` is a fact about
this build rather than a claim about it.
"""
from __future__ import annotations

import itertools

from .domain import (Sym, SymConst, SymExpr, SymUnknown, evaluate)

#: the integers every rule is proved over: negatives exercise the two's-complement
#: identities, powers of two exercise the shift and mask ones
GRID = (-8, -3, -2, -1, 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 255)

#: three-variable rules get a narrower grid, because 15^3 samples per rule at
#: import is time the user spends waiting for a CLI to start
GRID_3 = (-2, -1, 0, 1, 2, 3, 5, 8, 255)

_BINARY = {"+", "-", "*", "//", "%", "**", "<<", ">>", "&", "|", "^"}
_UNARY = {"~", "neg", "not"}


# --------------------------------------------------------------------------
# the rule language: an int is a literal, "$x"/"$y" is a metavariable, a tuple
# is an operation
# --------------------------------------------------------------------------

def _build(template, binds: dict[str, Sym]) -> Sym:
    if isinstance(template, int):
        return SymConst(value=template)
    if isinstance(template, str):
        if template.startswith("$"):
            return binds[template]
        raise ValueError(template)
    op, args = template[0], template[1:]
    return SymExpr(op=op, args=tuple(_build(item, binds) for item in args))


def _shape(node: Sym):
    """The template-shaped view of a node, for matching."""
    if isinstance(node, SymConst) and isinstance(node.value, int) \
            and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, SymUnknown):
        return ("?", node.name)
    if isinstance(node, SymExpr):
        return (node.op,) + tuple(_shape(item) for item in node.args)
    return None


def _match(pattern, shape, binds: dict) -> bool:
    if isinstance(pattern, str) and pattern.startswith("$"):
        if pattern in binds:
            return _same(binds[pattern], shape)
        binds[pattern] = shape
        return True
    if isinstance(pattern, int):
        return shape == pattern
    if not isinstance(pattern, tuple) or not isinstance(shape, tuple):
        return False
    if len(pattern) != len(shape) or pattern[0] != shape[0]:
        return False
    return all(_match(left, right, binds)
               for left, right in zip(pattern[1:], shape[1:]))


def _same(left, right) -> bool:
    return left == right


def _prove(pattern, replacement) -> bool:
    """Do the two templates agree on every sample in the grid?"""
    names = sorted({item for item in _metavars(pattern) | _metavars(replacement)})
    if len(names) > 3:
        return False
    grid = GRID if len(names) < 3 else GRID_3
    for values in itertools.product(grid, repeat=len(names)):
        binds = {name: SymConst(value=value) for name, value in zip(names, values)}
        try:
            left = evaluate(_build(pattern, binds))
            right = evaluate(_build(replacement, binds))
        except Exception:                             # noqa: BLE001 - a rule with holes
            return False
        if left != right:
            return False
    return True


def _metavars(template) -> set:
    if isinstance(template, str) and template.startswith("$"):
        return {template}
    if isinstance(template, tuple):
        out: set = set()
        for item in template[1:]:
            out |= _metavars(item)
        return out
    return set()


# --------------------------------------------------------------------------
# the candidates.  Anything the prover rejects never reaches a user's file.
# --------------------------------------------------------------------------

_CANDIDATES = [
    # --- mixed boolean arithmetic: the four ways to spell each of the four
    #     bitwise ops plus, minus and the two rotations of the same identity
    (("+", ("^", "$x", "$y"), ("*", 2, ("&", "$x", "$y"))), ("+", "$x", "$y")),
    (("+", ("^", "$x", "$y"), ("*", ("&", "$x", "$y"), 2)), ("+", "$x", "$y")),
    (("+", ("^", "$y", "$x"), ("*", 2, ("&", "$x", "$y"))), ("+", "$x", "$y")),
    (("+", ("*", 2, ("&", "$x", "$y")), ("^", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("*", 2, ("&", "$y", "$x")), ("^", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("*", ("&", "$x", "$y"), 2), ("^", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("|", "$x", "$y"), ("&", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("&", "$x", "$y"), ("|", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("|", "$x", "$y"), ("&", "$y", "$x")), ("+", "$x", "$y")),
    (("+", ("|", "$y", "$x"), ("&", "$x", "$y")), ("+", "$x", "$y")),
    (("+", ("&", "$x", "$y"), ("|", "$y", "$x")), ("+", "$x", "$y")),
    (("+", ("^", "$x", "$y"), ("+", ("&", "$x", "$y"), ("&", "$x", "$y"))),
     ("+", "$x", "$y")),
    (("+", ("+", ("^", "$x", "$y"), ("&", "$x", "$y")), ("&", "$x", "$y")),
     ("+", "$x", "$y")),
    # --- and the same identity one step out: x - y, x ^ y, x & y, x | y
    (("-", ("^", "$x", "$y"), ("*", 2, ("&", ("~", "$x"), "$y"))), ("-", "$x", "$y")),
    (("-", ("^", "$x", "$y"), ("*", ("&", ("~", "$x"), "$y"), 2)), ("-", "$x", "$y")),
    (("-", ("^", "$x", "$y"), ("+", ("&", ("~", "$x"), "$y"), ("&", ("~", "$x"), "$y"))),
     ("-", "$x", "$y")),
    (("-", ("|", "$x", "$y"), ("&", "$x", "$y")), ("^", "$x", "$y")),
    (("-", ("|", "$x", "$y"), ("&", "$y", "$x")), ("^", "$x", "$y")),
    (("^", ("+", ("|", "$x", "$y"), ("&", "$x", "$y")), ("+", "$x", "$y")), ("^", "$x", "$y")),
    (("+", ("&", "$x", "$y"), ("^", "$x", "$y")), ("|", "$x", "$y")),
    (("+", ("^", "$x", "$y"), ("&", "$x", "$y")), ("|", "$x", "$y")),
    (("+", ("^", "$y", "$x"), ("&", "$x", "$y")), ("|", "$x", "$y")),
    (("-", ("|", "$x", "$y"), ("^", "$x", "$y")), ("&", "$x", "$y")),
    (("&", ("~", ("|", "$x", "$y")), ("~", ("^", "$x", "$y"))), ("&", "$x", "$y")),
    # --- absorption: the pair that survives a mask or a merge
    (("&", ("|", "$x", "$y"), "$x"), "$x"),
    (("|", ("&", "$x", "$y"), "$x"), "$x"),
    (("&", "$x", ("|", "$x", "$y")), "$x"),
    (("|", "$x", ("&", "$x", "$y")), "$x"),
    (("&", ("+", "$x", "$y"), "$x"), ("&", "$y", "$x")),
    # --- distribution, which obfuscators use to make a constant disappear
    (("|", ("&", "$x", "$y"), ("&", "$x", 0)), ("&", "$x", "$y")),
    (("&", ("|", "$x", "$y"), ("|", "$x", 0)), ("|", "$x", "$y")),
    (("&", ("|", "$x", "$y"), ("|", "$x", "$z")), ("|", "$x", ("&", "$y", "$z"))),
    (("|", ("&", "$x", "$y"), ("&", "$x", "$z")), ("&", "$x", ("|", "$y", "$z"))),
    # --- identity elements and annihilators
    (("+", "$x", 0), "$x"),
    (("+", 0, "$x"), "$x"),
    (("-", "$x", 0), "$x"),
    (("*", "$x", 1), "$x"),
    (("*", 1, "$x"), "$x"),
    (("*", "$x", 0), 0),
    (("^", "$x", 0), "$x"),
    (("^", 0, "$x"), "$x"),
    (("|", "$x", 0), "$x"),
    (("&", "$x", -1), "$x"),
    (("&", "$x", "$x"), "$x"),
    (("|", "$x", "$x"), "$x"),
    (("^", "$x", "$x"), 0),
    (("-", "$x", "$x"), 0),
    (("&", "$x", ("~", "$x")), 0),
    (("|", "$x", ("~", "$x")), -1),
    (("^", "$x", -1), ("~", "$x")),
    (("+", "$x", "$x"), ("*", 2, "$x")),
    (("-", 0, "$x"), ("neg", "$x")),
    # --- involutions: the two operations that undo themselves
    (("~", ("~", "$x")), "$x"),
    (("neg", ("neg", "$x")), "$x"),
    (("neg", ("~", "$x")), ("+", "$x", 1)),
    (("~", ("neg", "$x")), ("-", "$x", 1)),
    # --- de Morgan, and the complement the obfuscator adds to hide a negation
    (("~", ("&", "$x", "$y")), ("|", ("~", "$x"), ("~", "$y"))),
    (("~", ("|", "$x", "$y")), ("&", ("~", "$x"), ("~", "$y"))),
    (("~", ("^", "$x", "$y")), ("^", ("~", "$x"), "$y")),
    (("^", ("~", "$x"), "$y"), ("~", ("^", "$x", "$y"))),
    # --- shifts written as multiplies, and back
    # a multiply never becomes a shift here: both spellings are the same size,
    # so restyling `x * 2` as `x << 1` would rewrite code that was never hidden
    ((">>", ("<<", "$x", 1), 1), "$x"),
    (("+", "$x", "$x"), ("<<", "$x", 1)),
    # --- cancelling an operation with its own inverse
    (("-", ("+", "$x", "$y"), "$y"), "$x"),
    (("+", ("-", "$x", "$y"), "$y"), "$x"),
    (("-", ("-", "$x", "$y"), "$y"), ("-", "$x", ("*", 2, "$y"))),
    (("^", ("^", "$x", "$y"), "$y"), "$x"),
    (("+", ("+", "$x", "$y"), ("neg", "$y")), "$x"),
    (("-", "$x", ("neg", "$y")), ("+", "$x", "$y")),
    # --- associativity in the direction that shortens the tree
    (("+", ("+", "$x", "$y"), "$z"), ("+", "$x", ("+", "$y", "$z"))),
    (("*", ("*", "$x", "$y"), "$z"), ("*", "$x", ("*", "$y", "$z"))),
    (("&", ("&", "$x", "$y"), "$z"), ("&", "$x", ("&", "$y", "$z"))),
    (("|", ("|", "$x", "$y"), "$z"), ("|", "$x", ("|", "$y", "$z"))),
    (("^", ("^", "$x", "$y"), "$z"), ("^", "$x", ("^", "$y", "$z"))),
    # --- subtract a sum, which is how a negative constant is smuggled in
    (("-", "$x", ("+", "$y", "$z")), ("-", ("-", "$x", "$y"), "$z")),
    (("-", "$x", ("-", "$y", "$z")), ("+", ("-", "$x", "$y"), "$z")),
    (("neg", ("+", "$x", "$y")), ("+", ("neg", "$x"), ("neg", "$y"))),
    (("neg", ("-", "$x", "$y")), ("-", "$y", "$x")),
    (("-", "$x", ("*", -1, "$y")), ("+", "$x", "$y")),
    (("+", "$x", ("*", -1, "$y")), ("-", "$x", "$y")),
    # --- the mask pair that rebuilds a value from two halves
    (("-", "$x", ("&", "$x", "$y")), ("&", "$x", ("~", "$y"))),
    (("-", ("|", "$x", "$y"), "$y"), ("&", "$x", ("~", "$y"))),
    (("+", ("&", "$x", "$y"), ("&", "$x", ("~", "$y"))), "$x"),
    (("|", ("&", "$x", "$y"), ("&", "$x", ("~", "$y"))), "$x"),
    (("^", ("&", "$x", "$y"), "$x"), ("&", "$x", ("~", "$y"))),
    (("&", ("^", "$x", "$y"), "$x"), ("&", ("~", "$x"), "$y")),
    # --- a multiply written as a shift and an add
    (("-", ("<<", "$x", 1), "$x"), "$x"),
    (("+", ("<<", "$x", 1), "$x"), ("*", "$x", 3)),
    (("+", "$x", ("<<", "$x", 1)), ("*", "$x", 3)),
    (("+", ("*", "$x", 2), "$x"), ("*", "$x", 3)),
    (("+", "$x", ("*", "$x", 2)), ("*", "$x", 3)),
    (("-", ("*", "$x", 3), ("*", "$x", 2)), "$x"),
    (("-", ("*", "$x", 3), ("<<", "$x", 1)), "$x"),
    (("-", ("+", "$x", "$y"), ("^", "$x", "$y")), ("*", 2, ("&", "$x", "$y"))),
    (("-", ("+", "$x", "$y"), ("|", "$x", "$y")), ("&", ("~", ("^", "$x", "$y")), ("|", "$x", "$y"))),
    (("//", ("*", "$x", 2), 2), "$x"),
    (("//", ("*", "$x", 4), 4), "$x"),
    # --- a modulo that can only be zero
    (("%", ("*", "$x", 2), 2), 0),
    (("%", ("*", "$x", 3), 3), 0),
    (("%", ("*", "$x", 4), 4), 0),
    (("%", "$x", 1), 0),
    # --- powers
    (("**", "$x", 1), "$x"),
    (("**", 1, "$x"), 1),
    (("**", 0, "$x"), 0),
    # --- negation distributed
    (("+", ("neg", "$x"), ("neg", "$y")), ("neg", ("+", "$x", "$y"))),
    (("-", ("neg", "$x"), "$y"), ("neg", ("+", "$x", "$y"))),
    (("+", "$x", ("neg", "$y")), ("-", "$x", "$y")),
    # --- comparisons that are decided by structure rather than value
    (("==", "$x", "$x"), 1),
    (("<=", ("&", "$x", "$y"), "$x"), 1),
    ((">=", ("|", "$x", "$y"), "$x"), 1),
    (("==", ("^", "$x", "$y"), 0), ("==", "$x", "$y")),
    (("==", ("-", "$x", "$y"), 0), ("==", "$x", "$y")),
    (("!=", ("^", "$x", "$y"), 0), ("!=", "$x", "$y")),
    (("!=", ("-", "$x", "$y"), 0), ("!=", "$x", "$y")),
    (("<=", "$x", ("|", "$x", "$y")), 1),
    ((">=", ("&", "$x", "$y"), ("-", "$x", 1)), 1),
]

#: the rules that survived the proof
def _dedupe(rules):
    """Drop a rule that appears twice; every kept rule is proved on its own."""
    kept, seen = [], set()
    for pattern, replacement in rules:
        key = (repr(pattern), repr(replacement))
        if key in seen:
            continue
        seen.add(key)
        kept.append((pattern, replacement))
    return tuple(kept)


IDENTITIES = _dedupe(rule for rule in _CANDIDATES if _prove(*rule))

#: how many candidates the prover rejected, which is worth being able to see
REJECTED = tuple(rule for rule in _CANDIDATES
                 if (repr(rule[0]), repr(rule[1])) not in
                 {(repr(p), repr(r)) for p, r in IDENTITIES})


def _instantiate(template, nodes: dict[str, Sym]) -> Sym:
    if isinstance(template, int):
        return SymConst(value=template)
    if isinstance(template, str):
        return nodes[template]
    op, args = template[0], template[1:]
    return SymExpr(op=op, args=tuple(_instantiate(item, nodes) for item in args))


def _collect(pattern, node: Sym, nodes: dict[str, Sym]) -> bool:
    if isinstance(pattern, str) and pattern.startswith("$"):
        if pattern in nodes:
            return _shape(nodes[pattern]) == _shape(node)
        nodes[pattern] = node
        return True
    if isinstance(pattern, int):
        return isinstance(node, SymConst) and node.value == pattern
    if not isinstance(node, SymExpr) or pattern[0] != node.op:
        return False
    if len(pattern) - 1 != len(node.args):
        return False
    return all(_collect(left, right, nodes)
               for left, right in zip(pattern[1:], node.args))


def simplify(node: Sym, steps: int = 96) -> Sym:
    """Rewrite *node* until no proven identity applies, bottom-up."""
    for _ in range(steps):
        moved = _rewrite_once(node)
        if moved is None:
            return node
        node = moved
    return node


def _rewrite_once(node: Sym) -> Sym | None:
    """One bottom-up pass.  Returns the new node, or None when nothing moved."""
    if not isinstance(node, SymExpr):
        return None
    if node.op == "bool":
        kind, values = node.args
        rebuilt = tuple(_rewrite_once(item) or item for item in values)
        if rebuilt != values:
            return SymExpr(op="bool", args=(kind, rebuilt))
        return None
    args = tuple(_rewrite_once(item) or item for item in node.args)
    current = node if args == node.args else SymExpr(op=node.op, args=args)
    if all(isinstance(item, SymConst) for item in current.args):
        try:
            return SymConst(value=evaluate(current))
        except Exception:                            # noqa: BLE001 - division by zero
            pass
    # A rewrite is taken only when it makes the tree strictly smaller, or the
    # same size and earlier in the ordering.  That makes the normal form unique
    # and the loop finite even when the library holds both directions of a
    # relation, which it does on purpose: both halves are true statements.
    shape = _shape(current)
    best = None
    current_key = (_weight(current), shape)
    for pattern, replacement in IDENTITIES:
        binds: dict = {}
        if not _match(pattern, shape, binds):
            continue
        nodes: dict[str, Sym] = {}
        if not _collect(pattern, current, nodes):
            continue
        built = _instantiate(replacement, nodes)
        key = (_weight(built), _shape(built))
        if key >= current_key:
            continue
        if best is None or key < best[0]:
            best = (key, built)
    if best is not None:
        return best[1]
    return current if args != node.args else None


def _weight(node) -> int:
    """Node count, the measure the rewriter is required to reduce."""
    if isinstance(node, SymExpr):
        if node.op == "bool":
            kind, values = node.args
            return 1 + sum(_weight(item) for item in values)
        return 1 + sum(_weight(item) for item in node.args)
    return 1


def canonical(node: Sym) -> str:
    """A structural key, so two spellings of one value compare equal."""
    return repr(_shape(simplify(node)))


def prove_true(node: Sym) -> bool | None:
    """True when *node* is decidably true, False when decidably false, else None.

    Deciding is done by rewriting, not by sampling the user's program: a
    predicate is true here only if the identity library turns it into the
    constant ``True``.  Anything else stays undecided, which is the answer that
    keeps a branch intact.
    """
    reduced = simplify(node)
    if isinstance(reduced, SymConst):
        if reduced.value is True or reduced.value == 1:
            return True
        if reduced.value is False or reduced.value == 0:
            return False
    # a comparison whose two sides have the same canonical form is true, and one
    # whose sides differ only by a decided amount is decided arithmetically
    if isinstance(reduced, SymExpr) and reduced.op in ("==", "!=", "<", "<=", ">", ">="):
        left, right = reduced.args
        if canonical(left) == canonical(right):
            return reduced.op in ("==", "<=", ">=")
        difference = simplify(SymExpr(op="-", args=(left, right)))
        if isinstance(difference, SymConst) and isinstance(difference.value, int):
            delta = difference.value
            return {"==": delta == 0, "!=": delta != 0, "<": delta < 0,
                    "<=": delta <= 0, ">": delta > 0, ">=": delta >= 0}[reduced.op]
    return None
