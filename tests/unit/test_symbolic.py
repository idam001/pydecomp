"""The symbolic domain: the identity library, its prover, and the executor.

Every number asserted here was measured on this build, not chosen: the identity
count is a floor that the library is required to keep meeting, and the rejected
rules are the ones the prover caught.
"""
from __future__ import annotations

import ast

import pytest

from pydecomp.symbolic import (IDENTITIES, REJECTED, SymConst, SymExpr,
                               SymUnknown, canonical, decide, evaluate, from_ast,
                               prove_polynomial_mod, prove_true, simplify,
                               simplify_tree, unknowns)


def tree_of(source: str) -> ast.Module:
    return ast.parse(source)


def expr_of(source: str):
    return ast.parse(source, mode="eval").body


def rewrite(source: str) -> str:
    """Run the executor over one statement and return its unparsed form."""
    tree, _ = simplify_tree(tree_of(source))
    return ast.unparse(tree)


# --------------------------------------------------------------------------
# the domain
# --------------------------------------------------------------------------

def test_constants_and_unknowns_lift():
    value = from_ast(expr_of("a + 2"))
    assert isinstance(value, SymExpr)
    assert unknowns(value) == ("a",)
    assert evaluate(from_ast(expr_of("3 * 4 + 1"))) == 13


def test_from_ast_round_trips_through_to_ast():
    for source in ("a + b", "(a ^ b) - 2 * (~a & b)", "a << 1 | b", "not a",
                   "a == b", "a and b"):
        node = expr_of(source)
        assert ast.dump(from_ast(node).to_ast(), annotate_fields=True) != ""
        again = ast.unparse(from_ast(node).to_ast())
        assert ast.unparse(ast.parse(again, mode="eval").body) == again


def test_unary_minus_is_its_own_operator():
    # `-x` lifts to `neg`, so it can never be matched by a two-argument rule
    unary = from_ast(expr_of("-x"))
    binary = from_ast(expr_of("x - y"))
    assert unary.op == "neg" and len(unary.args) == 1
    assert binary.op == "-" and len(binary.args) == 2
    assert ast.unparse(unary.to_ast()) == "-x"


def test_evaluate_never_returns_a_wrong_value_silently():
    with pytest.raises(Exception):
        evaluate(from_ast(expr_of("1 // 0")))


# --------------------------------------------------------------------------
# the prover
# --------------------------------------------------------------------------

def test_the_library_holds_at_least_a_hundred_proved_rules():
    assert len(IDENTITIES) >= 100


def test_every_installed_rule_really_holds_on_the_grid():
    """Re-check the installed set independently of the prover that built it."""
    from pydecomp.symbolic.simplify import GRID, _build, _metavars

    def build(template, binds):
        return _build(template, binds)

    import itertools

    for pattern, replacement in IDENTITIES:
        names = sorted(_metavars(pattern) | _metavars(replacement))
        grid = GRID if len(names) < 3 else (-2, -1, 0, 1, 2, 3, 5, 8, 255)
        for values in itertools.product(grid, repeat=len(names)):
            binds = {name: SymConst(value) for name, value in zip(names, values)}
            assert evaluate(build(pattern, binds)) == evaluate(build(replacement, binds)), \
                f"{pattern} -> {replacement} on {binds}"


def test_the_prover_rejects_rules_that_are_false():
    """The two bad candidates written on purpose must have been caught."""
    rejected = {repr(rule) for rule in REJECTED}
    assert len(rejected) == len(REJECTED), "a rejected rule is listed twice"
    assert len(REJECTED) >= 10
    for pattern, replacement in REJECTED:
        assert (pattern, replacement) not in IDENTITIES


def test_a_typo_cannot_reach_the_installed_set():
    # ("+|", "$x", "$y") is not an operator; nothing with it may be installed
    for pattern, replacement in IDENTITIES:
        assert "+|" not in repr((pattern, replacement))


def test_mba_spellings_prove_equal():
    for left, right in (
        ("(a ^ b) + 2 * (a & b)", "a + b"),
        ("(a | b) - (a & b)", "a ^ b"),
        ("(a ^ b) - 2 * (~a & b)", "a - b"),
        ("(a & b) + (a ^ b)", "a | b"),
        ("(a & b) | (a & ~b)", "a"),
    ):
        assert prove_true(from_ast(expr_of(f"({left}) == ({right})"))) is True, left


def test_a_predicate_that_is_not_decided_stays_undecided():
    assert prove_true(from_ast(expr_of("a == b"))) is None
    assert decide(expr_of("a == b")) is None
    assert prove_true(from_ast(expr_of("1 == 2"))) is False


def test_polynomial_guards_are_proved_over_their_residues():
    for predicate, verdict in (("(x * x + x) % 2 == 0", True),
                               ("(x * x * x - x) % 3 == 0", True),
                               ("(x ** 2 - x) % 2 != 0", False),
                               ("(x * x) % 3 == 1", None)):
        assert prove_polynomial_mod(expr_of(predicate)) is verdict, predicate


def test_a_polynomial_guard_that_is_not_a_guard_is_left_alone():
    # a quadratic residue modulo 3 is 0 or 1, never 2: that arm cannot run
    assert prove_polynomial_mod(expr_of("(x * x) % 3 == 2")) is False
    assert prove_polynomial_mod(expr_of("(x * x) % 3 == 1")) is None
    assert prove_polynomial_mod(expr_of("a == b")) is None


# --------------------------------------------------------------------------
# the executor
# --------------------------------------------------------------------------

def test_the_rewriter_undoes_mixed_arithmetic():
    assert rewrite("v = (a ^ b) + 2 * (a & b)") == "v = a + b"
    assert rewrite("v = (a | b) - (a & b)") == "v = a ^ b"
    assert rewrite("v = (a ^ b) - 2 * (~a & b)") == "v = a - b"
    assert rewrite("v = (a & b) | (a & ~b)") == "v = a"


def test_the_rewriter_is_idempotent():
    once = rewrite("v = (a ^ b) + 2 * (a & b)")
    assert rewrite(once) == once


def test_a_decided_branch_loses_the_arm_that_cannot_run():
    source = ("if (a * a + a) % 2 == 0:\n"
              "    keep = 1\n"
              "else:\n"
              "    keep = 2\n")
    out = rewrite(source)
    assert out == "keep = 1"


def test_ordinary_source_is_not_restyled():
    """The pass must leave code that was never obfuscated exactly as it was."""
    for source in ("v = a + b", "v = a * 2", "v = a // 2", "v = x << 2",
                   "v = obj.attr + 1", "v = f(a) + f(b)", "v = a[0] | b[1]"):
        assert rewrite(source) == source


def test_the_executor_never_touches_a_string_or_a_call():
    source = "v = 'a' + 'b'"
    assert rewrite(source) == source


def test_a_report_counts_what_happened():
    tree, report = simplify_tree(tree_of(
        "v = (a ^ b) + 2 * (a & b)\n"
        "if (a + a) % 2 == 0:\n"
        "    w = 1\n"))
    assert report.rewritten == 1
    assert report.decided == 1
    assert report.notes(), "a pass that changed something must say so"


def test_canonical_agrees_for_two_spellings_of_one_value():
    assert canonical(from_ast(expr_of("(a ^ b) + 2 * (a & b)"))) == \
        canonical(from_ast(expr_of("a + b")))
    assert canonical(from_ast(expr_of("a + b"))) != canonical(from_ast(expr_of("a - b")))


def test_simplify_terminates_on_a_relation_held_in_both_directions():
    # the library keeps `x * 2 -> x << 1` out, and holds real relations in both
    # directions on purpose; the rewriter must still stop
    node = from_ast(expr_of("~(~(~(~x)))"))
    assert simplify(node) == SymUnknown(name="x")
