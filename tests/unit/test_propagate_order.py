"""Constant propagation is only sound in statement order.

``propagate_constants`` exists to inline a literal that a packer bound once.  The
soundness condition is not just "bound once" - it is "bound once, *before* the
use, and never a parameter".  Both halves of that were missing, and both produced
code that compiles, reads correctly and computes something else:

    def run(n):
        return n + 1
        n = 99          # dead, after the return - but the old pass believed it

    # produced:  return 99 + 1

These tests pin the ordering and the parameter rule, and the differential gate
(``tools/diff_polish.py``) checks the same thing behaviourally.
"""
from __future__ import annotations

import ast

from pydecomp.polish.inline import propagate_constants


def rewrite(source: str) -> str:
    tree = ast.parse(source)
    propagate_constants(tree)
    return ast.unparse(ast.fix_missing_locations(tree))


def counts(source: str) -> int:
    tree = ast.parse(source)
    replaced, _env = propagate_constants(tree)
    return replaced


# --------------------------------------------------------------------------
# the ordering rule
# --------------------------------------------------------------------------

def test_an_assignment_after_a_use_is_not_propagated_backwards():
    source = "def run(n):\n    return n + 1\n    n = 99\n"
    text = rewrite(source)
    assert "return n + 1" in text, text
    assert "99 + 1" not in text, text


def test_a_binding_is_propagated_into_the_statements_that_follow_it():
    source = "def run(n):\n    k = 3\n    return n * k\n"
    assert rewrite(source) == "def run(n):\n    k = 3\n    return n * 3"
    assert counts(source) == 1


def test_a_use_before_the_binding_in_the_same_scope_is_left_alone():
    source = "def run(n):\n    out = n * k\n    k = 3\n    return out + k\n"
    assert "n * k" in rewrite(source)


def test_a_module_name_bound_below_a_function_is_still_a_constant_inside_it():
    source = "def run(n):\n    return len(_name) * n\n\n_name = 'abc'\n"
    assert rewrite(source).count("'abc'") == 2      # the binding and the use


# --------------------------------------------------------------------------
# the parameter rule
# --------------------------------------------------------------------------

def test_a_parameter_is_never_treated_as_a_constant():
    source = "def run(n):\n    n = 99\n    return n + 1\n"
    assert "99 + 1" not in rewrite(source)


def test_a_parameter_assigned_before_the_use_still_runs_before_the_use():
    source = "def run(n):\n    n = n * 2\n    return n + 1\n"
    assert "n * 2" in rewrite(source)


# --------------------------------------------------------------------------
# the rules that were already right, kept right
# --------------------------------------------------------------------------

def test_a_rebound_name_is_not_a_constant():
    source = "def run(n):\n    k = 1\n    for i in range(n):\n        k = k + i\n    return k\n"
    assert counts(source) == 0


def test_a_mutable_literal_is_not_a_constant():
    # the historical bug in docs/UPGRADES.md: `results = []` is not a constant
    source = ("def report(items):\n"
              "    results = []\n"
              "    for item in items:\n"
              "        results.append(item * 2)\n"
              "    return results\n")
    assert "results.append" in rewrite(source)


def test_a_docstring_or_function_definition_is_not_substituted():
    source = ("_v = 1\n\n"
              "def helper():\n"
              "    return _v\n\n"
              "def run(n):\n"
              "    return helper() * n\n")
    text = rewrite(source)
    assert "def helper():\n    return 1" in text
