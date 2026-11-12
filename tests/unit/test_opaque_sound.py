"""Gate: opaque-predicate proving must be sound, never optimistic.

The prover used to sample a free name over a fixed integer grid.  ``if word ==
34:`` was false for every value in that grid, so the predicate was "proved"
false and a live ``elif`` was deleted from a program that had never been
obfuscated - while the tool reported *output verified*.  These tests pin the
sound rule: a free name is unbounded, so a comparison against a literal it could
equal stays undecided, and every classic opaque idiom still proves.
"""
import ast
import sys
import textwrap

import pytest

sys.path.insert(0, "src")
from pydecomp.polish.fidelity import flow, summary, verify     # noqa: E402
from pydecomp.polish.opaque import prove, strip_opaque          # noqa: E402


def _prove(source: str):
    return prove(ast.parse(source, mode="eval").body)


@pytest.mark.parametrize("source", [
    "x * x >= 0",
    "x ** 2 >= 0",
    "x - x == 0",
    "x ^ x == 0",
    "len(s) >= 0",
    "abs(x) >= 0",
    "x * (x + 1) % 2 == 0",
    "(x | 1) % 2 == 1",
])
def test_real_opaque_idioms_are_proved_true(source):
    assert _prove(source) is True


@pytest.mark.parametrize("source", [
    "x * x < 0",
    "x & ~x == 0",          # True, but phrased as a comparison
])
def test_impossible_conditions_are_decided(source):
    assert _prove(source) in (True, False)


@pytest.mark.parametrize("source", [
    "word == 34",
    "state != 3",
    "word == 0x22",
    "x > 3",
    "x * x == 4",
    "x & 7 == 3",
    "x in (1, 2)",
    "name == 'main'",
])
def test_a_free_name_compared_to_a_literal_is_undecided(source):
    assert _prove(source) is None


def test_a_live_branch_survives_the_pruner():
    tree = ast.parse(textwrap.dedent('''
        def run(words):
            out = []
            for word in words:
                if isinstance(word, str):
                    out.append(word)
                elif word == 34:
                    out.append("seen 34")
            return out
        '''))
    strip_opaque(tree)
    text = ast.unparse(tree)
    assert "seen 34" in text, "the live elif was deleted"
    assert "word == 34" in text


def test_a_junk_branch_is_still_removed():
    tree = ast.parse(textwrap.dedent('''
        def f(x):
            if x * x >= 0:
                return "real"
            else:
                return "junk"
        '''))
    assert strip_opaque(tree) == 1
    text = ast.unparse(tree)
    assert "'real'" in text and "'junk'" not in text


# --- the tripwire that would have caught the deletion -----------------------
ORIGINAL = textwrap.dedent('''
    def run(words):
        out = []
        for word in words:
            if isinstance(word, str):
                out.append(word)
            elif word == 34:
                out.append("seen 34")
        return out
    ''')


def _without_elif(text: str) -> str:
    tree = ast.parse(text)
    function = tree.body[0]
    loop = [node for node in function.body if isinstance(node, ast.For)][0]
    loop.body[0].orelse = []
    return ast.unparse(tree) + "\n"


def test_fidelity_rolls_back_unexplained_control_flow_loss():
    cleaned = _without_elif(ORIGINAL)
    assert flow(cleaned) < flow(ORIGINAL)
    verdict = verify(ORIGINAL, cleaned, notes=["evaluated 2 pure expression(s)"])
    assert verdict["kept"] == "unpacked"
    assert "control flow" in verdict["reason"]
    assert "rolled back" in summary(verdict)


def test_fidelity_allows_control_flow_loss_with_a_proof():
    cleaned = _without_elif(ORIGINAL)
    verdict = verify(ORIGINAL, cleaned, notes=["proved 1 opaque predicate(s) away"])
    assert verdict["kept"] == "cleaned"


def test_fidelity_leaves_untouched_cleaning_alone():
    verdict = verify(ORIGINAL, ORIGINAL, notes=[])
    assert verdict["kept"] == "cleaned"
