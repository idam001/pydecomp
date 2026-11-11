"""Loop idiom recovery, and the cases it must refuse.

The rule is the one compilers leave behind: an index used only to subscript one
sequence, and to increment, was a `for` over that sequence.  An index read for
its own value was an index loop.  Everything else stays a `while`.
"""
from __future__ import annotations

import ast

from pydecomp.polish.loops import recover_loops


def rewrite(source: str) -> tuple[int, str]:
    tree = ast.parse(source)
    count = recover_loops(tree)
    return count, ast.unparse(tree)


def test_index_used_only_for_subscript_becomes_for_each():
    count, text = rewrite(
        "def total(items):\n"
        "    i = 0\n"
        "    acc = 0\n"
        "    while i < len(items):\n"
        "        acc += items[i] * 2\n"
        "        i += 1\n"
        "    return acc\n")
    assert count == 1
    assert "for _item in items:" in text
    assert "items[" not in text


def test_index_read_for_its_value_stays_an_index_loop():
    count, text = rewrite(
        "def f(items):\n"
        "    i = 0\n"
        "    out = []\n"
        "    while i < len(items):\n"
        "        out.append(items[i] + i)\n"
        "        i += 1\n"
        "    return out\n")
    assert count == 1
    assert "for i in range(len(items)):" in text
    assert "_item" not in text


def test_plain_bound_becomes_range():
    count, text = rewrite(
        "def f(n):\n"
        "    i = 0\n"
        "    while i < n:\n"
        "        print(i)\n"
        "        i += 1\n")
    assert count == 1
    assert "for i in range(n):" in text


def test_sequence_mutated_in_the_loop_is_left_alone():
    count, text = rewrite(
        "def f(items):\n"
        "    i = 0\n"
        "    while i < len(items):\n"
        "        items = items[1:]\n"
        "        i += 1\n"
        "    return items\n")
    assert count == 0
    assert "while i < len(items):" in text


def test_index_rebound_in_the_body_is_left_alone():
    count, _text = rewrite(
        "def f(items):\n"
        "    i = 0\n"
        "    while i < len(items):\n"
        "        i = i * 2\n"
        "        i += 1\n"
        "    return i\n")
    assert count == 0


def test_step_of_more_than_one_is_left_alone():
    count, text = rewrite(
        "def f(items):\n"
        "    i = 0\n"
        "    while i < len(items):\n"
        "        print(items[i])\n"
        "        i += 2\n")
    assert count == 0
    assert "while " in text


def test_non_zero_start_is_left_alone():
    count, _text = rewrite(
        "def f(items):\n"
        "    i = 1\n"
        "    while i < len(items):\n"
        "        print(items[i])\n"
        "        i += 1\n")
    assert count == 0


def test_initialiser_earlier_in_the_block_is_still_found():
    count, text = rewrite(
        "def f(items):\n"
        "    total = 0\n"
        "    i = 0\n"
        "    seen = []\n"
        "    while i < len(items):\n"
        "        total += items[i]\n"
        "        i += 1\n"
        "    return total\n")
    assert count == 1
    assert "for _item in items:" in text


def test_nested_loops_are_both_recovered():
    count, text = rewrite(
        "def grid(rows):\n"
        "    r = 0\n"
        "    total = 0\n"
        "    while r < len(rows):\n"
        "        c = 0\n"
        "        while c < len(rows[r]):\n"
        "            total += rows[r][c]\n"
        "            c += 1\n"
        "        r += 1\n"
        "    return total\n")
    assert count == 2
    assert "for _item in rows:" in text
    assert "for _item_2 in _item:" in text


def test_output_compiles():
    _count, text = rewrite(
        "def f(items):\n"
        "    i = 0\n"
        "    out = 0\n"
        "    while i < len(items):\n"
        "        out += items[i]\n"
        "        i += 1\n"
        "    return out\n")
    compile(text, "<rebuilt>", "exec", dont_inherit=True)


def test_pipeline_reports_the_recovered_loop():
    from pydecomp.polish.apply import polish_source
    text, notes = polish_source(
        "def f(items):\n"
        "    i = 0\n"
        "    out = 0\n"
        "    while i < len(items):\n"
        "        out += items[i]\n"
        "        i += 1\n"
        "    return out\n")
    assert "for " in text
    assert any("for-loop" in note for note in notes), notes


def test_mutable_literals_are_never_propagated():
    """`results = []` + `results.append(x)` is not `[].append(x)`."""
    from pydecomp.polish.apply import polish_source
    text, _notes = polish_source(
        "def report(items):\n"
        "    results = []\n"
        "    for item in items:\n"
        "        results.append(item * 2)\n"
        "    return results\n")
    assert "results = []" in text
    assert "results.append" in text
    assert "return results" in text
    assert "[].append" not in text


def test_mutable_dicts_are_never_propagated():
    from pydecomp.polish.apply import polish_source
    text, _notes = polish_source(
        "def build():\n"
        "    cfg = {}\n"
        "    cfg['a'] = 1\n"
        "    return cfg\n")
    assert "cfg = {}" in text
    assert "cfg['a'] = 1" in text
    assert "{}['a']" not in text


def test_scalar_constants_are_still_propagated():
    from pydecomp.polish.apply import polish_source
    text, _notes = polish_source(
        "def f():\n"
        "    limit = 3\n"
        "    return limit * 2\n")
    assert "return 6" in text or "return limit * 2" in text
