"""The de-flattener: what it must rebuild, and what it must refuse to touch.

Control-flow flattening is the one transformation where a wrong guess produces
code that still parses, still looks plausible, and lies.  These tests pin both
halves: the dispatchers that must come apart, and the near-misses that must be
left exactly as they are.
"""
from __future__ import annotations

import ast

from pydecomp.polish.unflatten import _unflatten


def rebuild(source: str) -> tuple[int, str]:
    tree = ast.parse(source)
    count = _unflatten(tree)
    return count, ast.unparse(tree)


SIMPLE_LOOP = '''
def total(items):
    _state = 3
    _acc = 0
    _index = 0
    while True:
        if _state == 0:
            _index = 0
            _acc = 0
            _state = 1
        elif _state == 1:
            if _index < len(items):
                _state = 2
            else:
                _state = 4
        elif _state == 2:
            _acc += items[_index] * 2
            _index += 1
            _state = 1
        elif _state == 3:
            if 7 * 7 == 49:
                _state = 0
            else:
                _state = 9
        elif _state == 4:
            return _acc
'''

BRANCHING = '''
def classify(value):
    _state = 0
    _result = None
    while True:
        if _state == 0:
            if value > 10:
                _state = 1
            else:
                _state = 2
        elif _state == 1:
            _result = "big"
            _state = 3
        elif _state == 2:
            _result = "small"
            _state = 3
        elif _state == 3:
            return _result
'''

NESTED = '''
def pairs(items):
    _state = 0
    _outer = 0
    _inner = 0
    _count = 0
    while True:
        if _state == 0:
            _outer = 0
            _count = 0
            _state = 1
        elif _state == 1:
            if _outer < len(items):
                _state = 2
            else:
                _state = 6
        elif _state == 2:
            _inner = 0
            _state = 3
        elif _state == 3:
            if _inner < len(items):
                _state = 4
            else:
                _state = 5
        elif _state == 4:
            _count += items[_outer] * items[_inner]
            _inner += 1
            _state = 3
        elif _state == 5:
            _outer += 1
            _state = 1
        elif _state == 6:
            return _count
'''

# --- near misses: none of these may be rewritten ---------------------------
STATE_READ = '''
def f(items):
    _state = 0
    while True:
        if _state == 0:
            if _state > 5:
                _state = 1
            else:
                _state = 2
        elif _state == 1:
            _state = 2
        elif _state == 2:
            return _state
'''

NO_TRANSITION = '''
def g(items):
    _state = 0
    while True:
        if _state == 0:
            print("one")
            _state = 1
        elif _state == 1:
            print("two")
        elif _state == 2:
            return 1
'''

DYNAMIC_STATE = '''
def h(items):
    _state = 0
    while True:
        if _state == 0:
            _state = other()
        elif _state == 1:
            _state = 2
        elif _state == 2:
            return 1
'''


def test_simple_loop_is_rebuilt():
    count, text = rebuild(SIMPLE_LOOP)
    assert count == 1
    assert "_state" not in text
    assert "while True" not in text
    assert "while _index < len(items):" in text
    assert "return _acc" in text


def test_opaque_entry_condition_does_not_become_a_branch():
    _, text = rebuild(SIMPLE_LOOP)
    assert "7 * 7" not in text and "49" not in text


def test_branching_dispatcher_keeps_both_arms():
    count, text = rebuild(BRANCHING)
    assert count == 1
    assert "_state" not in text
    assert '"big"' in text or "'big'" in text
    assert '"small"' in text or "'small'" in text
    assert "if value > 10:" in text


def test_nested_loops_are_rebuilt_as_nested_loops():
    count, text = rebuild(NESTED)
    assert count == 1
    assert "_state" not in text
    loop_lines = [line.strip() for line in text.splitlines() if "while " in line]
    assert len(loop_lines) >= 2, text
    assert "return _count" in text


def test_state_read_inside_a_block_is_left_alone():
    count, text = rebuild(STATE_READ)
    assert count == 0
    assert "_state" in text


def test_block_without_a_transition_is_left_alone():
    count, _text = rebuild(NO_TRANSITION)
    assert count == 0


def test_computed_state_is_left_alone():
    count, _text = rebuild(DYNAMIC_STATE)
    assert count == 0


def test_rebuilt_body_is_valid_python():
    for source in (SIMPLE_LOOP, BRANCHING, NESTED):
        _count, text = rebuild(source)
        compile(text, "<rebuilt>", "exec", dont_inherit=True)


def test_the_whole_pipeline_deflattens():
    from pydecomp.polish.apply import polish_source
    text, notes = polish_source(SIMPLE_LOOP)
    assert "_state" not in text
    assert "while " in text
    assert "return _acc" in text
    assert any("flatten" in note for note in notes), notes
