"""A container built statement by statement, and the two ways to get it wrong.

Loaders rarely hide the payload behind one expression.  They build it: a list of
integers appended in a loop, a class body holding the blob, a string grown with
``+=``.  Folding that statically is only worth shipping if it stays truthful in
both directions, so these tests pin the positive shapes and the guard that keeps
the folder away from a value it cannot know.

The guard is the important half.  Before it existed, this

    _b = bytearray()
    for _i in range(67):
        _b.append(...)
    exec(bytes(_b).decode())

folded to ``exec('')`` - a rewrite that compiles, runs, and does nothing.  The
loop appends, the folder saw only the empty seed, and the empty seed was written
out as the program.
"""
from __future__ import annotations

import ast

from pydecomp.engine.peel import find_payloads
from pydecomp.polish.evaluate import fold_expressions


PAYLOAD = "def greet(name):\n    return 'hello ' + name\n\nprint(greet('world'))\n"


def folded(source: str) -> str:
    tree = ast.parse(source)
    fold_expressions(tree, {})
    return ast.unparse(ast.fix_missing_locations(tree))


# --------------------------------------------------------------------------
# the positive shapes
# --------------------------------------------------------------------------

def test_a_class_body_is_read_as_constants():
    source = (
        "import base64\n"
        "class _C:\n"
        "    _p = b'aGVsbG8='\n"
        "exec(base64.b64decode(_C._p).decode())\n"
    )
    text = folded(source)
    assert "exec(" in text and "'hello'" in text


def test_a_straight_line_append_chain_folds():
    source = (
        "_out = bytearray()\n"
        "_out.append(104)\n"
        "_out.append(105)\n"
        "exec(bytes(_out).decode())\n"
    )
    text = folded(source)
    assert "exec(" in text and "'hi'" in text


def test_a_draw_from_a_literal_is_folded_once():
    source = "_keys = ['a', 'b']\nexec(_keys[1])\n"
    assert "exec('b')" in folded(source)


# --------------------------------------------------------------------------
# the guard: a value the folder cannot know is left alone
# --------------------------------------------------------------------------

def test_a_container_grown_in_a_loop_is_not_folded_to_its_seed():
    source = (
        "_n = [1, 2, 3]\n"
        "_b = bytearray()\n"
        "for _c in _n:\n"
        "    _b.append(_c + 100)\n"
        "exec(bytes(_b).decode())\n"
    )
    text = folded(source)
    assert "_b.append" in text, "the loop body must survive"
    assert "exec('')" not in text, "an empty container is not the value"
    assert "bytes(_b)" in text, "the use of the name must survive"


def test_a_container_under_a_conditional_is_not_folded():
    source = (
        "_b = bytearray()\n"
        "if _flag:\n"
        "    _b.append(7)\n"
        "exec(bytes(_b).decode())\n"
    )
    text = folded(source)
    assert "_b.append" in text
    assert "bytes(_b)" in text


# --------------------------------------------------------------------------
# the peeler's own reading of the same shapes
# --------------------------------------------------------------------------

def test_an_accumulator_loop_yields_the_payload():
    encoded = ", ".join(str(byte ^ 0x5A) for byte in PAYLOAD.encode())
    source = (
        "_n = [%s]\n"
        "_b = bytearray()\n"
        "for _c in _n:\n"
        "    _b.append(_c ^ 0x5A)\n"
        "exec(bytes(_b).decode())\n" % encoded
    )
    found = find_payloads(source)
    assert any(payload.data == PAYLOAD.encode() for payload in found), \
        "the loop builds the payload, so the payload is readable"
    assert any("accumulate" in payload.recipe for payload in found), \
        "the reading that replayed the loop is named"


def test_an_index_loop_over_a_literal_yields_the_payload():
    encoded = ", ".join(str(byte) for byte in PAYLOAD.encode())
    source = (
        "_n = [%s]\n"
        "_b = bytearray()\n"
        "for _i in range(%d):\n"
        "    _b.append(_n[_i])\n"
        "exec(bytes(_b).decode())\n" % (encoded, len(PAYLOAD))
    )
    found = [payload for payload in find_payloads(source)
             if payload.data == PAYLOAD.encode()]
    assert found


def test_a_constant_hidden_in_a_class_body_is_still_a_layer():
    import base64
    blob = base64.b64encode(PAYLOAD.encode())
    source = ("import base64\n"
              "class _C:\n"
              "    _p = %r\n"
              "exec(base64.b64decode(_C._p).decode())\n" % blob)
    found = [payload for payload in find_payloads(source)
             if payload.data == PAYLOAD.encode()]
    assert found, "the class body holds a constant, not an unknown"
    assert found[0].recipe, "a folded loader still says which layer it was"
