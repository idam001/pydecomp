"""What counts as "the payload", and what only looks like it.

The peeler decides a layer is the program when its bytes are source.  The
decoder that used to make that call - ``looks_like_python`` - accepted base64
text, because a base64 blob is a run of letters and digits and nothing else.
That is how three random stacks (a ``b64url`` under an ``xor``) came back
"recovered": the analyser wrote out the layer *before* the payload and called it
the answer.  These tests pin the rule that replaced it.
"""
from __future__ import annotations

import base64

from pydecomp.engine.peel import _folded_source, _is_program, find_payloads


def test_a_program_is_a_program() -> None:
    assert _is_program("x = 1\n")
    assert _is_program("def f():\n    return 1\n")
    assert _is_program("print('hi')\n")


def test_base64_is_not_a_program() -> None:
    blob = base64.b64encode(b"class Session:\n    def url(self):\n        pass\n")
    # one enormous identifier: parses perfectly, is not source
    assert _is_program(blob.decode()) is False


def test_garbage_is_not_a_program() -> None:
    assert _is_program("@#$%^&*") is False
    assert _is_program("") is False
    assert _is_program("('unclosed") is False


def test_a_docstring_only_blob_is_not_a_program() -> None:
    # a constant expression is a legal module and says nothing
    assert _is_program("'just a string'\n") is False
    assert _is_program("42\n") is False


def test_fold_turns_a_comprehension_into_a_literal() -> None:
    folded = _folded_source("_p = bytes([b ^ 0x33 for b in b'abc'])")
    assert folded is not None
    assert "_p = b'RQP'" in folded


def test_fold_leaves_real_code_alone() -> None:
    assert _folded_source("_p = 'hello'") is None
    assert _folded_source("import os\nos.system('x')") is None


def test_fold_refuses_a_conditional_comprehension() -> None:
    # an `if` makes the result depend on a predicate the folder will not guess
    assert _folded_source("_p = bytes([b ^ 0x33 for b in b'abc' if b])") is None


def test_the_payload_wins_over_the_layer_before_it() -> None:
    source = b"value = 1\nprint(value)\n"
    text = base64.urlsafe_b64encode(source).rstrip(b"=")
    blob = bytes(byte ^ 0x33 for byte in text)
    loader = ("import base64\n_p = %r\n"
              "exec(base64.b64decode(bytes([b ^ 0x33 for b in _p])))\n") % (blob,)
    found = find_payloads(loader)
    assert found, "the loader must yield at least one payload"
    assert found[0].data == source


def test_ranking_prefers_a_program_over_a_longer_blob() -> None:
    """The b64url → xor stack: the unde-xor'd text is *shorter* than the program.

    Padding restoration makes the text grow only sometimes, so length alone can
    never be the tie-break; the parse has to come first.
    """
    source = b"x = 1\n"
    text = base64.b64encode(source)          # b'eCA9IDEK', not a program
    assert len(text) > len(source)
    blob = bytes(byte ^ 0x33 for byte in text)
    loader = ("import base64\n_p = %r\n"
              "exec(base64.b64decode(bytes([b ^ 0x33 for b in _p])))\n") % (blob,)
    assert find_payloads(loader)[0].data == source


def test_getattr_is_a_name_not_a_mystery() -> None:
    """`getattr(builtins, "exec")` is `exec`, and the sink scan has to agree."""
    source = (
        "import zlib\n"
        "_p = %r\n"
        "_p = zlib.decompress(_p)\n"
        "getattr(__import__('builtins'), 'exec')(_p)\n"
    ) % (__import__("zlib").compress(b"def f():\n    return 2\n"),)
    found = find_payloads(source)
    assert any(b"def f()" in item.data for item in found)


def test_a_loader_inside_a_class_method_is_read() -> None:
    """Hyperion hides the loader in a method; nothing calls it by name."""
    import zlib

    payload = b"def hidden():\n    return 3\n"
    source = (
        "import zlib\n"
        "class _Loader:\n"
        "    def run(self):\n"
        "        blob = %r\n"
        "        blob = zlib.decompress(blob)\n"
        "        exec(blob)\n"
        "\n_Loader().run()\n"
    ) % (zlib.compress(payload),)
    found = find_payloads(source)
    assert any(item.data == payload for item in found)


SINK_SPELLINGS = (
    "b.exec(__import__('zlib').decompress(%r))",
    "__import__('built' + 'ins').exec(__import__('zlib').decompress(%r))",
    "getattr(__import__('built' + 'ins'), 'ex' + 'ec')(__import__('zlib').decompress(%r))",
    "__import__('builtins').__getattribute__('ex' + 'ec')(__import__('zlib').decompress(%r))",
    "sys.modules['builtins'].exec(__import__('zlib').decompress(%r))",
    "globals()['__builtins__'].exec(__import__('zlib').decompress(%r))",
    "getattr(__import__('builtins'), ''.join(['ex', 'ec']))(__import__('zlib').decompress(%r))",
)


def test_a_hidden_exec_is_still_exec() -> None:
    """Seven spellings of the same call, six of which used to be invisible.

    `"built" + "ins"`, `globals()['__builtins__']`, `__getattribute__` and a
    `join` of two halves are all routes to the builtin; the point of spelling it
    that way is to defeat a text scan, not to change what runs.
    """
    import zlib

    payload = b"def hidden_again():\n    return 11\n"
    blob = zlib.compress(payload)
    for spelling in SINK_SPELLINGS:
        source = "import sys, builtins\n_b = builtins\n" + (spelling % blob) + "\n"
        found = find_payloads(source)
        assert any(item.data == payload for item in found), spelling
