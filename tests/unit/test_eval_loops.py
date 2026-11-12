"""Loops, budgets, and the rule that a partial decode is never an answer.

Three things were true before this file existed and none of them were visible:

* a simulated ``while`` loop stopped after 1000 rounds and *said nothing*.  A
  base45 loader walks one round per three characters, so a 3 KB blob is 1125
  rounds - the analyser truncated it at round 1000 and went on to decode the
  fragment, which is a wrong answer delivered with confidence.
* a ``for`` loop over a long blob was silently sliced at 20000 items, with the
  same effect.
* a loader function with no ``return`` was a dead end, because the only way to
  simulate a ``def`` required one.

The tests below hold the line: complete loops finish, unfinished ones raise, and
a function's locals are readable.
"""
from __future__ import annotations

import ast
import base64

import pytest

from pydecomp.exceptions import EvalFailed
from pydecomp.limits import MAX_LOOP_ROUNDS
from pydecomp.eval.evaluator import Evaluator
from pydecomp.engine.peel import _namespace_payloads, find_payloads

B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _b45(data: bytes) -> bytes:
    out = []
    for index in range(0, len(data) - 1, 2):
        value = data[index] * 256 + data[index + 1]
        out += [B45[value % 45], B45[(value // 45) % 45], B45[value // 2025]]
    if len(data) % 2:
        out += [B45[data[-1] % 45], B45[data[-1] // 45]]
    return "".join(out).encode()


def test_a_while_loop_longer_than_a_thousand_rounds_finishes() -> None:
    """The base45 shape: 1500 rounds, which used to be cut to 1000."""
    payload = bytes(range(256)) * 12                    # 3072 bytes -> 4608 chars
    blob = _b45(payload)
    # one round per three characters, so this is the loop length the old cap cut
    assert len(blob) // 3 > 1000, "this test only means something above 1000 rounds"
    source = (
        "_p = %r\n"
        "_A = %r\n"
        "_o = bytearray()\n"
        "_i = 0\n"
        "while _i + 2 < len(_p):\n"
        "    _v = (_A.index(chr(_p[_i]))\n"
        "          + _A.index(chr(_p[_i + 1])) * 45\n"
        "          + _A.index(chr(_p[_i + 2])) * 2025)\n"
        "    _o.extend(_v.to_bytes(2, 'big'))\n"
        "    _i += 3\n"
        "if _i < len(_p):\n"
        "    _o.append(_A.index(chr(_p[_i])) + _A.index(chr(_p[_i + 1])) * 45)\n"
        "_p = bytes(_o)\n"
    ) % (blob, B45)
    ev = Evaluator()
    ev.run_body(ast.parse(source).body)
    assert bytes(ev.env["_p"].value) == payload


def test_a_loop_that_cannot_finish_raises_instead_of_truncating() -> None:
    """Silence is the bug. An unfinished loop must not leave a value behind."""
    body = ast.parse(
        "_n = 0\n"
        "for _c in b'%s':\n"
        "    _n += 1\n" % ("x" * (MAX_LOOP_ROUNDS + 1))
    ).body
    ev = Evaluator()
    with pytest.raises(EvalFailed):
        for stmt in body:
            ev._run_statement(stmt, [MAX_LOOP_ROUNDS + 10])


def test_a_function_without_a_return_still_reports_its_locals() -> None:
    source = (
        "import base64\n"
        "def _go():\n"
        "    blob = base64.b64decode(%r)\n"
        "    text = blob.decode()\n"
        "_go()\n"
    ) % (base64.b64encode(b"print('from a loader')\n"),)
    tree = ast.parse(source)
    ev = Evaluator()
    ev.absorb(tree)
    locals_after = ev.run_function(ev.functions["_go"])
    assert locals_after["text"].value == "print('from a loader')\n"


def test_the_payload_of_a_statement_loader_is_found() -> None:
    """Decode into a name, then exec the name: no decoding expression to read."""
    import zlib

    payload = b"def hello():\n    return 1\n\nhello()\n"
    source = (
        "import zlib\n"
        "def _go():\n"
        "    blob = %r\n"
        "    blob = zlib.decompress(blob)\n"
        "    exec(blob)\n"
        "_go()\n"
    ) % (zlib.compress(payload),)
    found = find_payloads(source)
    assert any(item.data == payload for item in found)


def test_a_plain_program_offers_no_payload() -> None:
    """No exec, no eval: it is not a loader, so nothing is "the payload"."""
    source = (
        "import base64\n"
        "SECRET = 'w4t9-hidden-token'\n"
        "def payload():\n"
        "    return base64.b64decode('cHJpbnQoJ2hpJyk=').decode()\n"
        "def main():\n"
        "    print(payload())\n"
        "main()\n"
    )
    tree = ast.parse(source)
    ev = Evaluator()
    ev.absorb(tree)
    assert _namespace_payloads(tree, ev) == []
