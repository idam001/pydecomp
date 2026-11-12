"""Gate: run-time key material can still be recovered by enumeration.

``_k = len(os.urandom(16))`` has no static value, but the space it can take is
tiny.  These tests pin the two halves of that claim: the space is inferred
correctly, and only a candidate whose payload is structurally valid is accepted
- so a wrong key can never be presented as a recovery.
"""
import sys

import pytest

sys.path.insert(0, "src")
from pydecomp.eval.keyhunt import candidates, describe, hunt   # noqa: E402

PAYLOAD = 'print("recovered-key-sample")'


def _sample(key: int, declared: str = "len(os.urandom(16))") -> str:
    encrypted = bytes(byte ^ key for byte in PAYLOAD.encode())
    return ("import os\n"
            f"_k = {declared}\n"
            f"_d = {encrypted!r}\n"
            "exec(bytes(c ^ _k for c in _d).decode())\n")


def test_the_obvious_space_is_inferred_exactly():
    spaces = dict(candidates(_sample(16)))
    assert spaces["_k"] == [16], "len(os.urandom(16)) is 16 and must be inferred"


def test_a_length_derived_key_is_found():
    result = hunt(_sample(16))
    assert result is not None
    assert result["value"] == 16
    assert PAYLOAD in str(result["payload"])
    assert result["ambiguous"] is False


def test_a_key_that_does_not_match_the_declared_length_is_still_found():
    result = hunt(_sample(0x5A))
    assert result is not None
    assert result["value"] == 0x5A
    assert PAYLOAD in str(result["payload"])


def test_a_wrong_key_is_never_reported():
    result = hunt(_sample(16))
    assert result is not None
    assert result["value"] != 0x11, "a candidate that yields garbage must not win"


def test_random_bytes_do_not_yield_a_key():
    source = ("import os\n"
              "_k = len(os.urandom(16))\n"
              "_d = " + repr(bytes(range(40))) + "\n"
              "exec(bytes(c ^ _k for c in _d).decode())\n")
    assert hunt(source) is None


def test_ord_and_modulo_spaces_are_understood():
    ord_space = dict(candidates("import os\nk = ord(os.urandom(1).decode())\n"))
    assert ord_space["k"] == list(range(256))
    mod_space = dict(candidates("import time\nk = int(time.time()) % 7\n"))
    assert mod_space["k"] == list(range(7))


def test_a_fixed_key_needs_no_hunting():
    source = ("_k = 7\n"
              "_d = " + repr(bytes(byte ^ 7 for byte in PAYLOAD.encode())) + "\n"
              "exec(bytes(c ^ _k for c in _d).decode())\n")
    assert candidates(source) == []


def test_describe_is_one_line_and_names_the_key():
    line = describe(hunt(_sample(16)))
    assert "\n" not in line
    assert "_k" in line and "0x10" in line
