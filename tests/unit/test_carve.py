"""Gate: a Python payload inside a native binary can still be carved out.

Compiled extensions and one-file executables hold their Python layer as bytes
with no Python syntax around them.  These tests pin both halves: real payloads
are found, and random data yields nothing (a false positive here would hand an
analyst an invented program).
"""
import base64
import marshal
import os
import sys
import zlib

import pytest

sys.path.insert(0, "src")
from pydecomp.engine.carve import carve, find_encoded, find_pyc, find_streams  # noqa: E402

CODE = compile('SECRET = "carved-sample"\n\ndef work(x):\n    return SECRET + str(x)\n',
               "<payload>", "exec")
BLOB = marshal.dumps(CODE)


def test_a_compressed_stream_inside_random_bytes_is_found():
    data = os.urandom(2048) + zlib.compress(BLOB) + os.urandom(256)
    found = find_streams(data)
    assert found, "the zlib stream was not carved"
    assert any(marshal.loads(payload).co_name == "<module>" for _o, _h, payload in found)
    assert carve(data), "carve() returned nothing for a carved stream"


def test_an_embedded_pyc_is_found():
    import importlib.util
    data = os.urandom(1024) + importlib.util.MAGIC_NUMBER + b"\x00" * 12 + BLOB
    found = find_pyc(data)
    assert found, "the embedded .pyc was not found"
    assert found[0][1] == "embedded .pyc"


def test_base64_and_base85_literals_are_opened():
    for encoder in (base64.b64encode, base64.b85encode):
        literal = encoder(zlib.compress(BLOB))
        data = os.urandom(1024) + literal + os.urandom(128)
        assert find_encoded(data), f"{encoder.__name__} literal was not opened"
        assert carve(data)


def test_random_data_yields_nothing():
    for _ in range(4):
        data = os.urandom(8192)
        assert carve(data) == []


def test_plain_text_yields_nothing():
    data = ("def work(x):\n    return x + 1\n" * 40).encode()
    assert carve(data) == []


def test_carved_payload_is_the_payload():
    data = os.urandom(512) + zlib.compress(BLOB) + os.urandom(64)
    _offset, _how, payload = carve(data)[0]
    assert marshal.loads(payload).co_name == "<module>"
