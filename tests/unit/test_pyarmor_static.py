"""PyArmor 8/9 must fall to static recovery, and must prove it when it does."""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import pyarmor_case as fixture  # noqa: E402
from pydecomp.protectors import pyarmor  # noqa: E402


def _case(key=None):
    folder = tempfile.mkdtemp(prefix="pyarmor-case-")
    return fixture.build(folder, key=key)


def test_header_fields():
    header = pyarmor.parse_header(fixture.make_blob())
    assert header["family"] == "8+"
    assert header["serial"] == "000000"
    assert header["version"] == (3, 13)
    assert header["protection"] == "normal"
    assert len(header["nonce"]) == 12


def test_bcc_flag_read():
    blob = bytearray(fixture.make_blob())
    blob[0x14] = 0x09
    assert pyarmor.parse_header(bytes(blob))["bcc"] is True


def test_runtime_key_is_carved_and_verified():
    case = _case()
    with open(case["runtime"], "rb") as handle:
        runtime = handle.read()
    result = pyarmor.unpack(case["blob"], runtime=runtime)
    assert result.recovered, result.note
    assert result.key == case["key"]
    assert "verified by marshal structure" in result.summary()
    version, code = result.codes[0]
    assert version == (3, 13)
    from pydecomp.lift.module import lift_module
    text = lift_module(code, version)
    assert case["marker"] in text
    assert "def collect" in text


def test_supplied_key_also_works():
    case = _case()
    result = pyarmor.unpack(case["blob"], key=case["key"])
    assert result.recovered
    assert result.source == "supplied key"


def test_wrong_runtime_makes_no_claim():
    case = _case()
    bogus = bytes(range(256)) * 8
    result = pyarmor.unpack(case["blob"], runtime=bogus, max_tries=2000)
    assert not result.recovered
    assert "--pyarmor-key" in result.note


def test_no_runtime_says_what_it_needs():
    result = pyarmor.unpack(fixture.make_blob())
    assert not result.recovered
    assert "runtime" in result.note and "code objects" in result.note


def test_pyarmor7_header_is_not_pretended():
    blob = b"PYARMOR\x00" + b"\x00" * 128
    result = pyarmor.unpack(blob, runtime=b"\x00" * 64)
    assert not result.recovered
    assert "7" in result.note


def test_runtime_found_beside_the_sample():
    case = _case()
    found = pyarmor.find_runtime(case["loader"])
    assert found and os.path.basename(os.path.dirname(found)).startswith("pyarmor_runtime")


def test_context_uses_the_sibling_runtime():
    case = _case()
    pyarmor.set_context(case["loader"])
    context = pyarmor.context()
    assert context["runtime"], "the sibling runtime was not picked up"
    assert context["runtime_path"].endswith("pyarmor_runtime.so")


def test_mixed_strings_decrypt():
    from pydecomp.crypto.aes import AES
    from pydecomp.crypto.modes import ctr_xor
    key, nonce = b"k" * 16, b"n" * 12
    plain = b"https://relay.internal.example/collect"
    const = b"\x81" + ctr_xor(AES(key), nonce, plain, counter_bits=32, start=1)
    assert pyarmor.decrypt_strings([const], key, nonce) == [plain.decode()]


def test_note_names_the_protection():
    note = pyarmor.note(pyarmor.parse_header(fixture.make_blob()))
    assert "PyArmor" in note and "AES-CTR" in note


if __name__ == "__main__":
    failures = 0
    for name, function in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            function()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print("all good" if not failures else f"{failures} failed")
    sys.exit(1 if failures else 0)
