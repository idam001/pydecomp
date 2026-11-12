"""Gate: sealed blob classification says something true, and nothing more.

The point of this module is to turn "4 opaque blobs, no idea" into measurements
an analyst can reproduce.  These tests keep it honest:

* random data must read as high entropy, never as a repeating key,
* padding must not be mistaken for a cipher,
* a genuine repeating-key XOR must be detected as a repeat at the key length,
* and no verdict may ever claim the blob was opened.
"""
import marshal
import os
import sys

import pytest

sys.path.insert(0, "src")
from pydecomp.triage.sealed import classify, dominant, entropy, period, render, summary  # noqa: E402

CLAIMS = ("decrypted", "unsealed", "recovered", "opened plaintext")


def test_entropy_bounds():
    assert entropy(os.urandom(4096)) > 7.0
    assert entropy(bytes(4096)) == 0.0
    assert 4.0 < entropy(bytes(range(256)) * 16) <= 8.0


def test_random_data_is_never_called_a_repeating_key():
    for _ in range(3):
        entry = classify(os.urandom(16384))
        assert entry["kind"] in {"high-entropy", "opaque"}
        assert entry["period"] == 0


def test_padding_is_not_a_cipher():
    entry = classify(bytes(9000))
    assert entry["kind"] == "structured"
    assert "padding" in entry["verdict"]


def test_repeating_key_xor_is_detected():
    plain = open(__file__, "rb").read() * 6          # skewed, not periodic
    key = b"\x13\xa7\x04\xc9\x2b\x7d\xe1\x55"
    sealed = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plain))
    entry = classify(sealed)
    assert entry["kind"] == "cyclical"
    assert entry["period"] % 8 == 0                    # multiples are fine
    assert entry["period_ratio"] >= 8.0


def test_marshalled_code_reads_as_structured_or_opaque():
    blob = marshal.dumps(compile("def f(x):\n    return x + 1\n", "<t>", "exec"))
    entry = classify(blob)
    assert entry["kind"] in {"structured", "opaque", "cyclical"}
    assert entry["size"] == len(blob)


def test_no_verdict_claims_an_open():
    samples = [os.urandom(8192), bytes(9000), bytes(range(256)) * 32,
               b"\x01\x02" * 4000]
    for blob in samples:
        verdict = classify(blob)["verdict"].lower()
        assert not any(claim in verdict for claim in CLAIMS)
        assert "not opened" in verdict or "not encrypted" in verdict or "padding" in verdict


def test_summary_counts_kinds():
    entries = [classify(os.urandom(8192)), classify(b"x" * 8192)]
    line = summary(entries)
    assert "2 blob(s)" in line and "high-entropy" in line


def test_render_lists_measurements():
    lines = render([classify(b"ab" * 5000)])
    assert any("entropy" in line for line in lines)
    assert any("dominant" in line for line in lines)


def test_dominant_and_period_are_measurable_by_hand():
    blob = b"abcabcabcabc"
    assert dominant(blob)[0] == ord("a")
    stride, score = period(blob)
    assert stride == 3 and score > 0.9
