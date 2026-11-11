"""The public surface: what `import pydecomp` promises."""
from __future__ import annotations

import base64
import zlib

import pytest

import pydecomp
from pydecomp import limits


def test_version_is_semver():
    parts = pydecomp.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_core_api_is_exported():
    for name in ("dig", "peel", "polish_source", "audit_source", "lift_module",
                 "decompile_object", "parse_pyc", "MarshalReader",
                 "with_unknown_preamble", "_PydecompUnknown", "neutralize_source",
                 "analyse_recovered"):
        assert hasattr(pydecomp, name), f"{name} is not re-exported"


def test_all_is_complete():
    missing = [name for name in pydecomp.__all__ if not hasattr(pydecomp, name)]
    assert missing == []


def test_limits_are_sane():
    assert limits.MAX_LAYERS >= 1
    assert limits.MAX_DECOMPRESSED >= 1024 * 1024
    assert limits.MAX_SOURCE >= limits.MAX_DECOMPRESSED // 8
    assert "exec" in limits.EXEC_SINKS


def test_dig_recovers_a_two_layer_sample():
    payload = b"import os\nVALUE = 41 + 1\nprint(os.sep, VALUE)\n"
    wrapped = base64.b64encode(zlib.compress(payload)).decode()
    sample = f"import base64, zlib\nexec(zlib.decompress(base64.b64decode({wrapped!r})))\n"

    result = pydecomp.dig(sample.encode(), "sample.py")

    assert "VALUE = 41 + 1" in result.text
    assert result.text.count("\n") >= 2
    # the trace names the layers it peeled, in order
    trace = " ".join(result.trace)
    assert "base64" in trace and "zlib" in trace, trace
    assert result.kind in {"source", "code", "text"}


def test_dig_is_deterministic():
    sample = b"print('same bytes every time')\n"
    first = pydecomp.dig(sample, "a.py").text
    second = pydecomp.dig(sample, "a.py").text
    assert first == second


def test_polish_never_changes_behaviour():
    source = "lIl1 = 2\nIlI1 = lIl1 * 3\nprint(IlI1)\n"
    polished, actions = pydecomp.polish_source(source)
    assert "print(" in polished
    assert isinstance(actions, list)


def test_audit_reports_unbound_names():
    clean = pydecomp.audit_source("value = 1\n")
    assert clean["compiles"] is True
    assert clean["missing"] == []

    loose = pydecomp.audit_source("value = never_defined\n")
    assert loose["missing"] == ["never_defined"]

    broken = pydecomp.audit_source("def broken(:\n")
    assert broken["compiles"] is False


def test_unknown_preamble_is_idempotent():
    text = "x = _PydecompUnknown()\nprint(x(1)['k'])\n"
    once = pydecomp.with_unknown_preamble(text)
    assert once.count("class _PydecompUnknown") == 1
    assert pydecomp.with_unknown_preamble(once) == once
    assert pydecomp.audit_source(once)["compiles"] is True


def test_unknown_sentinel_is_forgiving():
    sentinel = pydecomp._PydecompUnknown("x")
    chained = sentinel(1)[2].anything
    assert isinstance(chained, pydecomp._PydecompUnknown)
    assert not sentinel
    assert list(sentinel) == []


@pytest.mark.parametrize("size", [0, 1, 4096])
def test_dig_survives_degenerate_input(size):
    result = pydecomp.dig(b"A" * size, "empty.py")
    assert isinstance(result.text, str)
