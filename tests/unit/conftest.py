"""Conftest for the unit suite.

Two kinds of test live here:

* tests that are about *this interpreter's* bytecode - the round trip compiles a
  shape, marshals it, lifts it and compares instruction streams; the PyArmor and
  proof tests drive the instruction-identity table; the repo tests check that the
  committed fixtures are the ones the generator produces.  Those are only
  meaningful on the interpreter the fixtures were compiled with, because a .pyc
  is a snapshot of one version's opcodes.

* tests that are about the analyser itself - decoders, containers, indicators,
  locate, reports, MCP - and hold on any supported Python.

Running the first group on 3.9 would not be a harder test, it would be a test of
a different claim, so they are skipped there with the reason spelled out and CI
runs the version-neutral smoke on those interpreters instead.
"""
from __future__ import annotations

import sys

import pytest

FIXTURE_PY = (3, 13)

# modules whose assertions are statements about the bytecode of FIXTURE_PY
VERSION_LOCKED = {
    "test_roundtrip.py",
    "test_proof.py",
    "test_pyarmor_static.py",
    "test_platform.py",
    "test_repo.py",
}


def pytest_collection_modifyitems(config, items):
    if sys.version_info[:2] == FIXTURE_PY:
        return
    reason = (f"fixtures and the instruction-identity table are built for "
              f"{FIXTURE_PY[0]}.{FIXTURE_PY[1]}; running on "
              f"{sys.version_info[0]}.{sys.version_info[1]}")
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if item.fspath.basename in VERSION_LOCKED:
            item.add_marker(skip)
