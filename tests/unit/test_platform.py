"""The pipeline is this project's own: routing, versions, no delegation.

This file used to check *which external decompiler* a version routed to.  There
are none now: `route()` answers the same thing for every version because there
is one engine, it is bundled, and it is the only one that runs.  What is worth
testing is the invariant that makes the single-file build honest - nothing in
the package shells out, and nothing imports somebody else's decompiler.
"""
from __future__ import annotations

import ast
import marshal
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.bytecode import backends  # noqa: E402
from pydecomp.bytecode.backends.base import Backend  # noqa: E402
from pydecomp.bytecode.magic import identify_implementation  # noqa: E402
from pydecomp.protectors import nuitka  # noqa: E402

SOURCE = "def run(x):\n    return x * 2\n"

VERSIONS = [(3, 8), (3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14), (3, 15)]

#: packages that are somebody else's decompiler.  Naming them here is the point:
#: the test fails the day one of them appears in the source tree.
FOREIGN = ("pycdc", "uncompyle6", "decompyle3", "depyo", "decompyle", "pycdas",
           "hexpyrion", "nuitka_revenant", "revenant")


def _package_sources():
    root = os.path.join(ROOT, "src", "pydecomp")
    for folder, _dirs, files in os.walk(root):
        if "__pycache__" in folder:
            continue
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(folder, name)


def test_every_version_takes_the_same_route():
    for version in VERSIONS:
        assert backends.route(version) == ["pydecomp.lift"], version
        assert backends.candidates(version), version


def test_the_pool_has_one_engine():
    pool = backends.pool()
    assert list(pool) == ["pydecomp.lift"]
    assert pool["pydecomp.lift"].kind == "native"


def test_decompile_returns_a_tier():
    data = marshal.dumps(compile(SOURCE, "t.py", "exec"))
    text, name, tier = backends.decompile(data, (3, 13))
    assert text and name == "pydecomp.lift"
    assert tier in ("perfect", "semantic", "structural", "syntactic", "unverified")
    assert backends.LAST["tried"] == ["pydecomp.lift"]


def test_nothing_shells_out():
    """A deobfuscator that runs another binary is not self-contained."""
    offenders = []
    for path in _package_sources():
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name.split(".")[0] == "subprocess":
                    offenders.append(f"{os.path.relpath(path, ROOT)} imports subprocess")
    assert offenders == [], offenders


def test_no_foreign_decompiler_is_named_in_code():
    """Docstrings may mention them; executable code may not."""
    offenders = []
    for path in _package_sources():
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, path)
        for node in ast.walk(tree):
            text = None
            if isinstance(node, ast.Import):
                text = " ".join(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                text = node.module or ""
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # a shell command or a module path pointing at another tool
                if any(name in node.value for name in FOREIGN) and (
                        "/" in node.value or " " in node.value or "=" in node.value):
                    text = node.value
            elif isinstance(node, ast.Name):
                text = node.id
            if text and any(name in text for name in FOREIGN):
                offenders.append(f"{os.path.relpath(path, ROOT)}: {text[:60]}")
    assert offenders == [], offenders


def test_no_optional_backend_extra():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        text = handle.read()
    assert "backends = [" not in text
    assert "[project.optional-dependencies]" in text       # dev/docs extras stay
    assert "dependencies = []" in text


def test_nuitka_recovery_is_in_house():
    """No external tool, no subprocess: the image is read by our own parsers."""
    result = nuitka.recover("/nonexistent/image.bin", tempfile.mkdtemp())
    assert result["backend"] == "nuitka"
    assert "no such file" in result["note"]
    assert nuitka.available() == "in-house"


def test_cross_implementation_signatures():
    assert identify_implementation(b"\x0a\x0d\x0d\x0a" + b"\x00" * 8)["implementation"] == "pypy"
    assert identify_implementation(b"M\x03payload")["implementation"] == "micropython"


def test_a_custom_backend_can_still_win_on_evidence():
    """The interface stays honest: a better answer wins, whoever produced it."""
    good = compile(SOURCE, "t.py", "exec")

    class Good(Backend):
        name = "good"
        kind = "native"

        def decompile(self, data, version):
            return SOURCE

    class Bad(Backend):
        name = "bad"
        kind = "native"

        def decompile(self, data, version):
            return "def run(x):\n    return x - 2\n"

    original_candidates, original_route = backends.candidates, backends.route
    backends.candidates = lambda version: [Bad(), Good()]
    try:
        data = marshal.dumps(good)
        text, name, tier = backends.decompile(data, (3, 13))
        assert text and name == "good", (name, tier)
        assert tier in ("perfect", "semantic", "structural")
    finally:
        backends.candidates, backends.route = original_candidates, original_route
