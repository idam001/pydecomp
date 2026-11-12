"""Backend registry, cross-implementation routing, obfuscator naming, plugins."""
from __future__ import annotations

import marshal
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.bytecode import backends  # noqa: E402
from pydecomp.bytecode.backends import orchestrator  # noqa: E402
from pydecomp.bytecode.backends.base import Backend  # noqa: E402
from pydecomp.bytecode.magic import identify_implementation  # noqa: E402

SOURCE = "def run(x):\n    return x * 2\n"


def test_every_version_routes():
    for version in [(3, 8), (3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14), (3, 15)]:
        names = backends.route(version)
        assert names, version
        assert "pydecomp.lift" in names or "pycdc-rs" in names, (version, names)


def test_old_versions_prefer_uncompyle_familyn():
    assert backends.route((3, 8))[0] in ("uncompyle6", "decompyle3")
    assert backends.route((3, 9))[0] == "decompyle3"
    assert "pydecomp.lift" in backends.route((3, 9))


def test_newest_versions_are_not_missing():
    """3.14 and 3.15 must route somewhere, and never crash without the tools."""
    for version in [(3, 14), (3, 15)]:
        assert backends.route(version)
        assert orchestrator.candidates(version), version


def test_missing_backend_is_skipped_not_fatal():
    pool = orchestrator.pool()
    backend = pool["pycdc-rs"]
    assert not backend.available() or backend.available()      # never raises
    names = [item.name for item in orchestrator.candidates((3, 15))]
    assert names, "no candidate would run at all"


def test_decompile_returns_a_tier():
    data = marshal.dumps(compile(SOURCE, "t.py", "exec"))
    text, name, tier = backends.decompile(data, (3, 13))
    assert text and name == "pydecomp.lift"
    assert tier in ("semantic", "structural", "syntactic")
    assert backends.LAST["tried"]


def test_stronger_backend_wins():
    """A backend whose output is instruction-identical beats a broken one."""
    good = compile(SOURCE, "t.py", "exec")

    class Good(Backend):
        name = "good"
        kind = "external"

        def available(self):
            return True

        def decompile(self, data, version):
            return SOURCE

    class Bad(Backend):
        name = "bad"
        kind = "external"

        def available(self):
            return True

        def decompile(self, data, version):
            return "def run(x):\n    return x - 2\n"

    original_pool, original_routes = orchestrator.pool, orchestrator.ROUTES
    orchestrator.pool = lambda: {"pydecomp.lift": backends.NativeBackend(),
                                 "good": Good(), "bad": Bad()}
    orchestrator.ROUTES = (((3, 13), (3, 13), ["bad", "good"]),)
    try:
        data = marshal.dumps(good)
        text, name, tier = orchestrator.decompile(data, (3, 13))
        assert text and name == "good", (name, tier)
        assert tier in ("semantic", "structural")
    finally:
        orchestrator.pool, orchestrator.ROUTES = original_pool, original_routes


def test_upgrade_is_a_noop_without_externals():
    data = marshal.dumps(compile(SOURCE, "t.py", "exec"))
    assert orchestrator.try_upgrade(data, None, (3, 13), SOURCE) is None


def test_cross_implementation_signatures():
    assert identify_implementation(b"\x0a\x0d\x0d\x0a" + b"\x00" * 8)["implementation"] == "pypy"
    assert identify_implementation(b"M\x03payload")["implementation"] == "micropython"
    assert identify_implementation(b"\xca\xfe\xba\xbe\x00\x00")["implementation"] == "jython"
    assert identify_implementation(b"__BRYTHON__ setup")["implementation"] == "brython"
    cpython = identify_implementation((3571).to_bytes(2, "little") + b"\r\n" + b"\x00" * 12)
    assert cpython["implementation"] == "cpython" and cpython["version"] == (3, 13)


def test_obfuscators_are_named_only_on_their_contract():
    from pydecomp.obfuscators import detect, identify, known, unwrap
    assert len(known()) >= 19
    assert identify("# Created by pyminifier\nimport os\n") == "pyminifier"
    assert identify("print('hello')\n") is None
    assert identify("exec(__import__('zlib').decompress(b'xxx'))") == "unidentified loader"
    text, how = unwrap("# Created by pyminifier\nimport os\n")
    assert text and "pyminifier" not in text and how


def test_plugin_registry_runs_and_isolates_failures():
    from pydecomp import plugins
    plugins.REGISTRY.clear()

    @plugins.register_decoder("double", priority=5)
    def double(blob):
        return blob + blob

    @plugins.register_decoder("boom", priority=9)
    def boom(blob):
        raise RuntimeError("bad plugin")

    out, name = plugins.unwrap(b"ab")
    assert out == b"abab" and name == "double"
    assert "decoder" in plugins.summary()
    assert plugins.unregister("double") and plugins.unregister("boom")
    assert plugins.unwrap(b"ab") == (None, "")


def test_fetch_extracts_urls_and_refuses_odd_schemes():
    from pydecomp import fetch
    text = 'A = "https://relay.internal.example/collect"'
    assert fetch.urls(text) == ["https://relay.internal.example/collect"]
    refused = fetch.fetch("file:///etc/passwd", timeout=0.1)
    assert not refused.ok and "refused scheme" in refused.note


def test_fetch_is_opt_in():
    from pydecomp import fetch
    calls = []

    class Fake:
        status = 200

        def read(self, limit):
            calls.append(limit)
            return b"payload"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    original = fetch.urllib.request.urlopen
    fetch.urllib.request.urlopen = lambda *args, **kwargs: Fake()
    try:
        results = fetch.run('X = "http://payload.example/a.bin"', timeout=1)
    finally:
        fetch.urllib.request.urlopen = original
    assert calls, "urlopen was never called even with the opt-in"
    assert results[0].ok and results[0].body == b"payload"
    assert "1/1" in fetch.summary(results)


def test_mcp_handshake_and_tools():
    from pydecomp.mcp import server
    assert server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"]
    listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert {"identify", "peel", "triage", "decompile_pyc", "deobfuscate"} <= names
    bad = server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})
    assert bad["error"]["code"] == -32601
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_mcp_tools_work_read_only():
    from pydecomp.mcp import server
    folder = tempfile.mkdtemp(prefix="mcp-")
    path = os.path.join(folder, "sample.py")
    with open(path, "w") as handle:
        handle.write(SOURCE)
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "deobfuscate",
                                      "arguments": {"path": path, "out": folder}}})
    payload = reply["result"]["content"][0]["text"]
    assert "read-only" in payload and "SOURCE" not in payload.replace(SOURCE, "")
    assert not [name for name in os.listdir(folder) if name != "sample.py"]


def test_freezers_are_recognised_by_signature():
    import freezer_cases as fixtures
    from pydecomp.containers import match, unpack
    expected = {"shiv": "shiv", "pex": "pex", "briefcase": "briefcase",
                "cx_freeze": "cx_freeze", "cx_freeze_bare": "cx_freeze",
                "py2exe": "py2exe", "pyinstaller": "pyinstaller"}
    for name, builder in fixtures.CASES.items():
        reader = match(builder())
        assert reader is not None, name
        assert reader.name == expected[name], (name, reader.name)
        found, members = unpack(builder())
        assert members, name


def test_pyinstaller_recovers_pyz_modules():
    import freezer_cases as fixtures
    from pydecomp.containers import unpack
    _name, members = unpack(fixtures.pyinstaller())
    names = [member[0] for member in members]
    assert "script.pyc" in names
    assert any(member.startswith("pkg.") for member in names), names


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))
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
