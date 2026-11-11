"""Native gates: Cython (menu 2) and ELF (menu 3) recovery.

The fixtures in ``fixtures/native`` are built from one 64-line module whose
source is also kept, so every check here compares the recovery against the
truth instead of against itself:

    cython --line-directives -3 demo_module.py -o demo_module.c
    gcc -shared -fPIC -O1 ... demo_module.c     -> demo_module.so   (tier S)
    gcc -shared -fPIC -O1 -g ... demo_module.c  -> demo_lines.so    (tier B)
    gcc -shared -fPIC -O1 -g ... plain .c       -> demo_module_g.so (tier B)
    strip -s demo_module.so                     -> demo_stripped.so (tier A)

The rule the gates enforce: whatever else is lost, the names, the docstrings
and the class layout must survive, and when the generated C is present the
rebuilt ``.py`` must be byte-identical to the original.
"""
import io
import os
import sys
import contextlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from pydecomp.native import sidecar as N                          # noqa: E402
import pydecomp as P                                              # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "native")
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
ENV = {**os.environ, "PYTHONPATH": SRC}
if SRC not in sys.path:
    sys.path.insert(0, SRC)
FAILED = []
SKIPPED = []

METHOD_NAMES = {"__init__", "describe", "push",
                "build_headers", "parse_payload", "summarise", "main"}
DOCS = {
    "describe": "Return a human readable summary.",
    "build_headers": "Build the request header set.",
    "parse_payload": "Parse a JSON payload, returning an empty dict on failure.",
}


def check(name):
    def wrap(fn):
        if not os.path.isdir(FIXTURES) or not os.path.exists(os.path.join(FIXTURES, "demo_module.so")):
            SKIPPED.append(name)
            print(f"skip  {name}")
            return fn
        try:
            fn()
            print(f"ok    {name}")
        except Exception as exc:                                # noqa: BLE001
            FAILED.append(name)
            print(f"FAIL  {name}\n      {type(exc).__name__}: {exc}")
        return fn
    return wrap


def eq(got, want, label=""):
    assert got == want, f"{label}: got {got!r}, want {want!r}"


def ok(cond, label=""):
    assert cond, label or "condition failed"


def fixture(name):
    path = os.path.join(FIXTURES, name)
    with open(path, "rb") as handle:
        return path, N.ElfImage(handle.read(), path)


def info_for(name):
    path, img = fixture(name)
    return N.CythonInfo(img).analyse()


def truth():
    with open(os.path.join(FIXTURES, "demo_module.py"), encoding="utf-8") as handle:
        return handle.read()


def body_of(text):
    """Drop the banner comment block at the top of a rebuilt file."""
    lines = text.splitlines()
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    return lines


# --------------------------------------------------------------- ELF layer
@check("ELF header, sections and symbols parse")
def _elf():
    _path, img = fixture("demo_module.so")
    eq(img.bits, 64, "ELF class")
    ok(img.section(".text") is not None, "no .text")
    ok(img.section(".rodata") is not None, "no .rodata")
    ok(len(img.symbols) > 100, f"only {len(img.symbols)} symbols")
    ok(img.section(".rela.dyn") is not None or img.relocs, "no relocations")
    names = {symbol.name for symbol in img.symbols}
    ok("PyInit_demo_module" in names, "PyInit_demo_module missing")


@check("module identity: name, source file, compiler, Cython version")
def _identity():
    info = info_for("demo_module.so")
    eq(info.module, "demo_module", "module name")
    eq(info.source_name, "demo_module.py", "source file")
    ok("GCC" in info.compiler, f"compiler {info.compiler!r}")
    ok(info.cython_version.startswith("3."), f"cython {info.cython_version!r}")


@check("mangled C names decode to qualified Python names")
def _mangling():
    cases = {
        "__pyx_mdef_11demo_module_1build_headers": "demo_module.build_headers",
        "__pyx_mdef_11demo_module_7Session_3describe": "demo_module.Session.describe",
        "__pyx_pw_11demo_module_7Session_1__init__": "demo_module.Session.__init__",
        "__pyx_mdef_11demo_module_7main": "demo_module.main",
    }
    for mangled, want in cases.items():
        _kind, got = N.parse_mangled(mangled)
        eq(got, want, mangled)


# ------------------------------------------------------------ method tables
@check("PyMethodDef recovery on every build (7 methods, no junk)")
def _methods():
    for name in ("demo_module.so", "demo_stripped.so",
                 "demo_lines.so", "demo_module_g.so"):
        info = info_for(name)
        got = [method.name for method in info.methods]
        eq(len(got), 7, f"{name}: methods {got}")
        eq(set(got), METHOD_NAMES, f"{name}: method names")


@check("docstrings come out verbatim")
def _docstrings():
    info = info_for("demo_module.so")
    by_name = {method.name: method.doc for method in info.methods}
    for name, want in DOCS.items():
        eq(by_name.get(name), want, f"docstring of {name}")
    eq(by_name.get("__init__"), None, "empty docstring should stay empty")


@check("class layout survives an unstripped build")
def _classes():
    info = info_for("demo_module.so")
    methods = [method.name for method in info.classes.get("Session", [])]
    eq(sorted(methods), ["__init__", "describe", "push"], "Session methods")
    eq(sorted(method.name for method in info.functions),
       ["build_headers", "main", "parse_payload", "summarise"], "module functions")


@check("flag decoding matches PyMethodDef semantics")
def _flags():
    info = info_for("demo_module.so")
    method = next(item for item in info.methods if item.name == "describe")
    # Cython 3 on CPython 3.13+ declares `def` methods as FASTCALL|KEYWORDS
    ok("METH_KEYWORDS" in method.flag_names, method.flag_names)
    ok("METH_FASTCALL" in method.flag_names, method.flag_names)


# --------------------------------------------------------- tier S (verbatim)
@check("tier S: .c line comments rebuild the original file byte for byte")
def _tier_s_exact():
    info = info_for("demo_module.so")
    eq(info.tier, "S", "tier")
    recovered = N.cython_source(info)
    eq(body_of(recovered), truth().splitlines()[0:], "rebuilt body")


@check("tier S: the rebuilt file compiles")
def _tier_s_compiles():
    info = info_for("demo_module.so")
    compile(N.cython_source(info), "recovered.py", "exec")


@check("tier S: every quoted line is placed at its original line number")
def _tier_s_lines():
    info = info_for("demo_module.so")
    reference = truth().splitlines()
    eq(len(info.source_lines), len(reference), "quoted line count")
    for number, text in info.source_lines.items():
        if text.strip():
            eq(text.rstrip(), reference[number - 1].rstrip(), f"line {number}")


# ------------------------------------------------------ tier B / tier A
@check("tier B: DWARF gives the source line numbers")
def _tier_b():
    info = info_for("demo_lines.so")
    eq(info.tier, "B", "tier")
    ok(len(info.line_map) > 100, f"line rows {len(info.line_map)}")
    ok(info.line_extent and info.line_extent[1] >= 30, f"extent {info.line_extent}")


@check("tier B: the skeleton keeps names, docstrings and imports")
def _tier_b_skeleton():
    info = info_for("demo_lines.so")
    text = N.cython_source(info)
    for name in METHOD_NAMES:
        ok(f"def {name}(" in text, f"{name} missing from the skeleton")
    for want in DOCS.values():
        ok(want in text, f"docstring {want!r} missing")
    compile(text, "skeleton.py", "exec")


@check("tier A: a stripped build still yields every method and docstring")
def _tier_a():
    info = info_for("demo_stripped.so")
    eq(info.tier, "A", "tier")
    text = N.cython_source(info)
    for name in METHOD_NAMES:
        ok(f"def {name}(" in text, f"{name} missing")
    for want in DOCS.values():
        ok(want in text, f"docstring {want!r} missing")
    compile(text, "stripped.py", "exec")


@check("tier A: no Cython runtime text leaks into the rebuild")
def _tier_a_noise():
    info = info_for("demo_stripped.so")
    text = N.cython_source(info)
    for noise in ("cython_function_or_method", "Placeholder __annotate__",
                  "__pyx_", "_common_types_metatype"):
        ok(noise not in text, f"junk in the rebuild: {noise}")


# ------------------------------------------------------------- reporting
@check("report names the tier and the limits")
def _report():
    info = info_for("demo_module.so")
    text = N.cython_report(info)
    ok("tier" in text.lower(), "report has no tier")
    ok("demo_module" in text, "report has no module name")
    ok("Session.describe" in text, "report lists no methods")


@check("analyse_native writes source, report and the line dump")
def _analyse_native():
    import tempfile
    folder = tempfile.mkdtemp()
    result = N.analyse_native(os.path.join(FIXTURES, "demo_module.so"), folder)
    names = [os.path.basename(path) for path in result["written"]]
    eq(result["kind"], "cython", "kind")
    ok("demo_module_deob.py" in names, names)
    ok("demo_module_report.md" in names, names)
    ok("demo_module_lines.txt" in names, names)
    with open(os.path.join(folder, "demo_module_deob.py"), encoding="utf-8") as handle:
        eq(body_of(handle.read()), truth().splitlines()[0:], "written file")


@check("ELF mode hunts for python payloads without crashing")
def _elf_mode():
    import tempfile
    folder = tempfile.mkdtemp()
    result = N.analyse_native(os.path.join(FIXTURES, "demo_module.so"), folder, "elf")
    eq(result["kind"], "elf", "kind")
    ok(result["report"], "empty report")
    ok("Python payload detection" in result["report"], "report structure")


@check("ELF mode decompiles a payload appended to a stripped module")
def _zip_payload():
    import tempfile
    folder = tempfile.mkdtemp()
    packed = os.path.join(FIXTURES, "packed_zip.so")
    ok(os.path.exists(packed), "packed_zip.so fixture missing")
    result = N.analyse_native(packed, folder, "elf")
    eq(result["stats"]["payloads"], 1, "payload count")
    sources = [path for path in result["written"] if path.endswith("_deob.py")]
    eq(len(sources), 1, result["written"])
    with open(sources[0], encoding="utf-8") as handle:
        text = handle.read()
    ok("def parse_payload(" in text, "recovered body missing")
    ok("RECOVER_ME_7731" in text, "recovered literal missing")


@check("compressed containers are inflated without running anything")
def _compressed_streams():
    _path, img = fixture("packed_marshal.so")
    streams = N.compressed_streams(img.data)
    eq(len(streams), 1, f"streams {streams}")
    eq(streams[0]["kind"], "zlib", "container kind")
    ok(streams[0]["payload"].startswith(b"\xe3") or b"json" in streams[0]["payload"],
       f"payload head {streams[0]['payload'][:8]!r}")


@check("compressed payload: marshal code object recovered and decompiled")
def _compressed_payload():
    import tempfile
    folder = tempfile.mkdtemp()
    packed = os.path.join(FIXTURES, "packed_marshal.so")
    ok(os.path.exists(packed), "packed_marshal.so fixture missing")
    result = N.analyse_native(packed, folder, "elf")
    eq(result["stats"]["payloads"], 1, "payload count")
    with open(result["primary"], encoding="utf-8") as handle:
        text = handle.read()
    for want in ("import json", "LIMIT = 3", "def main(", "Payload used to test"):
        ok(want in text, f"{want!r} missing from the recovered payload")


@check("every code object in the tree becomes a definition")
def _payload_completeness():
    _path, img = fixture("packed_marshal.so")
    entry = N.compressed_payloads(img)[0]
    text, table, rebuilt = N.reconstruct_payload(
        entry["blob"], "packed", entry["version"], entry["code"])
    names = {code.name for code in N.code_tree(entry["code"])
             if code.name.isidentifier() and code.name != "<module>"}
    have = N._recovered_defs(text)
    eq(sorted(names - have), [], "code objects missing from the rebuild")
    ok(rebuilt >= 1, f"nothing rebuilt exactly (table {table})")


@check("misplaced nested defs are hoisted back to module scope")
def _hoist():
    import ast
    source = ("def outer():\n"
              "    if True:\n"
              "        def inner():\n"
              "            return 1\n"
              "    return 2\n")
    tree = N._hoist_module_defs(ast.parse(source), {"inner", "outer"})
    names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    eq(sorted(names), ["inner", "outer"], names)


@check("the lifter's open lines are repaired before parsing")
def _lift_repair():
    text = ("def f():\n"
            "    first_name = \n"
            "    0 ? names.rsplit(' ')\n"
            "    return 1\n")
    ok(N.parse_lifted(N.sanitize_lifted(text)) is not None, "repair failed")


@check("a real Android Cython stub is recovered end to end")
def _xynora():
    sample = os.path.join(FIXTURES, "xynora.so")
    if not os.path.exists(sample):
        raise RuntimeError("skip")
    import tempfile
    folder = tempfile.mkdtemp()
    result = N.analyse_native(sample, folder, "auto")
    eq(result["kind"], "cython", "kind")
    stats = result["stats"]
    eq(stats["payloads"], 1, "payload count")
    ok(stats["payload_functions"] >= 15, f"functions {stats['payload_functions']}")
    ok(stats["payload_rebuilt"] >= 9, f"rebuilt {stats['payload_rebuilt']}")
    with open(result["primary"], encoding="utf-8") as handle:
        text = handle.read()
    for want in ("def main(", "requests.Session()", "BeautifulSoup"):
        ok(want in text, f"{want!r} missing from the recovered payload")
    compile(text, "xynora.py", "exec")


@check("mode detection flags a Cython module")
def _detect():
    _path, img = fixture("demo_stripped.so")
    findings = N.detect(img)
    ok(findings["cython"], f"cython not detected: {findings}")


# --------------------------------------------------------------- menu + CLI
@check("--selftest confirms the install")
def _selftest():
    import subprocess
    result = subprocess.run([sys.executable, "-m", "pydecomp",
                             "--no-color", "--selftest"],
                            capture_output=True, text=True, timeout=300, env=ENV)
    eq(result.returncode, 0, result.stdout[-400:] + result.stderr[-400:])
    ok("native layer is ready" in result.stdout, result.stdout[-400:])


@check("a lone single-file build carries its own native layer, no traceback")
def _missing_native():
    """The bundle embeds the sidecar, so a bare .py file is self-sufficient."""
    import shutil
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    lonely = os.path.join(folder, "pydecomp.py")
    shutil.copyfile(os.path.join(ROOT, "dist", "pydecomp.py"), lonely)
    result = subprocess.run([sys.executable, lonely, "--no-color", "--no-anim",
                             os.path.join(FIXTURES, "demo_module.so"), "-o", folder],
                            capture_output=True, text=True, timeout=300)
    eq(result.returncode, 0, result.stdout[-400:] + result.stderr[-400:])
    ok("Traceback" not in result.stderr, result.stderr[-400:])
    ok([name for name in os.listdir(folder) if name.endswith("_deob.py")],
       "no source written by the bundle")


@check("single-file build works with no siblings on disk")
def _single_file():
    import shutil
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    build = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_single.py")],
                           capture_output=True, text=True, timeout=600, env=ENV)
    eq(build.returncode, 0, build.stderr[-400:])
    single = os.path.join(ROOT, "dist", "pydecomp.py")
    ok(os.path.exists(single), "dist/pydecomp.py was not written")
    alone = os.path.join(folder, "pydecomp.py")
    shutil.copyfile(single, alone)
    sample = os.path.join(folder, "Xynora.so")
    shutil.copyfile(os.path.join(ROOT, "uploads", "xynora.so.txt"), sample) \
        if os.path.exists(os.path.join(ROOT, "uploads", "xynora.so.txt")) else None
    target = sample if os.path.exists(sample) else \
        os.path.join(FIXTURES, "packed_marshal.so")
    result = subprocess.run([sys.executable, alone, "--no-color", "--no-anim",
                             target, "-o", folder],
                            capture_output=True, text=True, timeout=900)
    eq(result.returncode, 0, result.stderr[-400:])
    ok("DONE" in result.stdout, result.stdout[-400:])
    eq([n for n in os.listdir(folder) if n == "native.py"], [],
       "the build leaked a native.py sibling")
    recovered = [name for name in os.listdir(folder) if name.endswith("_deob.py")]
    ok(recovered, f"nothing recovered: {os.listdir(folder)}")


@check("menu offers options 1, 2 and 3")
def _menu():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        P.menu()
    text = buffer.getvalue()
    for key in ("[1]", "[2]", "[3]", "[0]"):
        ok(key in text, f"{key} missing from the menu")
    ok("Cython" in text, "no Cython row")
    ok("ELF" in text, "no ELF row")


@check("option 2 end to end through the interactive loop")
def _loop_cython():
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    sample = os.path.join(FIXTURES, "demo_module.so")
    result = subprocess.run([sys.executable, "-m", "pydecomp",
                             "--no-color", "--no-anim", "-o", folder],
                            input=f"2\n{sample}\n\n0\n",
                            capture_output=True, text=True, timeout=600, env=ENV)
    eq(result.returncode, 0, result.stderr[-400:])
    ok("DONE" in result.stdout, result.stdout[-400:])
    written = [name for name in os.listdir(folder) if name.endswith("_deob.py")]
    eq(len(written), 1, f"outputs {written}")


@check("option 3 end to end through the interactive loop")
def _loop_elf():
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    sample = os.path.join(FIXTURES, "demo_stripped.so")
    result = subprocess.run([sys.executable, "-m", "pydecomp",
                             "--no-color", "--no-anim", "-o", folder],
                            input=f"3\n{sample}\n\n0\n",
                            capture_output=True, text=True, timeout=600, env=ENV)
    eq(result.returncode, 0, result.stderr[-400:])
    written = [name for name in os.listdir(folder) if name.endswith("_report.md")]
    ok(written, f"no report written: {os.listdir(folder)}")


@check("the CLI routes an ELF file to the native path on its own")
def _cli_auto():
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    result = subprocess.run([sys.executable, "-m", "pydecomp",
                             os.path.join(FIXTURES, "demo_module.so"),
                             "-o", folder, "--no-color", "--no-anim"],
                            capture_output=True, text=True, timeout=600, env=ENV)
    eq(result.returncode, 0, result.stderr[-400:])
    ok("source-bearing" in result.stdout, result.stdout[-400:])


@check("option 1 still handles a plain script")
def _plain_still_works():
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    sample = os.path.join(HERE, "integration", "t8_plain.py")
    result = subprocess.run([sys.executable, "-m", "pydecomp", sample,
                             "-o", folder, "--no-color", "--no-anim"],
                            capture_output=True, text=True, timeout=600, env=ENV)
    eq(result.returncode, 0, result.stderr[-400:])
    ok([name for name in os.listdir(folder) if name.endswith(".py")], "no output")


# --------------------------------------------------------------------------- 7.2.0
class _LineStub:
    """Just enough of ElfImage for the DWARF line parser."""

    def __init__(self, data):
        self.data = data
        self.bits = 64

    def section(self, name):
        return None

    def _u16(self, pos):
        return int.from_bytes(self.data[pos:pos + 2], "little")

    def _u32(self, pos):
        return int.from_bytes(self.data[pos:pos + 4], "little")

    def _u64(self, pos):
        return int.from_bytes(self.data[pos:pos + 8], "little")


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)


def _dwarf_v4_unit():
    """Hand-built DWARF 4 line unit: two rows, one from a named directory."""
    prologue = bytearray()
    prologue += bytes([1, 1, 1, 0xFB, 14, 13])          # min_inst, max_ops, stmt, base, range, opbase
    prologue += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    prologue += b"src\0\0"                               # include_directories + terminator
    prologue += b"demo.py\0" + _uleb(1) + _uleb(0) + _uleb(0)
    prologue += b"demo.c\0" + _uleb(1) + _uleb(0) + _uleb(0)
    prologue += b"\0"                                     # file_names terminator
    program = bytearray()
    program += bytes([0]) + _uleb(9) + bytes([2]) + (0x401000).to_bytes(8, "little")
    program += bytes([1])                                 # copy -> line 1
    program += bytes([2]) + _uleb(4)                      # advance_pc 4
    program += bytes([3]) + _sleb(1)                      # advance_line +1
    program += bytes([1])                                 # copy -> line 2
    program += bytes([0]) + _uleb(1) + bytes([1])         # end_sequence
    body = bytearray()
    body += (4).to_bytes(2, "little")                     # version 4
    body += len(prologue).to_bytes(4, "little")           # header_length
    body += prologue + program
    return len(body).to_bytes(4, "little") + bytes(body)


@check("DWARF 2-4 file table is parsed (masu.so ships one)")
def _dwarf_v4_rows():
    data = _dwarf_v4_unit()
    stub = _LineStub(data)
    rows = N._dwarf_line_rows(stub, type("Sec", (), {"off": 0, "size": len(data)})())
    eq(rows, [(0x401000, os.path.join("src", "demo.py"), 1),
              (0x401004, os.path.join("src", "demo.py"), 2)], "v4 rows")


@check("DWARF 5 line tables still parse (demo_lines.so)")
def _dwarf_v5_rows():
    _path, img = fixture("demo_lines.so")
    section = img.section(".debug_line")
    ok(section is not None, "no .debug_line")
    rows = N._dwarf_line_rows(img, section)
    ok(len(rows) > 1000, f"only {len(rows)} rows")
    ok(any(name.endswith((".py", ".pyx")) for _a, name, _l in rows),
       "no .py rows in demo_lines.so")


@check("hex-carved payload is recovered from a compiled image")
def _carve_hex():
    _path, img = fixture("packed_hex.so")
    entries = N.carve_payloads(img)
    eq(len(entries), 1, f"entries: {[e['label'] for e in entries]}")
    eq(entries[0]["encoding"], "hex")
    with open(os.path.join(FIXTURES, "payload_src.py"), "rb") as handle:
        eq(entries[0]["blob"].strip(), handle.read().strip(), "carved hex source")


@check("base64-carved payload is recovered too")
def _carve_b64():
    _path, img = fixture("packed_b64.so")
    entries = N.carve_payloads(img)
    eq(len(entries), 1, f"entries: {[e['label'] for e in entries]}")
    eq(entries[0]["encoding"], "base64")
    with open(os.path.join(FIXTURES, "payload_src.py"), "rb") as handle:
        eq(entries[0]["blob"].strip(), handle.read().strip(), "carved base64 source")


@check("a carved payload is written out, compiles and passes the audit")
def _carved_output():
    import tempfile
    _path, img = fixture("packed_hex.so")
    folder = tempfile.mkdtemp()
    paths, rows, _notes = N.recover_payloads(img, "packed_hex", folder)
    eq(len(paths), 1, f"paths: {paths}")
    text = open(paths[0], encoding="utf-8").read()
    ok("class Headers" in text or "def " in text, text[:200])
    audit = P.audit_source(text)
    ok(audit["compiles"], audit["error"])
    eq(rows[0]["audit"]["compiles"], True, "row audit")
    eq(audit["missing"], [], f"unbound: {audit['missing']}")


@check("unresolved operands stay callable instead of becoming None(...)")
def _sentinel():
    sentinel = P._PydecompUnknown("coki")
    chained = sentinel("value")["k"].attr
    ok(isinstance(chained, P._PydecompUnknown), type(chained))
    eq(str(chained), "<unknown>")
    eq(len(list(sentinel)), 0)
    ok(not sentinel, "sentinel must be falsy")
    text = "x = _PydecompUnknown()\nprint(x(1)['k'])\n"
    once = P.with_unknown_preamble(text)
    eq(once.count("class _PydecompUnknown"), 1, "preamble added once")
    eq(P.with_unknown_preamble(once), once, "preamble is idempotent")
    ok(P.audit_source(once)["compiles"], "preamble must compile")


@check("audit_source flags syntax errors and unbound globals")
def _audit():
    clean = P.audit_source("import os\nvalue = os.sep\n")
    ok(clean["compiles"], clean["error"])
    eq(clean["missing"], [])
    broken = P.audit_source("def broken(:\n")
    ok(not broken["compiles"], "syntax error must be reported")
    ok("line 1" in broken["error"], broken["error"])
    loose = P.audit_source("value = not_defined_anywhere\n")
    eq(loose["missing"], ["not_defined_anywhere"])


@check("[*('A', 'B')] keeps its items (random.choice must not get [])")
def _list_extend_tuple():
    import py_compile
    import tempfile
    source = ("import random\n"
              "def pick():\n"
              "    return random.choice([*('A', 'B', 'C')])\n")
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "starred.py")
    open(path, "w").write(source)
    with open(py_compile.compile(path, cfile=path + "c", doraise=True), "rb") as handle:
        version, module = P.parse_pyc(handle.read())
    text = P.lift_module(module, version)
    ok("random.choice" in text, text)
    for item in ("'A'", "'B'", "'C'"):
        ok(item in text, f"{item} lost from the starred literal:\n{text}")
    ok("choice([])" not in text.replace(" ", ""), "empty choice list")


if __name__ == "__main__":
    print()
    if SKIPPED:
        print(f"{len(SKIPPED)} skipped (fixtures absent)")
    if FAILED:
        print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
        raise SystemExit(1)
    print("all good")
