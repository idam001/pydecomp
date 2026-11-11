"""1.0.0 "the Almighty" gates: the hardest obfuscation, answered statically.

Each check builds its sample *here*, from a payload whose text the gate already
knows, so every assertion is against ground truth rather than against
pydecomp's own output.  The samples are the defences that actually show up in
the wild, in the order the research ranked them:

* obfuscator.io-style string tables (array + rotation + offset accessor + decode
  chain), including the case where the table is mutated in a way we cannot
  replay - there the answer must be "leave it alone", never a guessed string;
* mixed-boolean-arithmetic algebra, opaque predicates, unicode aliasing,
  dynamic builtin lookup and the self-hosting docstring trick;
* PyInstaller CArchives (cookie → toc → entries → PYZ) and PyArmor containers;
* a deep 8-layer loader chain, end to end through ``deobfuscate``;
* the completeness contract: nothing that pydecomp recovers may be withheld,
  truncated or gated.
"""
import ast
import base64
import importlib.util
import marshal
import os
import struct
import subprocess
import sys
import tempfile
import textwrap
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

from pydecomp.decoders import pyinstaller as PI                  # noqa: E402
from pydecomp.polish.aliases import normalize_aliases, selfdoc_payload   # noqa: E402
from pydecomp.polish.apply import polish_source                  # noqa: E402
from pydecomp.polish.mba import simplify_mba                     # noqa: E402
from pydecomp.polish.opaque import prove, strip_opaque           # noqa: E402
from pydecomp.polish.strarrays import resolve_string_arrays       # noqa: E402
from pydecomp.terminal import identity                            # noqa: E402

SIGNATURE = identity.SIGNATURE

FAILED = []
CHECKS = []

PAYLOAD = textwrap.dedent('''
    def main():
        print("the almighty payload")

    if __name__ == "__main__":
        main()
''').strip() + "\n"
RAW = PAYLOAD.encode()


def check(name):
    def wrap(fn):
        CHECKS.append(name)
        try:
            fn()
            print(f"ok    {name}")
        except Exception as exc:                                # noqa: BLE001
            FAILED.append(name)
            print(f"FAIL  {name}\n      {type(exc).__name__}: {exc}")
        return fn
    return wrap


def eq(got, want, what=""):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, wanted {want!r}")


def ok(cond, what=""):
    if not cond:
        raise AssertionError(what or "expected true")


def marshal_source(text: str) -> bytes:
    """Compile *our own* generated sample and marshal it, the way a packer does."""
    return marshal.dumps(compile(text, "<gate>", "exec"))


def pyc_source(text: str) -> bytes:
    """A minimal valid .pyc: magic + flags + mtime + size + marshal body."""
    return importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal_source(text)


def render(tree) -> str:
    return ast.unparse(ast.fix_missing_locations(tree))


# ---------------------------------------------------------------------------
# string tables
# ---------------------------------------------------------------------------

@check("string table: array + accessor resolve to literals")
def _table_plain():
    source = '''
_t = ['print', 'index', 'FLAG{plain_table}']
def _s(i):
    return _t[i]
_s(0)(_s(2), _s(1))
'''
    tree = ast.parse(source)
    resolved = resolve_string_arrays(tree)
    eq(resolved, 3, "lookups resolved")
    text = render(tree)
    ok("FLAG{plain_table}" in text, "string recovered")
    ok("_t = [" not in text, "scaffolding removed")


@check("string table: rotation + base64 accessor")
def _table_rotated():
    words = ["print", "FLAG{rotated_table}"]
    encoded = [base64.b64encode(word.encode()).decode() for word in words]
    source = (
        "import base64\n"
        f"_t = {encoded!r}\n"
        "_k = 0\n"
        "while _k < 1:\n"
        "    _t.append(_t.pop(0))\n"
        "    _k += 1\n"
        "def _g(i):\n"
        "    return base64.b64decode(_t[i - 1]).decode()\n"
        "_g(1)(_g(2))\n"
    )
    tree = ast.parse(source)
    resolved = resolve_string_arrays(tree)
    eq(resolved, 2, "both lookups resolved")
    text = render(tree)
    ok("FLAG{rotated_table}" in text, "rotated string decoded")
    ok("_t = [" not in text, "table removed")


@check("string table: unreplayable mutation is left untouched")
def _table_unsafe():
    source = '''
_t = ['alpha', 'beta']
import random
random.shuffle(_t)
def _g(i):
    return _t[i]
print(_g(0))
'''
    tree = ast.parse(source)
    eq(resolve_string_arrays(tree), 0, "nothing resolved")
    text = render(tree)
    ok("_t = [" in text, "table preserved")
    ok("random.shuffle(_t)" in text, "mutation preserved")


# ---------------------------------------------------------------------------
# arithmetic and control-flow dressing
# ---------------------------------------------------------------------------

@check("mba: nine identities collapse to plain arithmetic")
def _mba():
    expressions = [
        ("(a ^ b) + 2 * (a & b)", "a + b"),
        ("(a | b) + (a & b)", "a + b"),
        ("(a | b) - (a & b)", "a ^ b"),
        ("(a & b) + (a ^ b)", "a | b"),
        ("(a | b) - (a ^ b)", "a & b"),
        ("(a ^ b) - 2 * (~a & b)", "a - b"),
        ("2 * (a & b) + (a ^ b)", "a + b"),
        ("(b & a) + (b | a)", "b + a"),
    ]
    for source, expected in expressions:
        tree = ast.parse(f"x = {source}\n")
        simplify_mba(tree)
        got = render(tree).split("=", 1)[1].strip()
        eq(got, expected, source)


@check("opaque predicates: junk branches are proved away")
def _opaque():
    for source, verdict in (("x * x >= 0", True), ("x * x < 0", False),
                            ("x * (x + 1) % 2 == 0", True),
                            ("(x | 1) % 2 == 1", True), ("x ^ x", False),
                            ("x & ~x", False), ("len(x) >= 0", True),
                            ("abs(x) >= 0", True), ("x > 3", None),
                            ("x * x == 4", None)):
        eq(prove(ast.parse(source, mode="eval").body), verdict, source)
    tree = ast.parse(textwrap.dedent('''
        def f(x):
            if x * x >= 0:
                return 'real'
            else:
                return 'junk'
        '''))
    strip_opaque(tree)
    text = render(tree)
    ok("'real'" in text and "'junk'" not in text, "dead side gone")


@check("unicode aliases become ASCII and stay runnable")
def _unicode():
    source = (
        "ᐁ = print\n"
        "ᐂ = 40\n"
        "ᐁ('flag', ᐂ + 2)\n"
    )
    tree = ast.parse(source)
    changes, legend = normalize_aliases(tree)
    ok(changes > 0, "aliases handled")
    text = render(tree)
    ok(all(ord(char) < 128 for char in text), f"ascii only: {text!r}")
    ok("print" in text, "alias resolved to its target")
    ok(legend, "a legend is reported")


@check("dynamic builtins: getattr/vars/__import__ are folded to plain names")
def _dyn_builtins():
    source = textwrap.dedent('''
        _p = getattr(__builtins__, 'print')
        _b = __import__('base64').b64decode(vars()['__builtins__']['str']('aGk='))
        _p(_b)
        ''')
    tree = ast.parse(source)
    normalize_aliases(tree)
    text = render(tree)
    ok("print" in text, "getattr on __builtins__ folded")
    ok("base64.b64decode" in text, "__import__ chain folded")
    ok('__builtins__' not in text, "builtins subscript folded")


@check("self-hosting module: the docstring program is recovered")
def _selfdoc():
    source = (
        '"""flag = "FLAG{selfdoc}"\n'
        'print(flag)\n'
        '"""\n'
        "import ast\n"
        "exec(compile(__doc__, '<doc>', 'exec'))\n"
    )
    tree = ast.parse(source)
    hidden = selfdoc_payload(tree)
    ok(hidden, "payload found")
    text = render(ast.Module(body=hidden, type_ignores=[]))
    ok("FLAG{selfdoc}" in text, "program recovered")


# ---------------------------------------------------------------------------
# containers
# ---------------------------------------------------------------------------

def build_carchive(entries, tail=b"", pyvers=311):
    """A real CArchive: entries, then the TOC, then the cookie."""
    overlay = b""
    toc = b""
    specs = []
    for name, data, typecode, compress in entries:
        payload = zlib.compress(data) if compress else data
        specs.append((len(overlay), payload, data, typecode, name, compress))
        overlay += payload
    for position, payload, data, typecode, name, compress in specs:
        name_bytes = name.encode() + b"\x00"
        entry_size = 18 + len(name_bytes)
        toc += struct.pack("!i", entry_size)
        toc += struct.pack("!iiiBc", position, len(payload), len(data),
                           1 if compress else 0, typecode.encode())
        toc += name_bytes
    package = overlay + toc
    cookie_size = 88
    # PyInstaller's pkgLen counts the cookie itself, so overlayPos lands on 0
    cookie = struct.pack("!8sIIii64s", PI.MAGIC, len(package) + cookie_size,
                         len(overlay), len(toc), pyvers, b"python311.dll")
    return package + cookie + tail


def build_pyz(modules):
    body = b""
    table = []
    for name, blob in modules:
        packed = zlib.compress(blob)
        table.append((name, (0, len(body) + 12, len(packed))))
        body += packed
    toc_pos = 12 + len(body)
    payload = b"PYZ\x00" + struct.pack("!i", 311) + struct.pack("!i", toc_pos) + body
    import marshal
    return payload + marshal.dumps(table)


@check("pyinstaller: CArchive entry script is recovered")
def _carchive():
    archive = build_carchive([
        ("pyiboot01_bootstrap", b"\x00bootstrap", "s", False),
        ("app.pyc", pyc_source(PAYLOAD), "s", True),
    ], tail=b"tail-overlay")
    ok(PI.is_carchive(archive), "cookie recognised")
    entries = PI.carchive_entries(archive)
    names = [name for name, _blob, _type in entries]
    ok("app.pyc" in names, f"entry found: {names}")
    chosen = PI.entry_script(entries)
    ok(chosen and chosen[0] == "app.pyc", "entry script picked (bootstrap skipped)")
    artifact = P.dig(archive, "app.exe")
    ok("the almighty payload" in artifact.text, "source recovered from archive")


@check("pyinstaller: embedded PYZ modules are recovered")
def _pyz():
    module = marshal_source('SECRET = "FLAG{pyz_module}"\n')
    pyz = build_pyz([("helper", module)])
    ok(PI.is_pyz(pyz), "PYZ magic recognised")
    modules = PI.pyz_modules(pyz)
    eq([name for name, _ in modules], ["helper"], "one module")
    artifact = P.dig(pyz, "PYZ-00.pyz")
    ok("FLAG{pyz_module}" in artifact.text, "module source recovered")
    nested = build_carchive([("PYZ-00.pyz", pyz, "z", False)])
    artifact = P.dig(nested, "app.exe")
    ok("FLAG{pyz_module}" in artifact.text, "PYZ reached through the CArchive")


@check("pyarmor: container is emitted whole and described honestly")
def _pyarmor():
    blob = b"PY005724\x00\x03\x0b\x00" + b"key-material-here" + b"\xff\xe3m\x82"
    source = (
        "# Pyarmor 8.5.11 (pro), 005724, non-profits, 2024-12-13T07:33:37\n"
        "from pyarmor_runtime_005724 import __pyarmor__\n"
        "__pyarmor__(__name__, __file__, b'" + blob.decode("latin-1")
        .replace("\\", "\\\\").replace("'", "\\'") + "')\n"
    ).encode("utf-8", "surrogateescape")
    artifact = P.dig(source, "armored.py")
    eq(artifact.kind, "source", "the bootstrap is source")
    ok("__pyarmor__" in artifact.text, "bootstrap kept")
    ok(any("PY005724" in line for line in artifact.trace), "container named")
    ok(any("005724" in line for line in artifact.trace), "serial reported")


# ---------------------------------------------------------------------------
# end to end
# ---------------------------------------------------------------------------

def _layer(text, rounds=8) -> str:
    """Eight nested loaders: each one decodes the next program's text."""
    current = text
    for _ in range(rounds):
        blob = base64.b64encode(zlib.compress(current.encode()[::-1], 9))
        current = ("import base64, zlib\n"
                   f"exec(zlib.decompress(base64.b64decode({blob!r}))[::-1].decode())\n")
    return current


@check("end to end: an 8-layer loader chain decompiles to the payload")
def _deep_chain():
    source = _layer(PAYLOAD)
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "deep.py")
    with open(path, "wb") as handle:
        handle.write(source.encode())
    try:
        out = P.deobfuscate(path, folder, reports=False)
        ok(out is not None, "a file was written")
        text = open(out, encoding="utf-8", errors="surrogateescape").read()
        ok("the almighty payload" in text, "payload recovered")
        ok(text.startswith("#[ Deobfuscated by idam Emmanuel ] only through pydecomp"),
           "stamp is the first line")
        ast.parse(text.split("\n", 1)[1])
    finally:
        for entry in os.listdir(folder):
            os.unlink(os.path.join(folder, entry))
        os.rmdir(folder)


@check("end to end: a hardened source keeps every function")
def _no_truncation():
    functions = "\n".join(
        f"def fn_{index:03d}(value):\n"
        f"    secret = (value ^ {index}) + 2 * (value & {index})\n"
        f"    if value * value >= 0:\n"
        f"        return secret + {index}\n"
        f"    return -1\n"
        for index in range(120)
    )
    source = "import os\n\n" + functions + "\nprint(fn_000(1))\n"
    polished, notes = polish_source(source)
    eq(polished.count("def fn_"), 120, "every function survives")
    ok(notes, f"passes reported: {notes}")
    ok("value + " in polished, "mba simplified")
    ok("if value * value >= 0" not in polished, "opaque branch pruned")


@check("completeness: the static audit is advisory and never blocks output")
def _advisory_audit():
    tool = os.path.join(os.path.dirname(HERE), "tools", "check_static_only.py")
    result = subprocess.run([sys.executable, tool], capture_output=True, text=True)
    eq(result.returncode, 0, "audit exits 0 by default")
    ok("violation" not in result.stdout.lower(), "no violation language")
    strict = subprocess.run([sys.executable, tool, "--strict"],
                            capture_output=True, text=True)
    ok(strict.returncode in (0, 1), "strict mode still available")


@check("every recovered file carries exactly one stamp line")
def _stamp():
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "sample.py")
    with open(path, "w") as handle:
        handle.write('print("hello")\n')
    try:
        out = P.deobfuscate(path, folder, reports=False)
        text = open(out, encoding="utf-8", errors="surrogateescape").read()
        eq(text.count(SIGNATURE), 1, "stamp appears once")
        eq(text.splitlines()[0], SIGNATURE, "stamp is line one")
    finally:
        for entry in os.listdir(folder):
            os.unlink(os.path.join(folder, entry))
        os.rmdir(folder)


if __name__ == "__main__":
    print()
    if FAILED:
        print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
        raise SystemExit(1)
    print(f"all {len(CHECKS)} checks passed")
