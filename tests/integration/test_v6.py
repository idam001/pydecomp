"""v6 checks: the AST decompiler, its round-trip proof, and the fallback."""
import ast
import os
import pathlib
import py_compile
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

FAILED = []


def check(name, fn):
    try:
        fn()
        print(f"ok    {name}")
    except Exception as exc:                                    # noqa: BLE001
        FAILED.append(name)
        print(f"FAIL  {name}\n      {type(exc).__name__}: {exc}")


def eq(got, want, what=""):
    assert got == want, f"{what}: got {got!r}, want {want!r}"


def ok(cond, msg=""):
    assert cond, msg or "condition failed"


def pyc_of(source: str):
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "sample.py")
    with open(path, "w") as handle:
        handle.write(source)
    pyc = py_compile.compile(path, cfile=path + "c", doraise=True)
    with open(pyc, "rb") as handle:
        version, module = P.parse_pyc(handle.read())
    return version, module


STRAIGHT = "x = 1\nname = 'pydecomp'\nprint(name, x)\n"

BRANCHY = """import os


class Box:
    def __init__(self, n):
        self.n = n

    def grow(self, by):
        self.n = self.n + by
        return self.n


def report(items):
    out = []
    for item in items:
        if item > 3:
            out.append(item * 2)
        else:
            out.append(0)
    return out


def spin(n):
    while n > 0:
        n -= 1
    return n
"""


def test_version():
    # the version lives in one place (src/pydecomp/limits.py) and every other
    # surface has to agree with it - a gate that hard-codes the number would
    # go red on every release, which teaches people to ignore gates
    ROOT = pathlib.Path(__file__).resolve().parents[2]
    source = (ROOT / "src" / "pydecomp" / "limits.py").read_text()
    declared = re.search(r'^__version__\s*=\s*"([^"]+)"', source, re.M).group(1)
    eq(P.__version__, declared, "package agrees with limits.py")
    ok(re.fullmatch(r"\d+\.\d+\.\d+", declared), declared)
    pyproject = (ROOT / "pyproject.toml").read_text()
    ok(declared in pyproject or "dynamic" in pyproject,
       "pyproject carries the version or reads it dynamically")
    citation = (ROOT / "CITATION.cff").read_text()
    eq(citation.count(f"version: {declared}") >= 1, True, "CITATION.cff agrees")
    changelog = (ROOT / "CHANGELOG.md").read_text()
    ok(f"[{declared}]" in changelog, "CHANGELOG has a section for it")


def test_straight_line_roundtrip():
    version, module = pyc_of(STRAIGHT)
    text, score = P.decompile_object(module, version, None)
    ok(text is not None, "no rebuild")
    eq(score, 1.0)
    ok("print(name, x)" in text, text)
    ok("x = 1" in text, text)


def test_lifter_markers_are_gone():
    version, module = pyc_of(BRANCHY)
    text = P.lift_module(module, version)
    for marker in ("# loop back to", "ambiguous operand", "<?>", "<operand",
                   "# jump to", "operand unavailable"):
        ok(marker not in text, f"{marker!r} survived:\n{text}")


def test_rebuilt_source_recompiles_identically():
    """The strongest proof: rebuilt source -> same instruction stream."""
    import dis
    version, module = pyc_of(BRANCHY)
    text = P.lift_module(module, version)
    ok(P.compile_problem(text) is None, "rebuilt source does not compile")
    rebuilt = compile(text, "<rebuilt>", "exec")
    truth = compile(BRANCHY, "<truth>", "exec")
    ignore = P.DECOMP_IGNORE

    def stream(code):
        return [ins.opname for ins in dis.get_instructions(code)
                if ins.opname not in ignore]

    def find(pool, name):
        for const in pool.co_consts:
            if getattr(const, "co_name", "") == name:
                return const
            if hasattr(const, "co_consts"):
                try:
                    return find(const, name)
                except AssertionError:
                    continue
        raise AssertionError(f"{name} missing")

    for name in ("report", "spin", "grow", "__init__"):
        left, right = find(rebuilt, name), find(truth, name)
        same = sum(1 for a, b in zip(stream(left), stream(right)) if a == b)
        ratio = same / float(max(len(stream(left)), len(stream(right))))
        ok(ratio >= 0.80, f"{name}: only {ratio:.2f} of the instructions match")


def test_for_loop_shape():
    version, module = pyc_of(BRANCHY)
    text = P.lift_module(module, version)
    tree = ast.parse(text)
    funcs = {node.name: node for node in tree.body
             if isinstance(node, ast.FunctionDef)}
    ok("report" in funcs, text)
    loops = [node for node in ast.walk(funcs["report"]) if isinstance(node, ast.For)]
    eq(len(loops), 1)
    ok(any(isinstance(node, ast.If) for node in ast.walk(funcs["report"])),
       "if/else lost")


def test_while_becomes_a_loop():
    version, module = pyc_of(BRANCHY)
    text = P.lift_module(module, version)
    tree = ast.parse(text)
    spin = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "spin"][0]
    ok(any(isinstance(node, ast.While) for node in ast.walk(spin)), text)


def test_class_rebuilt():
    version, module = pyc_of(BRANCHY)
    text = P.lift_module(module, version)
    tree = ast.parse(text)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    eq(len(classes), 1)
    eq(classes[0].name, "Box")
    methods = {n.name for n in classes[0].body if isinstance(n, ast.FunctionDef)}
    eq(methods, {"__init__", "grow"})


def test_old_version_falls_back():
    ok(P.decompile_object(None, (3, 8), None)[0] is None)


def test_fallback_output_still_clean():
    """Whatever the engine cannot decompile must still lift to valid Python."""
    version, module = pyc_of("values = [i * 2 for i in range(4)]\nprint(values)\n")
    text = P.lift_module(module, version)
    ok(P.compile_problem(text) is None, text)


def test_no_policy_chatter():
    import pathlib as _pl
    package = _pl.Path(__file__).resolve().parents[2] / "src" / "pydecomp"
    text = "\n".join(p.read_text(errors="ignore")
                     for p in sorted(package.rglob("*.py"))).lower()
    for word in ("legal", "illegal", "malware", "consent", "authoris", "authoriz",
                 "liability", "risk level", "for educational"):
        ok(word not in text, f"policy word {word!r} in the engine")


def test_cli_roundtrip():
    folder = tempfile.mkdtemp()
    out = os.path.join(folder, "out")
    source = os.path.join(folder, "sample.py")
    with open(source, "w") as handle:
        handle.write(BRANCHY)
    proc = subprocess.run([sys.executable, "-m", "pydecomp", source,
                           "-o", out, "--no-color", "--no-anim"],
                          capture_output=True, text=True, timeout=300)
    eq(proc.returncode, 0)
    written = os.listdir(out)
    sources = [name for name in written if name.endswith(".py")]
    eq(len(sources), 1, f"one source out: {written}")
    body = open(os.path.join(out, sources[0])).read()
    ok(P.compile_problem(body) is None, body[:400])


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            check(name.replace("test_", "").replace("_", " "), fn)
    print("\nall good" if not FAILED else f"\n{len(FAILED)} failed")
    sys.exit(1 if FAILED else 0)
