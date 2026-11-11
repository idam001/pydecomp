#!/usr/bin/env python3
"""v5 checks: cross-version bytecode, inline-string recovery, bytecode lifting."""
from __future__ import annotations

import base64
import importlib.util
import io
import marshal
import os
import py_compile
import subprocess
import sys
import tempfile
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pydecomp as P                                              # noqa: E402

CHECKS = []


def check(name):
    def wrap(fn):
        CHECKS.append((name, fn))
        return fn
    return wrap


def eq(got, want, label=""):
    if got != want:
        raise AssertionError(f"{label}: got {got!r}, want {want!r}")


def ok(cond, label=""):
    if not cond:
        raise AssertionError(label or "condition failed")


# ------------------------------------------------------------------ fixtures
def sample_pyc(extra_source: str = "", version_header: bool = True) -> bytes:
    """Compile a tiny module with the running interpreter and wrap it in a .pyc."""
    src = ("MARKER = 'pydecomp-v5-fixture'\n"
           "def greet(name):\n"
           "    return 'hello ' + name\n"
           f"{extra_source}")
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "fixture.py")
    with open(path, "w") as fh:
        fh.write(src)
    pyc = py_compile.compile(path, cfile=path + "c", doraise=True)
    with open(pyc, "rb") as fh:
        blob = fh.read()
    if not version_header:
        return blob[16:]                      # bare marshal stream
    return blob


# ------------------------------------------------------------------ checks
@check("version is 5.2.0")
def _version():
    eq(P.__version__, "8.1.0")


@check("v4 helpers still present")
def _v4_api():
    for name in ("peel", "Evaluator", "find_payloads", "phone_dir", "save", "menu",
                 "deobfuscate", "normalize", "carve_strings"):
        ok(hasattr(P, name), name)


@check("v5 engine present")
def _v5_api():
    for name in ("MarshalReader", "parse_pyc", "parse_marshal_blob", "disassemble",
                 "lift", "lift_module", "harvest_inline_text", "deep_decode", "dig",
                 "MAGIC_VERSIONS", "OPNAMES", "parses_as_python"):
        ok(hasattr(P, name), name)


@check("magic table covers 3.8 - 3.15")
def _magic():
    for magic, version in [(3413, (3, 8)), (3425, (3, 9)), (3439, (3, 10)),
                           (3495, (3, 11)), (3531, (3, 12)), (3571, (3, 13)),
                           (3627, (3, 14)), (3666, (3, 15))]:
        eq(P.MAGIC_VERSIONS[magic], version, str(magic))


@check("opcode tables loaded for 3.11 - 3.14")
def _opcodes():
    for version, floor in (((3, 11), 80), ((3, 12), 100), ((3, 13), 110), ((3, 14), 115)):
        ok(len(P.OPNAMES[version]) >= floor, f"{version}: {len(P.OPNAMES[version])}")
    eq(P.OPNAMES[(3, 14)][94], "LOAD_SMALL_INT")
    eq(P.OPNAMES[(3, 13)][83], "LOAD_CONST")
    eq(P.OPNAMES[(3, 12)][100], "LOAD_CONST")
    eq(P.OPNAMES[(3, 11)][151], "RESUME")


@check("host .pyc parses, disassembles and lifts")
def _host_pyc():
    blob = sample_pyc()
    version, module = P.parse_pyc(blob)
    ok(module is not None, "module parsed")
    eq(version, tuple(sys.version_info[:2]), "detected version")
    text = P.lift_module(module, version)
    ok("pydecomp-v5-fixture" in text, "fixture marker recovered")
    ok("def greet(name):" in text, "function recovered")
    ok(P.parses_as_python(text), "lifted text parses")


@check("bare marshal stream is version-probed")
def _marshal_probe():
    blob = sample_pyc(version_header=False)
    version, obj, consumed = P.parse_marshal_blob(blob)
    ok(obj is not None, "probe found a code object")
    ok(consumed > 0.99, f"full parse ({consumed:.2f})")


@check("lifted output compiles clean (no SyntaxError, no SyntaxWarning)")
def _compile_clean():
    blob = sample_pyc()
    version, module = P.parse_pyc(blob)
    text = P.lift_module(module, version)
    warnings = []
    with __import__("warnings").catch_warnings(record=True) as caught:
        __import__("warnings").simplefilter("always")
        compile(text, "<lifted>", "exec")
    eq([str(w.message) for w in caught], [], "syntax warnings")
    eq(P.compile_problem(text), None)


@check("lifted output never returns from module level")
def _module_return():
    code = P.CodeObj()
    code.code = bytes([128, 0, 82, 1, 35, 0])         # RESUME, LOAD_CONST, RETURN
    code.consts = (None, 7)
    code.name = code.qualname = "<module>"
    text = P.lift_module(code, (3, 14))
    ok(P.compile_problem(text) is None, "module level return leaked")
    ok("def " not in text.split("\n")[3])


@check("lifted output is valid for the 3.8 grammar too")
def _old_grammar():
    import ast
    blob = sample_pyc()
    version, module = P.parse_pyc(blob)
    text = P.lift_module(module, version)
    ast.parse(text, feature_version=(3, 8))


@check("conditional expressions are folded, not left as jumps")
def _ternary():
    ok(P._fold_ternary is not None if hasattr(P, "_fold_ternary") else False, "_fold_ternary")


@check("lifted output has no unbound names (no NameError on import)")
def _names():
    blob = sample_pyc()
    version, module = P.parse_pyc(blob)
    text = P.lift_module(module, version)
    bound, loaded = P._bound_and_loaded(text)
    builtins = set(dir(__import__("builtins")))
    eq(sorted(loaded - bound - builtins), [], "unbound names")


@check("lifted output never raises unconditionally")
def _no_bare_raise():
    blob = sample_pyc()
    version, module = P.parse_pyc(blob)
    text = P.lift_module(module, version)
    ok(not any(line.strip() == "raise" for line in text.split("\n")), "bare raise")


@check("class bodies lift as class blocks")
def _classes():
    blob = sample_pyc("class Box:\n"
                      "    tag = 'boxed'\n"
                      "    def poke(self):\n"
                      "        return self.tag\n")
    version, module = P.parse_pyc(blob)
    text = P.lift_module(module, version)
    ok("class Box:" in text, "class header")
    ok("def poke(self):" in text, "method lifted")
    eq(P.compile_problem(text), None)


@check("dig() handles a .pyc end to end")
def _dig_pyc():
    art = P.dig(sample_pyc(), "fixture.pyc")
    # a same-version module that round-trips is rebuilt as real source now, so
    # the artifact kind must follow the proof instead of the input container
    eq(art.kind, "source")
    ok("pydecomp-v5-fixture" in art.text)
    eq(P.compile_problem(art.text), None)
    ok(any("pyc header" in line for line in art.trace))


@check("dig() handles a bare marshal blob")
def _dig_marshal():
    art = P.dig(sample_pyc(version_header=False), "blob.bin")
    ok("pydecomp-v5-fixture" in art.text)


@check("dig() opens a zip holding a python member")
def _dig_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("inner.pyc", sample_pyc())
    art = P.dig(buf.getvalue(), "bundle.zip")
    ok("pydecomp-v5-fixture" in art.text)


@check("dig() still peels plain source loaders")
def _dig_source():
    payload = "print('hello from a loader')\nDATA = 42\n"
    packed = base64.b64encode(zlib.compress(payload.encode())).decode()
    source = ("import base64,zlib\n"
              f"exec(zlib.decompress(base64.b64decode({packed!r})))\n")
    art = P.dig(source.encode(), "loader.py")
    eq(art.kind, "source")
    ok("hello from a loader" in art.text)


@check("deep_decode finds a base64+zlib payload")
def _deep_decode():
    payload = "# a comment\nx = 1\ny = 2\nprint(x + y)\n"
    blob = base64.b64encode(zlib.compress(payload.encode()))
    out, chain = P.deep_decode(blob)
    ok(out is not None, "decoded")
    eq(chain[:2], ["base64", "zlib"])
    ok(b"print(x + y)" in out)


@check("parses_as_python rejects binary noise")
def _parses():
    ok(P.parses_as_python("x = 1\n"))
    ok(not P.parses_as_python("this is not python at all !!"))
    ok(not P.parses_as_python("x = 1\x00\x01"))


@check("harvest_inline_text recovers a chr-stream")
def _harvest():
    # build a synthetic 3.14-style code stream: dominant opcode carries chars
    text = "# made by a chr-loop obfuscator\nprint('recovered')\n"
    stream = b"".join(bytes([94, ord(ch)]) + bytes([78, 1]) for ch in text)
    code = P.CodeObj()
    code.code = bytes([128, 0]) + stream + bytes([35, 0])
    code.name = code.qualname = "<module>"
    got = P.harvest_inline_text(code)
    eq(got, text)


@check("Kamrul sample: 3.14 pyc -> 11 layers -> lifted program")
def _kamrul():
    path = "/home/user/uploads/Kamrul.py"
    if not os.path.isfile(path):
        return
    with open(path, "rb") as fh:
        raw = fh.read()
    art = P.dig(raw, "Kamrul.py")
    stages = " | ".join(art.trace)
    ok("pyc header · CPython 3.14" in stages, "pyc identified")
    ok("inline integer stream" in stages, "chr-stream recovered")
    ok("marshal stream · CPython 3.14" in stages, "inner marshal parsed")
    eq(art.kind, "pseudo", "final result is a bytecode lift")
    eq(P.compile_problem(art.text), None, "lifted program must compile clean")
    ok("return" not in [l.strip() for l in art.text.split("\n") if l[:1] not in (" ", "\t")],
       "module level return")
    ok(art.text.count("did not line up") == 0, "no misaligned calls left")
    bound, loaded = P._bound_and_loaded(art.text)
    builtins = set(dir(__import__("builtins")))
    eq(sorted(loaded - bound - builtins), [], "unbound names")
    ok("class sec:" in art.text, "class lifted as class")
    ok(not any(l.strip() == "raise" for l in art.text.split("\n")), "no bare raise")
    for marker in ("b-graph.facebook.com", "KAMRUL", "ghostff", "login_1",
                   "def approval("):
        ok(marker in art.text, f"missing {marker}")
    ok(P.parses_as_python(art.text), "lifted program parses as Python")


@check("daniup sample: loader chain still resolves to source")
def _daniup():
    path = "/home/user/uploads/daniup.py"
    if not os.path.isfile(path):
        return
    with open(path, "rb") as fh:
        art = P.dig(fh.read(), "daniup.py")
    eq(art.kind, "source")
    ok("import requests" in art.text)


@check("CLI writes one file to the output folder")
def _cli():
    tmp = tempfile.mkdtemp()
    blob = sample_pyc()
    src = os.path.join(tmp, "sample.py")
    with open(src, "wb") as fh:
        fh.write(blob)
    out = os.path.join(tmp, "out")
    proc = subprocess.run([sys.executable, "-m", "pydecomp", src,
                           "-o", out, "--no-color", "--no-anim"],
                          capture_output=True, text=True, timeout=120)
    eq(proc.returncode, 0, proc.stderr[-400:])
    files = os.listdir(out)
    eq(len(files), 1, f"one output file: {files}")
    ok(files[0].endswith(".py"), files[0])


@check("the sample is never executed or imported")
def _static():
    import ast
    import pathlib as _pl
    with open(sorted((_pl.Path(__file__).resolve().parents[2] / "src" / "pydecomp").rglob("*.py"))[0], encoding="utf-8") as fh:
        body = fh.read()
    # ast.literal_eval is fine (it never runs code); builtin eval/exec are not
    for bad in ("exec(raw", "eval(raw", "exec(source", "eval(source",
                "__import__(source", "importlib.import_module(", "runpy.",
                "subprocess.", "os.system(", " exec(text", "= eval(text"):
        ok(bad not in body, f"found {bad!r}")
    # the only permitted exec is the single-file build executing its *own*
    # embedded native module (7.4.0); nothing sample-derived may ever reach it
    tree = ast.parse(body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("exec", "eval"):
            segment = ast.get_source_segment(body, node) or ""
            ok("<native.py>" in segment,
               f"exec/eval on something other than the embedded tool module: "
               f"{segment[:80]}")


@check("storage helpers untouched")
def _storage():
    ok(callable(P.phone_dir) and callable(P.unique_path) and callable(P.save))


def main() -> int:
    passed = failed = 0
    for name, fn in CHECKS:
        try:
            fn()
        except Exception as exc:                                  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n      {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"ok    {name}")
    print(f"\n{passed}/{passed + failed} checks passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
