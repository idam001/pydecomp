"""v7 checks: the CPython 3.14 sample that broke version detection.

`uploads/Old.py` is a single ``exec(marshal.loads(...))`` whose payload was
compiled by 3.14.  Everything here is about that sample: picking the right
interpreter, rebuilding the whole module, and keeping the shapes a 3.14-only
module uses (``LOAD_SPECIAL`` with-blocks, f-strings, the implicit
``except ... as e`` cleanup).  The sample is not shipped with the tool, so
every check skips politely when it is absent.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

SAMPLE = os.path.join(ROOT, "uploads", "Old.py")
FAILED = []
SKIPPED = []


def check(name):
    def wrap(fn):
        if not os.path.exists(SAMPLE):
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


_CACHE = {}


def payload():
    """The inner marshal blob of the sample, extracted once."""
    if "blob" in _CACHE:
        return _CACHE["blob"]
    raw = open(SAMPLE, "rb").read()
    blob = None
    for node in ast.walk(ast.parse(raw.decode("utf-8", "replace"))):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "loads":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, bytes):
                    blob = arg.value
    _CACHE["blob"] = blob
    return blob


def module():
    if "module" not in _CACHE:
        version, code, consumed = P.parse_marshal_blob(payload())
        _CACHE["module"] = (version, code)
    return _CACHE["module"]


@check("payload is a 3.14 code object")
def _version():
    version, code = module()
    eq(version, (3, 14), "detected version")
    eq(len(code.code), 45762, "module bytecode size")
    ok(len(code.consts) > 5000, "module keeps its constants")


@check("3.13 cannot outscore 3.14 on this payload")
def _scoring():
    _version, code = module()
    scores = {version: P._version_score(code, version)
              for version in ((3, 11), (3, 12), (3, 13), (3, 14))}
    best = max(scores, key=lambda key: scores[key])
    eq(best, (3, 14), f"scores {scores}")
    ok(scores[(3, 14)] - scores[(3, 13)] > 5, "margin over 3.13")


@check("whole module rebuilds and compiles")
def _rebuild():
    version, code = module()
    text, score = P.decompile_object(code, version, None)
    ok(text is not None, "engine returned source")
    ok(P.compile_problem(text) is None, "rebuilt module compiles")
    ok(P.decompile_accepted(score, version), f"round trip {score:.3f}")
    ok(score >= 0.6, f"round trip {score:.3f} below 0.6")
    _CACHE["text"] = text


@check("the 3.14 with-block becomes a with statement")
def _with_block():
    text = _CACHE.get("text") or ""
    ok("with ThreadPool(max_workers=40) as ____iloveyou____:" in text,
       "with-block not recovered")
    ok("____iloveyou____.submit(_____method_____, ids, passlist)" in text,
       "with body missing")


@check("except clauses keep their alias")
def _except_alias():
    text = _CACHE.get("text") or ""
    ok("except Exception as e:" in text, "no `except Exception as e:`")
    for junk in ("if Exception:", "del e", "e = None"):
        ok(junk not in text, f"cleanup bookkeeping leaked as {junk!r}")


@check("no dead statements in the rebuild")
def _no_junk():
    text = _CACHE.get("text") or ""
    tree = ast.parse(text)
    bare = 0
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list):
            for stmt in body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) \
                        and stmt.value.value is None:
                    bare += 1
    eq(bare, 0, "`None` statements left in the output")
    ok(not any(line.strip() == "return" for line in text.split("\n")
               if line[:1] not in (" ", "\t")), "module level return")


@check("constants survive the rebuild")
def _content():
    text = _CACHE.get("text") or ""
    for marker in ("chat.whatsapp.com/LvzFL7Cxxl335Xeoe8AlQo",
                   "https://graph.facebook.com/auth/login",
                   "/sdcard/MONSTER-OLD-OK.txt",
                   "com.facebook.account.login.protocol.Fb4aAuthHandler",
                   "[MONSTER-XD]",
                   "['123456', '1234567', '12345678', '123456789', '123123', '143143']"):
        ok(marker in text, f"missing {marker!r}")


@check("cross-version score trusts the rebuild")
def _score():
    version, code = module()
    text = _CACHE.get("text") or ""
    host = compile(text, "<rebuild>", "exec")
    cross = P.cross_version_score(code, version, host)
    ok(cross > 0.55, f"cross-version score {cross:.3f}")
    coverage = P.content_coverage(code, text)
    ok(coverage > 0.90, f"content coverage {coverage:.3f}")


@check("the CLI writes the rebuild, not the statement lifter")
def _cli():
    import subprocess
    import tempfile
    folder = tempfile.mkdtemp()
    result = subprocess.run([sys.executable, os.path.join(HERE, "pydecomp.py"), SAMPLE,
                             "-o", folder, "--no-color", "--no-anim"],
                            capture_output=True, text=True, timeout=600)
    eq(result.returncode, 0, result.stderr[-400:])
    written = [name for name in os.listdir(folder) if name.endswith(".py")]
    eq(len(written), 1, f"outputs {written}")
    text = open(os.path.join(folder, written[0]), encoding="utf-8").read()
    ok("result : pseudo" not in text, "artifact still flagged as pseudo")
    ok("whole module decompiled" in text, "header does not claim a rebuild")


if __name__ == "__main__":
    print()
    if SKIPPED:
        print(f"{len(SKIPPED)} skipped (sample absent)")
    if FAILED:
        print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
        raise SystemExit(1)
    print("all good")
