"""Gate: six freezers, one recovery path, no special cases in the engine."""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import freezer_cases  # noqa: E402

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def run(*args):
    return subprocess.run([sys.executable, "-m", "pydecomp", *args],
                          capture_output=True, text=True, timeout=600,
                          env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src"),
                               "NO_COLOR": "1", "COLUMNS": "100"})


def sources(folder):
    return [name for name in os.listdir(folder)
            if name.endswith(".py")] if os.path.isdir(folder) else []


work = tempfile.mkdtemp(prefix="freezer-gate-")
paths = freezer_cases.write_all(work)
expected = {"shiv": "shiv", "pex": "pex", "briefcase": "briefcase",
            "cx_freeze": "cx_freeze", "cx_freeze_bare": "cx_freeze",
            "py2exe": "py2exe", "pyinstaller": "pyinstaller"}

for name, path in paths.items():
    out = os.path.join(work, "out-" + name)
    done = run(path, "-o", out, "--no-color", "--no-anim")
    ok(done.returncode == 0, f"{name}: run exits 0 ({done.stderr[-200:]})")
    ok(expected[name] in done.stdout.lower(),
       f"{name}: the container is named ({done.stdout[:300]})")
    found = sources(out)
    ok(found, f"{name}: a source file was written ({os.listdir(out) if os.path.isdir(out) else []})")
    if found:
        body = open(os.path.join(out, found[0]), encoding="utf-8").read()
        ok("FREEZER-MARKER" in body or "def run(" in body or "def helper(" in body,
           f"{name}: the recovered text is the freezer's own program ({body[:160]!r})")
        ok("MEI" not in body[:200], f"{name}: the output is not the container's raw bytes")

# a plain zip must not be mistaken for a freezer
import zipfile  # noqa: E402
plain = os.path.join(work, "plain.zip")
with zipfile.ZipFile(plain, "w") as archive:
    archive.writestr("app.py", "print('plain zip')\n")
plain_out = os.path.join(work, "out-plain")
done = run(plain, "-o", plain_out, "--no-color", "--no-anim")
ok(done.returncode == 0, "a plain zip still works")
ok("plain zip" in open(os.path.join(plain_out, sources(plain_out)[0]),
                       encoding="utf-8").read() if sources(plain_out) else False,
   "the plain zip's own source came through")

print()
print("all good" if not FAILED else f"{len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
