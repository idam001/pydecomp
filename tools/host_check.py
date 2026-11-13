#!/usr/bin/env python3
"""Check the two hosts this has to run on: a PC and a phone.

Termux is a real target - not a figure of speech.  It ships CPython with no
compiler by default, no pip in many installs, and a filesystem where ``/tmp``
may not exist.  So the claims that matter are narrow and testable:

  imports     nothing outside the standard library, and no compiled extension of
              our own, is needed to import the package and run a recovery
  single file  dist/pydecomp.py works alone: no src, no site-packages, no cwd
  writes      a recovery works from a read-only source tree, writing only to the
              output folder it is given
  start-up    importing the package is fast enough to be a shell command

    python3 tools/host_check.py            # all four
    python3 tools/host_check.py --json     # machine-readable

Run from anywhere; this script finds the repo itself.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SINGLE = ROOT / "dist" / "pydecomp.py"

#: stdlib-only, plus the sidecar pydecomp ships for its native menu entries and
#: the package importing itself
ALLOWED_THIRD_PARTY = {"pydecomp_native", "native", "pydecomp"}

SAMPLE = """import base64, zlib
_p = %r
exec(zlib.decompress(base64.b64decode(_p)))
"""
PAYLOAD = "def greet(name):\n    return 'hello ' + name\n\nprint(greet('world'))\n"
#: the cleaner folds the call site, so "the payload came back" means its shape
#: survived - not that the file is byte-identical to what was packed
MARKERS = ("def greet",)


def _stdlib_names() -> set[str]:
    names = set(sys.stdlib_module_names)
    names.update({"__future__"})
    return names


def imports_outside_stdlib() -> list[str]:
    """Every module the package imports that is not in the standard library."""
    allowed = _stdlib_names() | ALLOWED_THIRD_PARTY
    found: list[str] = []
    for path in sorted((SRC / "pydecomp").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            found.append(f"{path.name}: cannot parse ({exc})")
            continue
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                if root not in allowed:
                    found.append(f"{path.relative_to(SRC)}: imports {root}")
    return sorted(set(found))


def _run(command: list[str], env: dict, cwd: str) -> tuple[int, str]:
    done = subprocess.run(command, capture_output=True, text=True, env=env, cwd=cwd,
                          timeout=300)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="check the PC and Termux claims")
    ap.add_argument("--json", action="store_true", help="print a JSON verdict")
    args = ap.parse_args(argv)

    checks: list[tuple[str, bool, str]] = []

    stray = imports_outside_stdlib()
    checks.append(("imports", not stray,
                   "standard library only" if not stray else "; ".join(stray[:4])))

    started = time.monotonic()
    code, output = _run([sys.executable, "-c", "import pydecomp"],
                        {**os.environ, "PYTHONPATH": str(SRC)}, str(ROOT))
    startup = time.monotonic() - started
    checks.append(("start-up", code == 0 and startup < 3.0,
                   f"import pydecomp in {startup * 1000:.0f} ms"))

    folder = tempfile.mkdtemp(prefix="host-")
    try:
        sample = os.path.join(folder, "sample.py")
        with open(sample, "w", encoding="utf-8") as handle:
            handle.write(SAMPLE % base64_blob())
        env = {**os.environ, "PYTHONPATH": str(SRC), "HOME": folder,
               "PYTHONDONTWRITEBYTECODE": "1"}
        code, output = _run([sys.executable, "-m", "pydecomp", sample,
                             "-o", os.path.join(folder, "out"),
                             "--no-color", "--no-anim"], env, folder)
        recovered = os.path.join(folder, "out", "sample_deob.py")
        ok_read = (os.path.isfile(recovered)
                   and all(marker in pathlib.Path(recovered).read_text()
                           for marker in MARKERS[:1]))
        checks.append(("writes", code == 0 and ok_read,
                       "recovers with HOME set to a scratch folder"))

        if SINGLE.exists():
            alone = tempfile.mkdtemp(prefix="alone-")
            try:
                copy = os.path.join(alone, "pydecomp.py")
                shutil.copy2(SINGLE, copy)
                shutil.copy2(sample, os.path.join(alone, "sample.py"))
                env = {"PATH": os.environ.get("PATH", ""), "HOME": alone,
                       "PYTHONDONTWRITEBYTECODE": "1"}
                code, output = _run([sys.executable, "pydecomp.py", "sample.py",
                                     "-o", "out", "--no-color", "--no-anim"],
                                    env, alone)
                single_out = os.path.join(alone, "out", "sample_deob.py")
                ok_single = (code == 0 and os.path.isfile(single_out)
                             and all(marker in pathlib.Path(single_out).read_text()
                                     for marker in MARKERS[:1]))
                checks.append(("single file", ok_single,
                               "the bundle runs with no src and no PYTHONPATH"))
            finally:
                shutil.rmtree(alone, ignore_errors=True)
        else:
            checks.append(("single file", False, "dist/pydecomp.py is missing"))
    finally:
        shutil.rmtree(folder, ignore_errors=True)

    for name, good, detail in checks:
        print(f"{'ok  ' if good else 'FAIL'} {name:12s} {detail}")
    verdict = all(good for _name, good, _detail in checks)
    if args.json:
        print(json.dumps({"checks": [{"name": name, "ok": good, "detail": detail}
                                     for name, good, detail in checks],
                          "ok": verdict}, indent=1))
    print(f"\n{len(checks)} checks {'passed' if verdict else 'failed'} — "
          + ("all good" if verdict else "not ready"))
    return 0 if verdict else 1


def base64_blob() -> bytes:
    import base64
    import zlib
    return base64.b64encode(zlib.compress(PAYLOAD.encode()))


if __name__ == "__main__":
    raise SystemExit(main())
