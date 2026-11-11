#!/usr/bin/env python3
"""Run every example and check the recovery against its expectations.

Each example is a tiny synthetic obfuscated file plus a JSON file listing what
the recovery must contain. Nothing is executed: the comparison is textual and
the recovered file is only compiled, never run.

    python3 examples/run_examples.py
    python3 examples/run_examples.py 04_marshal_b64 --keep
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "src"
EXPECT = HERE / "expected"


def run(name: str, keep: bool) -> tuple[bool, str]:
    sample = HERE / f"{name}.py"
    expectation = json.loads((EXPECT / f"{name}.json").read_text(encoding="utf-8"))
    out = pathlib.Path(tempfile.mkdtemp(prefix=f"pydecomp-{name}-"))
    env = {**dict(**{k: v for k, v in __import__("os").environ.items()}),
           "PYTHONPATH": str(SRC), "NO_COLOR": "1"}
    done = subprocess.run(
        [sys.executable, "-m", "pydecomp", str(sample), "-o", str(out),
         "--no-color", "--no-anim"],
        capture_output=True, text=True, timeout=300, env=env)
    if done.returncode != 0:
        return False, f"cli exit {done.returncode}: {done.stderr[-300:]}"

    written = sorted(out.glob("*.py"))
    if len(written) != 1:
        return False, f"expected one output file, got {[p.name for p in written]}"
    text = written[0].read_text(encoding="utf-8")

    problems = []
    try:
        ast.parse(text)
    except SyntaxError as exc:
        problems.append(f"recovery does not parse: {exc}")
    for want in expectation.get("contains", []):
        if want not in text:
            problems.append(f"missing {want!r}")
    for forbidden in expectation.get("excludes", []):
        if forbidden in text:
            problems.append(f"should not contain {forbidden!r}")
    if expectation.get("preamble") and "Deobfuscated by idam Emmanuel" not in text:
        problems.append("no pydecomp signature line")

    if keep:
        kept = HERE / "expected" / f"{name}.recovered.py"
        kept.write_text(text, encoding="utf-8")
        problems.append(f"(kept {kept.name})") if False else None
    if problems:
        return False, "; ".join(problems)
    return True, f"{len(text):,} bytes recovered"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="examples to run (default: all)")
    parser.add_argument("--keep", action="store_true",
                        help="also write the recovery next to the expectations")
    args = parser.parse_args()

    names = args.names or sorted(path.stem for path in HERE.glob("[0-9]*.py"))
    if not names:
        print("no examples found")
        return 1

    failures = 0
    print()
    for name in names:
        ok, detail = run(name, args.keep)
        print(f"  {'ok  ' if ok else 'FAIL'} {name:<22} {detail}")
        failures += 0 if ok else 1
    print()
    print(f"  {len(names) - failures}/{len(names)} examples recovered")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
