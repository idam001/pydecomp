#!/usr/bin/env python3
"""Regression tests for pydecomp v4 (premium one-button build).

Run: python3 tests/test_v4.py
"""
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
TOOL = None  # run as `-m pydecomp`
REAL = HERE.parent.parent / "uploads" / "daniup.py"
MARKER = "def go(uid)"


def run(args, keys="", cwd=None):
    return subprocess.run([sys.executable, "-m", "pydecomp", *[str(a) for a in args],
                           "--no-color"], input=keys, capture_output=True,
                          text=True, timeout=120, cwd=cwd)


def saved(out: pathlib.Path) -> str:
    hits = sorted(out.glob("*.py"))
    return hits[0].read_text(errors="replace") if hits else ""


def main() -> int:
    failures = 0
    total = 0
    cases = [
        ("t1_b64_zlib.py", "payload"),
        ("t2_lambda_reverse.py", "payload"),
        ("t3_bz2_alias.py", "payload"),
        ("t4_lzma_compile.py", "payload"),
        ("t5_nested3.py", "payload"),
        ("t6_hex_join.py", "payload"),
        ("t7_gzip_rev.py", "payload"),
        ("t8_plain.py", "plain"),
        ("t9_marshal.py", "lifted"),
        ("t10_rot13_concat.py", "payload"),
    ]
    for name, expect in cases:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            proc = run([HERE / name, "-o", out])
            body = saved(out)
            if expect == "payload":
                ok = proc.returncode == 0 and MARKER in body
            elif expect == "plain":
                # nothing to peel: the source itself is the answer
                ok = proc.returncode == 0 and "def go(uid)" in body
            elif expect == "lifted":
                # v5 lifts the marshal payload into readable Python
                ok = proc.returncode == 0 and body.lstrip().startswith("#")
            else:
                ok = "350685531728" in body
            failures += 0 if ok else 1
            total += 1
            print(f"{'PASS' if ok else 'FAIL'}  {name:<24} "
                  f"→ {[p.name for p in out.glob('*.py')]}  exit={proc.returncode}")

    # bytecode + binary inputs
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        src = tmp / "p.py"
        src.write_text('import os\nKEY = "sekrit"\nprint(KEY)\n')
        subprocess.run([sys.executable, "-c",
                        f"import py_compile;py_compile.compile(r'{src}',cfile=r'{tmp}/p.pyc')"],
                       check=True)
        out = tmp / "out"
        run([tmp / "p.pyc", "-o", out])
        got = saved(out)
        ok = "sekrit" in got and "KEY" in got
        failures += 0 if ok else 1
        total += 1
        print(f"{'PASS' if ok else 'FAIL'}  .pyc input → lifted to source")

        blob = tmp / "blob.bin"
        blob.write_bytes(bytes(range(256)) * 3 + b"https://example.test/x KEY=abc")
        out2 = tmp / "out2"
        run([blob, "-o", out2])
        ok = "https://example.test/x" in saved(out2)
        failures += 0 if ok else 1
        total += 1
        print(f"{'PASS' if ok else 'FAIL'}  binary blob → carved strings")

    # menu flow: launch → [1] → path → run → [0] exit
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        sample = REAL if REAL.exists() else HERE / "t1_b64_zlib.py"
        proc = run(["-o", out], keys=f"1\n{sample}\n\n0\n")
        body = saved(out)
        checks = {
            "banner": ("WELCOME TO IDAM EMMANUEL TOOLS" in proc.stdout
                       and "[ NETWORK ]" in proc.stdout
                       and "[ COUNTRY ]" in proc.stdout
                       and "Idam Emmanuel" in proc.stdout),
            "main menu": "MAIN MENU" in proc.stdout and "[1]" in proc.stdout,
            "prompted for path": "paste the path" in proc.stdout,
            "animated/plain progress": "Decompiling" in proc.stdout,
            "result panel": "saved to" in proc.stdout,
            "file written": bool(body),
            "returned to menu": proc.stdout.count("MAIN MENU") >= 2,
            "clean exit": proc.returncode == 0,
        }
        for label, ok in checks.items():
            failures += 0 if ok else 1
            total += 1
            print(f"{'PASS' if ok else 'FAIL'}  menu flow: {label}")

    # real sample + collision + no chatter
    if REAL.exists():
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            run([REAL, "-o", out])
            first = saved(out)
            run([REAL, "-o", out])
            names = sorted(p.name for p in out.glob("*.py"))
            ok = "auth.login" in first and names == ["daniup_deob.py", "daniup_deob_2.py"]
            failures += 0 if ok else 1
            total += 1
            print(f"{'PASS' if ok else 'FAIL'}  real sample + collision → {names}")

            proc = run([REAL, "-o", out])
            banned = ["risk", "policy", "illegal", "cfaa", "behaviour flag",
                      "what to do", "recommend", "ioc"]
            leaked = [b for b in banned if b in proc.stdout.lower()]
            failures += 0 if not leaked else 1
            total += 1
            print(f"{'PASS' if not leaked else 'FAIL'}  no risk/policy chatter"
                  + (f"  (leaked {leaked})" if leaked else ""))

    print(f"\n{total - failures}/{total} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
