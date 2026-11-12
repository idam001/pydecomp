"""Benchmarks with budgets, not vibes.

    python3 tests/benchmarks/bench_core.py            # numbers + verdicts
    python3 tests/benchmarks/bench_core.py --json out.json

Budgets are the contract; the sandbox factor makes them meaningful on a phone
or a shared runner without turning the gate into a coin flip.  A regression that
doubles the time still passes; a regression that makes the tool quadratic does
not.
"""
from __future__ import annotations

import argparse
import base64
import json
import marshal
import os
import sys
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.crypto.aes import AES  # noqa: E402
from pydecomp.crypto.modes import ctr_xor  # noqa: E402
from pydecomp.engine.dig import dig  # noqa: E402

# CI runners and phones are slower than a laptop.  The factor is stated in the
# output so a green run never looks tighter than it was.
SANDBOX = 8.0 if os.environ.get("CI") else 4.0

BUDGETS = {
    "peel_1mb": 2.0,               # a 1 MB packed script, end to end
    "pyc_module": 0.5,             # one .pyc decompiled
    "aes_ctr_1mb": 8.0,            # pure-Python AES-CTR over 1 MB
}

PROGRAM = "".join(
    f"def f{index}(value):\n"
    f"    total = value * {index + 1}\n"
    f"    for step in range(3):\n"
    f"        total += step\n"
    f"    return total\n\n"
    for index in range(220))


def _entropy_hex(size: int = 700_000) -> str:
    """Deterministic, incompressible filler so the packed blob really is a MB."""
    import hashlib
    out = []
    digest = hashlib.sha256(b"seed").digest()
    while sum(len(chunk) for chunk in out) < size:
        digest = hashlib.sha256(digest).digest()
        out.append(digest.hex())
    return "".join(out)[:size]


def packed_megabyte() -> bytes:
    """A megabyte of source, zlib'd, base64'd, wrapped in a loader."""
    body = (PROGRAM * 8) + "\nTABLE = bytes.fromhex('" + _entropy_hex() + "')\n"
    blob = base64.b64encode(zlib.compress(marshal.dumps(compile(body, "big.py", "exec"))))
    return (b"import base64, zlib, marshal\n"
            b"exec(marshal.loads(zlib.decompress(base64.b64decode(b'" + blob + b"'))))\n")


def pyc_bytes(source: str) -> bytes:
    magic = __import__("importlib.util", fromlist=["MAGIC_NUMBER"]).MAGIC_NUMBER
    return magic + b"\x00" * 12 + marshal.dumps(compile(source, "<bench>", "exec"))


def timed(function, *args):
    started = time.perf_counter()
    result = function(*args)
    return time.perf_counter() - started, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="also write the numbers here")
    args = parser.parse_args()
    rows = []

    sample = packed_megabyte()
    seconds, artifact = timed(dig, sample)
    rows.append(("peel_1mb", seconds, BUDGETS["peel_1mb"],
                 f"{len(sample):,} B in, {len(artifact.text):,} chars out, "
                 f"{artifact.kind}"))

    module = pyc_bytes("def run(x):\n    return x + 1\n")
    seconds, _ = timed(dig, module)
    rows.append(("pyc_module", seconds, BUDGETS["pyc_module"], "one module"))

    key, nonce, data = b"k" * 16, b"n" * 12, os.urandom(1024 * 1024)
    seconds, _ = timed(ctr_xor, AES(key), nonce, data)
    rows.append(("aes_ctr_1mb", seconds, BUDGETS["aes_ctr_1mb"], "1 MiB"))

    failed = 0
    print()
    for name, seconds, budget, note in rows:
        allowed = budget * SANDBOX
        mark = "ok  " if seconds <= allowed else "FAIL"
        if seconds > allowed:
            failed += 1
        print(f"  {mark} {name:<12} {seconds:>7.3f}s   budget {budget:.2f}s "
              f"(x{SANDBOX:.0f} sandbox = {allowed:.1f}s)   {note}")
    print()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump([{"name": n, "seconds": round(s, 3), "budget": b, "note": extra}
                       for n, s, b, extra in rows], handle, indent=2)
    print(f"{len(rows) - failed}/{len(rows)} budgets met — all good"
          if not failed else f"{failed} budget(s) missed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
