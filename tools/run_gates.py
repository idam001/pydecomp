#!/usr/bin/env python3
"""Run every integration gate and print one table.

Each gate is a plain script under ``tests/integration`` that prints a final
verdict line (``20/20 passed``, ``all good``, ``44/44``…).  This runner executes
them with ``PYTHONPATH=src`` so they test the package exactly as it ships,
caches the verdict, and exits non-zero if anything is red.

    python3 tools/run_gates.py               # everything
    python3 tools/run_gates.py v8 probes     # a subset
    python3 tools/run_gates.py --json out.json
    python3 tools/run_gates.py --list
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATES = ROOT / "tests" / "integration"
BENCH = ROOT / "tests" / "benchmarks" / "bench_obf_bench.py"
EXAMPLES = ROOT / "examples" / "run_examples.py"

# name -> (path, extra environment, needs a bigger stack)
SUITE = {
    "v4": (GATES / "test_v4.py", {}, False),
    "v5": (GATES / "test_v5.py", {}, False),
    "v6": (GATES / "test_v6.py", {}, False),
    "v7": (GATES / "test_v7.py", {}, False),
    "v8": (GATES / "test_v8.py", {}, False),
    "almighty": (GATES / "test_almighty.py", {}, False),
    "reconstruct": (GATES / "test_reconstruct.py", {}, False),
    "families": (GATES / "families_probe.py", {}, False),
    "iocs": (GATES / "test_iocs.py", {}, False),
    "shapes": (GATES / "shapes_probe.py", {}, False),
    "yara": (GATES / "test_yara.py", {}, False),
    "coverage": (GATES / "test_coverage.py", {}, False),
    "identity": (GATES / "test_identity.py", {}, False),
    "probes": (GATES / "test_probes.py", {}, False),
    "native": (GATES / "test_native.py", {}, True),
    "bench": (BENCH, {}, False),
    "examples": (EXAMPLES, {}, False),
}

GOOD = re.compile(r"(all good|passed|instruction-identical|probe shapes recovered|"
                  r"semantic score|examples recovered)", re.I)


def run(name: str, verbose: bool = False) -> dict:
    path, extra, heavy = SUITE[name]
    if not path.exists():
        return {"gate": name, "ok": False, "verdict": "missing", "seconds": 0.0}
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"),
           "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1", **extra}
    command = [sys.executable, "-u", str(path)]
    if heavy:
        # the native gate parses a 92 KB ELF with a pure-Python DWARF reader
        command = ["/bin/sh", "-c", f"ulimit -v 4000000; exec {' '.join(command)}"]
    started = time.time()
    done = subprocess.run(command, capture_output=True, text=True, timeout=1800, env=env)
    elapsed = time.time() - started
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    verdict = lines[-1].strip() if lines else (done.stderr.strip().splitlines() or ["no output"])[-1]
    ok = done.returncode == 0 and bool(GOOD.search(verdict))
    if verbose or not ok:
        print(done.stdout[-4000:])
        if done.stderr.strip():
            print(done.stderr[-2000:], file=sys.stderr)
    return {"gate": name, "ok": ok, "verdict": verdict, "seconds": round(elapsed, 1)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("gates", nargs="*", help="gate names (default: all)")
    parser.add_argument("--json", help="also write the results as JSON here")
    parser.add_argument("--list", action="store_true", help="print the gate names")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.list:
        print(" ".join(SUITE))
        return 0

    names = args.gates or list(SUITE)
    unknown = [name for name in names if name not in SUITE]
    if unknown:
        print(f"unknown gate(s): {', '.join(unknown)}\navailable: {', '.join(SUITE)}")
        return 2

    results = []
    print()
    for name in names:
        result = run(name, args.verbose)
        results.append(result)
        mark = "ok  " if result["ok"] else "FAIL"
        print(f"  {mark} {name:<9} {result['seconds']:>6.1f}s   {result['verdict']}")

    failed = [result for result in results if not result["ok"]]
    print()
    print(f"  {len(results) - len(failed)}/{len(results)} gates green"
          f"   ({sum(r['seconds'] for r in results):.1f}s)")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
