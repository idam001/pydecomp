#!/usr/bin/env python3
"""Every backend that declares an inverse, checked against itself.

A backend that can forge what it opens can be tested without a sample: forge a
known payload, hand the result back, and see whether the payload comes out.  The
ones that read bytes made by something else - a zip member, a pyc header, an RC4
head - have no inverse to declare and are listed as such, which is a fact about
them rather than a problem with them.

    python3 tools/backend_matrix.py            # a table
    python3 tools/backend_matrix.py --json     # what the gate reads
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "src"))

from pydecomp.plugins.backends import backends          # noqa: E402
from pydecomp.plugins.backends.explore import explore   # noqa: E402
from pydecomp.plugins.backends.spec import Budget       # noqa: E402


def fixture() -> bytes:
    """A layer-shaped payload: text, and text that is a compressed stream."""
    body = b"".join(b"def step%d(value):\n    return value * %d + 1\n\n" % (index, index)
                    for index in range(40))
    return base64.b64encode(zlib.compress(body))


def check(backend, payload: bytes) -> tuple[str, float, int, str]:
    forged = backend.inverts(payload)
    if forged is None:
        return "no forge", 0.0, 0, "forge returned nothing"
    if forged == payload:
        return "identity", 0.0, 0, "forge returned the payload unchanged"
    start = time.perf_counter()
    candidates = backend.candidates(forged)
    elapsed = time.perf_counter() - start
    if payload in candidates:
        return "ok", elapsed, len(candidates), ""
    if not candidates:
        return "silent", elapsed, 0, "the forged blob opened into nothing"
    # a container cuts the layer free but does not open it, so the question is
    # whether the tree reaches the payload from here, not whether this backend
    # does it alone
    reached = explore(forged, lambda data, chain: data == payload, depth=3,
                      budget=Budget(opens=600, seconds=4.0))
    if reached.hits:
        return "ok", elapsed, len(candidates), "reached in a chain"
    return "wrong", elapsed, len(candidates), "the payload was not among the candidates"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    payload = fixture()
    rows = []
    for backend in backends():
        if backend.forge is None:
            rows.append({"name": backend.name, "kind": backend.kind,
                         "state": "carried", "seconds": 0.0, "candidates": 0,
                         "note": "no inverse declared"})
            continue
        state, elapsed, count, note = check(backend, payload)
        rows.append({"name": backend.name, "kind": backend.kind, "state": state,
                     "seconds": round(elapsed, 4), "candidates": count, "note": note})

    forged = [row for row in rows if row["state"] != "carried"]
    failed = [row for row in forged if row["state"] != "ok"]
    if args.json:
        print(json.dumps({"forged": len(forged), "failed": len(failed),
                          "carried": len(rows) - len(forged),
                          "failing": [row for row in failed]},
                         separators=(", ", ": ")))
        return 1 if failed else 0

    width = max(len(row["name"]) for row in rows) + 2
    for row in rows:
        mark = {"ok": "ok  ", "carried": "--  "}.get(row["state"], "FAIL")
        print(f"  {mark} {row['name']:<{width}} {row['kind']:<10} "
              f"{row['state']:<6} {row['candidates']:>3} cand  "
              f"{row['seconds'] * 1000:7.2f} ms  {row['note']}")
    print(f"\n  {len(forged) - len(failed)}/{len(forged)} forges roundtrip, "
          f"{len(rows) - len(forged)} read bytes made elsewhere")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
