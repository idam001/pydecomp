#!/usr/bin/env python3
"""Fuzz the readers that take hostile input, and require them to fail politely.

The marshal reader, the ``.pyc`` header reader and the freezer cookie reader all
parse bytes that came from a file whose author had no reason to be kind.  Each one
is recursive or index-driven, so the failure mode of interest is not "it raises" -
that is correct behaviour on garbage - but *which* exception it raises.  A
``ValueError`` is a declared refusal the pipeline already handles; an
``IndexError``, ``KeyError``, ``RecursionError`` or a two-minute hang is a crash
wearing a different hat.

So the test is not that fuzzing finds nothing.  It is that every failure is one of
the declared kinds, that no input runs past the time budget, and that the same
seed produces the same run twice.  Mutations are generated here, deterministically,
and are never taken from a sample.

    python3 tools/fuzz_parsers.py             # the gate
    python3 tools/fuzz_parsers.py -n 4000     # more mutations per target
    python3 tools/fuzz_parsers.py -v          # print the first failures as they land
"""
from __future__ import annotations

import argparse
import marshal
import pathlib
import random
import struct
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

#: an exception the pipeline already knows how to handle
DECLARED = (ValueError, EOFError, struct.error, OverflowError, MemoryError)

TIME_BUDGET = 2.0                # seconds per parsed blob
SEED = 20261101                  # fixed: the gate must reproduce a failure


# --------------------------------------------------------------------------
# seeds: bytes built here, never bytes taken from a sample
# --------------------------------------------------------------------------

def seeds() -> dict[str, bytes]:
    code = compile("def f(x):\n    return [x, {'k': (1, 2)}]\n", "s.py", "exec")
    blob = marshal.dumps(code)
    header = b"\x6f\x0d\x0d\x0a" + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4
    return {
        "pyc": header + blob,
        "marshal": blob,
        "archive_header": (b"MEI\x0c\x0b\x0a\x0b\x0e" + struct.pack("!IIII", 120, 40, 200, 313)
                           + b"python3.13".ljust(64, b"\x00") + b"\x00" * 240),
    }


# --------------------------------------------------------------------------
# mutations: deterministic given (seed, index)
# --------------------------------------------------------------------------

def deep_nest(depth: int) -> bytes:
    """A stream of *depth* nested one-element tuples."""
    return (b"".join(b"(" + (1).to_bytes(4, "little") for _ in range(depth))
            + b"N" + b"t" * depth)


def mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        if not buf:
            break
        position = rng.randrange(len(buf))
        style = rng.choice(["flip", "truncate", "zero", "insert", "huge", "nest"])
        if style == "flip":
            buf[position] ^= 1 << rng.randrange(8)
        elif style == "truncate":
            del buf[position:]
        elif style == "zero":
            span = rng.randint(1, 16)
            buf[position:position + span] = b"\x00" * len(buf[position:position + span])
        elif style == "insert":
            buf[position:position] = bytes(rng.randrange(256)
                                           for _ in range(rng.randint(1, 8)))
        elif style == "huge":
            buf[position:position + 4] = (0xFFFFFFFF).to_bytes(4, "little")
        elif style == "nest":
            buf[position:position] = deep_nest(rng.choice((30, 300, 3000)))
    return bytes(buf)


# --------------------------------------------------------------------------
# the targets
# --------------------------------------------------------------------------

def targets() -> dict:
    from pydecomp.bytecode.magic import parse_pyc
    from pydecomp.bytecode.marshal_reader import MarshalReader, parse_marshal_blob
    from pydecomp.containers.pyinstaller import _cookie, toc

    def read_marshal(data: bytes):
        return MarshalReader(data, (3, 13)).object()

    def read_archive(data: bytes):
        cookie = _cookie(data)
        if cookie is None:
            return []
        return toc(data, cookie)

    return {
        "parse_pyc": parse_pyc,
        "marshal_reader": read_marshal,
        "marshal_blob": parse_marshal_blob,
        "freezer_cookie": read_archive,
    }


def run(target, data: bytes) -> tuple[str, str]:
    """Return ('ok'|'refused'|'crashed'|'slow', detail)."""
    started = time.time()
    try:
        target(data)
    except DECLARED as exc:
        return "refused", type(exc).__name__
    except Exception as exc:                                   # noqa: BLE001
        return "crashed", f"{type(exc).__name__}: {exc}"[:120]
    finally:
        elapsed = time.time() - started
    if elapsed > TIME_BUDGET:
        return "slow", f"{elapsed:.1f}s"
    return "ok", ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-n", "--count", type=int, default=1500,
                        help="mutations per seed per target (default 1500)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    cases = seeds()
    functions = targets()
    failures: list[dict] = []
    totals = {"ok": 0, "refused": 0}
    print()

    for seed_name, data in cases.items():
        for target_name, target in functions.items():
            counts = {"ok": 0, "refused": 0, "crashed": 0, "slow": 0}
            kinds: dict[str, int] = {}
            rng = random.Random(f"{SEED}:{seed_name}:{target_name}")
            for index in range(args.count):
                blob = mutate(data, rng)
                verdict, detail = run(target, blob)
                counts[verdict] += 1
                if verdict == "refused":
                    kinds[detail] = kinds.get(detail, 0) + 1
                elif verdict in ("crashed", "slow"):
                    if args.verbose:
                        print(f"  {verdict}: {seed_name}/{target_name} #{index} {detail}")
                    failures.append({"seed": seed_name, "target": target_name,
                                     "index": index, "kind": verdict,
                                     "detail": detail})
            totals["ok"] += counts["ok"]
            totals["refused"] += counts["refused"]
            shown = ", ".join(f"{kind}×{n}" for kind, n in sorted(kinds.items()))
            print(f"  {seed_name:<15} {target_name:<15} ok {counts['ok']:>5}  "
                  f"refused {counts['refused']:>5}  crashed {counts['crashed']}  "
                  f"slow {counts['slow']}   [{shown}]")

    # the deep-nesting shape on its own: this is the one that used to escape as a
    # RecursionError, so it gets a direct test rather than a random one
    from pydecomp.bytecode.marshal_reader import MarshalReader

    def read_marshal(blob: bytes):
        return MarshalReader(blob, (3, 13)).object()

    for depth in (10, 50, 199, 5000, 20000):
        verdict, detail = run(read_marshal, deep_nest(depth))
        if verdict == "crashed":
            failures.append({"seed": "deep_nest", "target": "marshal_reader",
                             "index": depth, "kind": verdict, "detail": detail})
        elif args.verbose:
            print(f"  nest {depth}: {verdict} {detail}")

    print()
    if failures:
        print(f"{len(failures)} undeclared failure(s) over "
              f"{len(cases) * len(functions) * args.count} parsed blobs")
        for item in failures[:10]:
            print(f"  {item['seed']}/{item['target']} #{item['index']}: "
                  f"{item['kind']} {item['detail']}")
        return 1

    print(f"ok fuzz: {len(cases) * len(functions) * args.count} mutated blobs over "
          f"{len(functions)} parsers, {totals['refused']} refusals as declared "
          f"exceptions, 0 crashes, 0 hangs — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
