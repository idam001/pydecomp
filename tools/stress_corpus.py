#!/usr/bin/env python3
"""A hundred random stacks, built and recovered, to check the corpus generalises.

The corpus proves 46 named families.  This asks the harder question: does the
engine work on combinations nobody wrote down?  Each run picks a payload, picks
between one and twelve layers from the same table the families use, cooks it,
writes a loader, runs the analyser and grades the result exactly as the corpus
does.  The seed is fixed so the answer is reproducible.

    python3 tools/stress_corpus.py             # 100 stacks
    python3 tools/stress_corpus.py --runs 500
    python3 tools/stress_corpus.py --seed 7 --verbose
    python3 tools/stress_corpus.py --check     # gate mode: one line, exit 4 on a miss

Nothing is executed: every stack is built with the same pure transforms the
corpus uses, and graded by reading what the analyser wrote.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import random
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(ROOT, "src"), os.path.join(ROOT, "tools"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)


def _corpus_module():
    spec = importlib.util.spec_from_file_location(
        "make_corpus", os.path.join(ROOT, "tools", "make_corpus.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MC = _corpus_module()

# every reversible layer the corpus knows, minus the ones that need a tail
# only layers whose loader line is real Python: the alphabet codecs are spelled
# out per family (base58/45/z85/uu) and have no one-line expression, so a random
# stack must not pretend to use them
LAYERS = ["b64", "b64url", "base32", "base85", "a85", "hex", "zlib", "lzma",
          "gzip", "bz2", "reverse", "rot13", "xor5a", "xor33", "escapes"]


def build(seed: int, run: int) -> tuple[str, bytes, str]:
    """One cooked sample, the payload it holds, and the stack that made it."""
    rng = random.Random(seed * 100003 + run)
    payload_name = rng.choice(sorted(MC.PAYLOADS))
    payload = MC.PAYLOADS[payload_name].encode()
    depth = rng.choice([1, 2, 3, 4, 6, 8, 12])
    layers = tuple(rng.choice(LAYERS) for _ in range(depth))
    # a text codec (rot13, escapes) needs text: if the stack mixes one in after a
    # binary layer, drop it and carry on - the point is random stacks, not
    # impossible ones
    safe = []
    for name in layers:
        if name in ("rot13", "escapes", "base58", "base62", "base45", "z85", "uu") \
                and safe and safe[-1] in ("zlib", "lzma", "gzip", "bz2", "xor5a",
                                          "xor33", "reverse"):
            continue
        safe.append(name)
    layers = tuple(safe) or ("b64",)
    try:
        cooked, _steps = MC.cook(payload, layers)
    except Exception:                                # noqa: BLE001 - fall back to base64
        layers = ("b64",)
        cooked, _steps = MC.cook(payload, layers)
    loader = MC.loader_for(cooked, layers, "exec")
    return loader, payload, " → ".join(layers)


def grade(loader: str, payload: bytes) -> dict:
    from eval_corpus import compiles, recall, tokens
    from pydecomp.engine.run import deobfuscate as run
    import contextlib
    import io

    folder = tempfile.mkdtemp(prefix="stress-")
    sample = os.path.join(folder, "sample.py")
    with open(sample, "w", encoding="utf-8") as handle:
        handle.write(loader)
    out = os.path.join(folder, "out")
    with contextlib.redirect_stdout(io.StringIO()):
        written = run(sample, out, clean=False, reports=False)
    text = ""
    if written and os.path.isfile(written):
        with open(written, encoding="utf-8", errors="surrogateescape") as handle:
            text = handle.read()
    score = recall(payload.decode(), text)
    return {"ok": score >= 0.90 and compiles(text), "recall": round(score, 3),
            "tokens": len(tokens(payload.decode()))}


#: the share of random stacks that must come back recovered
FLOOR = 0.80


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="random stacks against the analyser")
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])

    rows = []
    for run in range(args.runs):
        loader, payload, stack = build(args.seed, run)
        try:
            result = grade(loader, payload)
        except Exception as exc:                     # noqa: BLE001 - one stack must not stop the run
            result = {"ok": False, "recall": 0.0, "error": f"{type(exc).__name__}: {exc}"}
        result["stack"] = stack
        rows.append(result)
        if args.verbose and not result["ok"]:
            print(f"  miss #{run:<4} recall {result['recall']:.2f}  {stack}")

    good = sum(1 for row in rows if row["ok"])
    rate = good / len(rows) if rows else 0.0
    mean_depth = sum(len(row["stack"].split("→")) for row in rows) / max(len(rows), 1)
    if args.check:
        # a floor, not a boast: random stacks are harder than named families, and
        # the gate exists so the floor can only go up
        floor = int(len(rows) * FLOOR)
        if good < floor:
            print(f"FAIL stress {good}/{len(rows)} random stacks recovered "
                  f"(floor {floor})")
            for row in rows:
                if not row["ok"]:
                    print(f"  recall {row['recall']:.2f}  {row['stack']}")
            return 4
        if good < len(rows):
            print(f"ok stress {good}/{len(rows)} random stacks recovered "
                  f"(floor {floor}, mean {mean_depth:.1f} layers)")
            return 0
        print(f"ok stress {good}/{len(rows)} random stacks recovered "
              f"({mean_depth:.1f} layers on average)")
        return 0
    print(f"{good}/{len(rows)} random stacks recovered ({rate * 100:.0f}%), "
          f"mean depth {mean_depth:.1f} layers, seed {args.seed}")
    if good < len(rows):
        for row in rows:
            if not row["ok"]:
                print(f"  miss: {row['stack']} (recall {row['recall']:.2f})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
