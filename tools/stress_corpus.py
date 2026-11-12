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
    python3 tools/stress_corpus.py --seeds 1,2,3,4,5 --runs 40   # many seeds
    python3 tools/stress_corpus.py --deep --runs 200             # up to 24 layers
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
# `escapes` needs text on its input, so it is only valid as the innermost layer;
# a random stack has no idea where that is, and pretending otherwise builds
# samples that would not run at all.  It stays in the corpus, out of the fuzz.
LAYERS = ["b64", "b64url", "base32", "base85", "a85", "hex", "zlib", "lzma",
          "gzip", "bz2", "reverse", "rot13", "xor5a", "xor33",
          "base58", "base62", "base45", "z85"]

#: codecs with an alphabet of their own.  The named families spell their loaders
#: out by hand; in a random stack the spelling has to be generated, and it has to
#: be the *same shape* a real loader uses - a counting loop, not a call to a
#: decoder we invented - or the sample would be testing our vocabulary, not the
#: analyser's reading.
ALPHABETS = {"base58": MC.B58, "base62": MC.B62, "base45": MC.B45, "z85": MC.Z85}


def _alphabet_stage(name: str) -> list[str]:
    alphabet = ALPHABETS[name]
    if name == "z85":
        return [f"_A = {alphabet!r}", "_o = bytearray()",
                "for _i in range(0, len(_p), 5):",
                "    _v = 0",
                "    for _c in _p[_i:_i + 5]:",
                "        _v = _v * 85 + _A.index(chr(_c))",
                "    _o.extend(_v.to_bytes(4, 'big'))",
                "_p = bytes(_o).rstrip(b'\\x00')"]
    if name == "base45":
        return [f"_A = {alphabet!r}", "_o = bytearray()", "_i = 0",
                "while _i + 2 < len(_p):",
                "    _v = (_A.index(chr(_p[_i]))",
                "          + _A.index(chr(_p[_i + 1])) * 45",
                "          + _A.index(chr(_p[_i + 2])) * 2025)",
                "    _o.extend(_v.to_bytes(2, 'big'))",
                "    _i += 3",
                "if _i < len(_p):",
                "    _o.append(_A.index(chr(_p[_i]))"
                " + _A.index(chr(_p[_i + 1])) * 45)",
                "_p = bytes(_o)"]
    return [f"_A = {alphabet!r}", "_n = 0",
            "for _c in _p.decode().strip():",
            "    _n = _n * len(_A) + _A.index(_c)",
            "_p = _n.to_bytes(max(1, (_n.bit_length() + 7) // 8), 'big')"]


def loader_for(cooked: bytes, layers: tuple[str, ...]) -> str:
    """A loader that undoes ``layers``, one statement per layer.

    `make_corpus.loader_for` writes one nested expression, which cannot express a
    loop.  Here every layer is its own statement, which can.
    """
    body = ["import base64, codecs, zlib, lzma, gzip, bz2", f"_p = {cooked!r}"]
    for name in reversed(layers):
        if name in ALPHABETS:
            body += _alphabet_stage(name)
        else:
            body.append(f"_p = {MC.OPS[name][2].format(x='_p')}")
    body.append("exec(_p)")
    return "\n".join(body) + "\n"


#: shapes the *loader* can take, independent of the codec stack: a stack tests
#: the decoders, a wrapper tests the reader.  Real obfuscators ship both.
STUB = b"x = 1\n"


def _indent(text: str) -> str:
    return "\n".join("    " + line for line in text.splitlines())


def _chunk(text: str, size: int = 40) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


def wrap(loader: str, name: str) -> str:
    """Put the loader inside one of the shapes obfuscators actually ship."""
    if name == "bare":
        return loader
    if name == "function":
        return "def _go():\n" + _indent(loader) + "\n\n_go()\n"
    if name == "decoy":
        import base64
        stub = base64.b64encode(STUB).decode()
        return ("import base64\nexec(base64.b64decode(b'%s'))\n" % stub) + loader
    if name == "chunks":
        parts = _chunk(loader)
        body = ", ".join(repr(part) for part in parts)
        return "parts = [%s]\nexec(''.join(parts))\n" % body
    if name == "reversed-lines":
        lines = loader.splitlines()
        body = ", ".join(repr(line + "\n") for line in reversed(lines))
        return "lines = [%s]\nexec(''.join(reversed(lines)))\n" % body
    raise SystemExit(f"unknown wrapper {name!r}")


#: depths a stack may have; `--depth-max` trims this ladder, `--deep` lifts it
DEPTHS = (1, 2, 3, 4, 6, 8, 12, 16, 20, 24)


WRAPPERS = ("bare", "bare", "function", "decoy", "chunks", "reversed-lines")


def build(seed: int, run: int, depth_max: int = 12) -> tuple[str, bytes, str, str]:
    """One cooked sample, the payload it holds, and the stack that made it."""
    rng = random.Random(seed * 100003 + run)
    payload_name = rng.choice(sorted(MC.PAYLOADS))
    payload = MC.PAYLOADS[payload_name].encode()
    depth = rng.choice([d for d in DEPTHS if d <= depth_max])
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
    # a layer applied twice in a row can cancel itself out - xor with the same
    # key, reverse, rot13 - and a stack that cancels is not a hard sample, it is
    # a sample with no obfuscation left in it.  Collapse those pairs.
    collapsed: list[str] = []
    for name in safe:
        if collapsed and collapsed[-1] == name and name in (
                "reverse", "rot13", "xor5a", "xor33"):
            collapsed.pop()
            continue
        collapsed.append(name)
    layers = tuple(collapsed) or ("b64",)
    try:
        cooked, _steps = MC.cook(payload, layers)
    except Exception:                                # noqa: BLE001 - fall back to base64
        layers = ("b64",)
        cooked, _steps = MC.cook(payload, layers)
    loader = loader_for(cooked, layers)
    shape = WRAPPERS[rng.randrange(len(WRAPPERS))]
    loader = wrap(loader, shape)
    return loader, payload, " → ".join(layers), shape


def grade(loader: str, payload: bytes) -> dict:
    from eval_corpus import compiles, recall, tokens
    from pydecomp.engine.run import deobfuscate as run
    import contextlib
    import io
    import warnings

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
    with warnings.catch_warnings():
        # generated samples can carry a stray escape; that is the sample's
        # business, not the analyser's, and it must not pollute the gate log
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        score = recall(payload.decode(), text)
        parsed = compiles(text)
    # an output that is just the sample handed back is not a decompile, however
    # many payload tokens the sample happens to quote
    copied = text.strip() == loader.strip()
    return {"ok": score >= 0.90 and parsed and not copied,
            "recall": 0.0 if copied else round(score, 3),
            "tokens": len(tokens(payload.decode()))}


#: the share of random stacks that must come back recovered.  Five seeds of forty
#: stacks, up to twenty-four layers deep, with the loader inside one of six
#: shapes: this is the corner of the space, so the floor sits near the ceiling.
FLOOR = 0.98


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="random stacks against the analyser")
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--seeds", default="", help="comma list, overrides --seed")
    parser.add_argument("--depth-max", type=int, default=12)
    parser.add_argument("--deep", action="store_true", help="stacks up to 24 layers")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.deep:
        args.depth_max = max(args.depth_max, 24)
    seeds = ([int(part) for part in args.seeds.split(",") if part.strip()]
             or [args.seed])
    args.seed = seeds[0]

    rows = []
    for seed in seeds:
        for run in range(args.runs):
            loader, payload, stack, shape = build(seed, run, args.depth_max)
            try:
                result = grade(loader, payload)
            except Exception as exc:                # noqa: BLE001 - one stack must not stop the run
                result = {"ok": False, "recall": 0.0,
                          "error": f"{type(exc).__name__}: {exc}"}
            result["stack"] = stack
            result["shape"] = shape
            rows.append(result)
            if args.verbose and not result["ok"]:
                hint = result.get("error") or f"recall {result['recall']:.2f}"
                print(f"  miss seed {seed} run {run:<4} {hint}  "
                      f"[{shape}] {stack}")

    good = sum(1 for row in rows if row["ok"])
    rate = good / len(rows) if rows else 0.0
    depth_sum = sum(len(row["stack"].split("→")) for row in rows)
    mean_depth = depth_sum / max(len(rows), 1)
    floor = int(len(rows) * FLOOR)
    where = (f"mean {mean_depth:.1f} layers, max depth {args.depth_max}, "
             f"seed{'s' if len(seeds) > 1 else ''} "
             f"{','.join(str(seed) for seed in seeds)}")
    if args.check:
        # a floor, not a boast: random stacks are harder than named families, and
        # the gate exists so the floor can only go up
        if good < floor:
            print(f"FAIL stress {good}/{len(rows)} random stacks recovered "
                  f"(floor {floor})")
            for row in rows:
                if not row["ok"]:
                    print(f"  [{row.get('shape', '?')}] recall "
                          f"{row['recall']:.2f}  {row['stack']}")
            return 4
        print(f"ok stress {good}/{len(rows)} random stacks recovered "
              f"(floor {floor}, {where})")
        return 0
    print(f"{good}/{len(rows)} random stacks recovered ({rate:.0%}), {where}")
    for row in rows:
        if not row["ok"]:
            print(f"  miss: [{row.get('shape', '?')}] {row['stack']} "
                  f"(recall {row['recall']:.2f})")
    return 0 if good >= floor else 4


if __name__ == "__main__":
    sys.exit(main(sys.argv))
