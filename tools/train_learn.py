#!/usr/bin/env python3
"""Train the decoder ranking on the corpus, and prove the training helped.

The corpus is the data centre: 26 families of cooking, each applied to four real
payload programs, with the outermost layer known.  For every case this tool takes
the blob out of the sample, asks each registered decoder whether it opens the
blob, and records which ones do.  That is the label; the features are computed
from the bytes alone.  An averaged perceptron learns the mapping and writes
``src/pydecomp/learn/weights.py``.

    python3 tools/train_learn.py            # train, write weights, print metrics
    python3 tools/train_learn.py --check    # committed weights still reproduce?
    python3 tools/train_learn.py --json out.json

The two numbers that matter are printed together, because a model that cannot
beat the registry order is not worth shipping:

    order          top-1   mean attempts before the right decoder
    registry          ..%                  ..
    learned           ..%                  ..
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")
WEIGHTS = os.path.join(ROOT, "src", "pydecomp", "learn", "weights.py")
for path in (os.path.join(ROOT, "src"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)


def transforms():
    from pydecomp.decoders.registry import TRANSFORMS, _transform_allowed
    return TRANSFORMS, _transform_allowed


def opens(blob: bytes, name: str) -> bool:
    """Does this decoder take the blob somewhere a payload could be?"""
    from pydecomp.bytecode.magic import MAGIC_VERSIONS_BYTES
    from pydecomp.decoders.emoji import parses_as_python
    from pydecomp.decoders.registry import TRANSFORMS, _mostly_text, _transform_allowed
    if not _transform_allowed(name, blob):
        return False
    try:
        out = TRANSFORMS[name](blob)
    except Exception:                                # noqa: BLE001 - a decoder that throws does not open anything
        return False
    if not out or len(out) < 16 or len(out) >= len(blob) * 4:
        return False
    if out[:2] in MAGIC_VERSIONS_BYTES:
        return True
    if _mostly_text(out, 0.9):
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return parses_as_python(text)
    return False


def biggest_blob(source: str) -> bytes | None:
    """The cooked payload sitting in the sample, as bytes."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    best = b""
    for node in ast.walk(tree):
        value = None
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
            value = node.value
        if value is None:
            continue
        data = value if isinstance(value, bytes) else value.encode("utf-8", "surrogateescape")
        if len(data) > len(best):
            best = data
    return best or None


def gather() -> list[dict]:
    rows: list[dict] = []
    for family in sorted(os.listdir(CORPUS)):
        folder = os.path.join(CORPUS, family)
        if not os.path.isdir(folder):
            continue
        for case in sorted(os.listdir(folder)):
            sample = os.path.join(folder, case, "sample.py")
            if not os.path.isfile(sample):
                continue
            with open(sample, encoding="utf-8") as handle:
                blob = biggest_blob(handle.read())
            if blob is None:
                continue
            live = sorted(name for name in transforms()[0] if opens(blob, name))
            rows.append({"family": family, "case": case, "blob": blob, "live": live})
    return rows


def metrics(rows: list[dict], ordering: dict[str, list[str]]) -> dict:
    top1 = hits = 0
    attempts = 0
    graded = 0
    for row in rows:
        live = set(row["live"])
        blob = row["blob"]
        if not live:
            continue
        graded += 1
        best = None
        for position, name in enumerate(ordering["rank"](blob)):
            if name in live:
                best = position
                break
        if best is None:
            continue
        attempts += best + 1
        if best == 0:
            top1 += 1
            hits += 1
    return {"graded": graded, "top1": top1,
            "top1_rate": round(top1 / graded, 3) if graded else 0.0,
            "mean_attempts": round(attempts / graded, 2) if graded else 0.0}


def digest(rows: list[dict]) -> str:
    sha = hashlib.sha256()
    for row in rows:
        sha.update(row["family"].encode())
        sha.update(row["case"].encode())
        sha.update(hashlib.sha256(row["blob"]).digest())
        sha.update(",".join(row["live"]).encode())
    return sha.hexdigest()


def write_weights(weights: dict[str, list[int]], classes: list[str], code: str) -> None:
    lines = ['"""Generated by tools/train_learn.py - do not edit by hand.',
             "",
             "A one-vs-rest linear model over pydecomp.learn.features.  Trained on the",
             "corpus; retrain with `python3 tools/train_learn.py`.",
             '"""',
             "from __future__ import annotations",
             "",
             f"TRAINED_DIGEST = {code!r}",
             f"TRAINED_CLASSES = {tuple(classes)!r}",
             "",
             "TRAINED_WEIGHTS: dict[str, list[int]] = {"]
    for name in classes:
        lines.append(f"    {name!r}: {weights[name]},")
    lines.append("}")
    lines.append("")
    with open(WEIGHTS, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="train the decoder ranking")
    parser.add_argument("--check", action="store_true",
                        help="re-train and compare against the committed weights")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--epochs", type=int, default=80)
    args = parser.parse_args(argv[1:])

    if not os.path.isdir(CORPUS):
        print("no corpus: run python3 tools/make_corpus.py")
        return 2

    rows = gather()
    classes = list(transforms()[0])
    code = digest(rows)

    # Train on three of the four payload programs and measure on the fourth.
    # Training accuracy on the corpus it was trained on would say nothing about a
    # blob the model has never seen, and that is the only number that matters.
    holdout = "text"
    seen = [row for row in rows if row["case"] != holdout]
    unseen = [row for row in rows if row["case"] == holdout]

    from pydecomp.learn import model
    # what the *committed* weights do, measured before training touches anything
    committed = metrics(unseen, {"rank": lambda blob: model.rank(classes, blob)})
    weights = model.fit([(row["blob"], set(row["live"])) for row in seen], classes,
                        epochs=args.epochs)
    model.TRAINED_WEIGHTS = weights
    model.TRAINED_CLASSES = tuple(classes)

    registry = {"rank": lambda blob: classes}
    learned = {"rank": lambda blob: model.rank(classes, blob)}
    before = metrics(unseen, registry)
    after = metrics(unseen, learned)
    trained_on = metrics(seen, learned)

    report = {"cases": len(rows), "digest": code, "registry": before, "learned": after,
              "committed": committed, "train": trained_on, "holdout": holdout,
              "classes": classes}
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=1, sort_keys=True)
            handle.write("\n")

    print(f"{len(rows)} blob(s) from the corpus, {len(classes)} decoder class(es); "
          f"trained on {len(seen)}, held out {len(unseen)} (payload '{holdout}')")
    print(f"  {'order':<10}{'top-1':>8}{'mean attempts':>16}")
    for label, score in (("registry", before), ("learned", after)):
        print(f"  {label:<10}{score['top1_rate'] * 100:>7.1f}%{score['mean_attempts']:>16.2f}")
    print(f"  (learned on the payloads it trained on: "
          f"{trained_on['top1_rate'] * 100:.1f}%, {trained_on['mean_attempts']:.2f} attempts)")

    if args.check:
        if not os.path.isfile(WEIGHTS):
            print("no learned weights committed: run tools/train_learn.py")
            return 1
        from pydecomp.learn.weights import TRAINED_DIGEST
        if TRAINED_DIGEST != code:
            print(f"the corpus changed since the weights were trained "
                  f"({TRAINED_DIGEST[:12]}… != {code[:12]}…) — retrain")
            return 1
        if trained_on["top1"] < before["top1"]:
            print("retraining now would be worse than the registry order — "
                  "the committed weights are kept")
            return 1
        if committed["top1"] < before["top1"] or                 committed["mean_attempts"] > before["mean_attempts"]:
            print("the committed weights are worse than the registry order — retrain")
            return 1
        print(f"ok learned ranking {code[:12]}… held out '{holdout}': top-1 "
              f"{before['top1_rate'] * 100:.0f}% -> {committed['top1_rate'] * 100:.0f}%, "
              f"decodes before the right one "
              f"{before['mean_attempts']:.2f} -> {committed['mean_attempts']:.2f}")
        return 0

    write_weights(weights, classes, code)
    print(f"wrote {os.path.relpath(WEIGHTS, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
