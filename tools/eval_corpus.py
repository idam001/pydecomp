#!/usr/bin/env python3
"""Measure pydecomp against its own corpus, family by family.

For every case in ``corpus/``: run the analyser, read what it wrote, and compare
that against the payload the corpus says is inside.  The comparison is on
behaviour-bearing tokens (names, strings, numbers, keywords) plus "does it
compile", because a recovered program that cannot be parsed is not recovered.

    python3 tools/eval_corpus.py                  # full run, table to stdout
    python3 tools/eval_corpus.py --json eval.json # machine-readable
    python3 tools/eval_corpus.py --md eval.md     # the leaderboard file
    python3 tools/eval_corpus.py --family r_mix_four --verbose

Exit code is 0 whatever the score: this is an instrument, not a gate.  The gate
that fails on a regression is ``tools/run_gates.py corpus``.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")
for path in (os.path.join(ROOT, "src"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

KEYWORDS = {"def", "class", "return", "import", "for", "while", "if", "else", "elif",
            "try", "except", "finally", "with", "lambda", "yield", "raise", "assert",
            "global", "nonlocal", "pass", "break", "continue", "del", "in", "not",
            "and", "or", "is", "None", "True", "False", "self"}


def tokens(text: str) -> set[str]:
    """The tokens a reader would call the program: names, strings, numbers."""
    found: set[str] = set()
    try:
        for item in tokenize.generate_tokens(io.StringIO(text).readline):
            if item.type == tokenize.NAME:
                found.add(item.string)
            elif item.type == tokenize.STRING:
                # compare what a string *means*, not how it is spelled: r'\b'
                # and '\\b' are the same program, and so are "x" and 'x'
                try:
                    found.add(repr(ast.literal_eval(item.string)))
                except (ValueError, SyntaxError):
                    found.add(item.string.strip("'\""))
            elif item.type == tokenize.NUMBER:
                found.add(item.string)
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        pass
    return {item for item in found if item and item not in KEYWORDS}


def compiles(text: str) -> bool:
    try:
        ast.parse(text)
    except SyntaxError:
        return False
    return True


def recall(payload: str, recovered: str) -> float:
    """What share of the payload's own tokens survived, weighted the same."""
    want = tokens(payload)
    if not want:
        return 0.0
    return len(want & tokens(recovered)) / len(want)


def evaluate_case(folder: str) -> dict:
    truth = json.load(open(os.path.join(folder, "truth.json"), encoding="utf-8"))
    source = os.path.join(folder, "sample.py")
    payload = open(os.path.join(folder, "payload.py"), encoding="utf-8").read()
    source_text = open(source, encoding="utf-8").read()
    out = tempfile.mkdtemp(prefix="eval-")
    started = time.time()
    from pydecomp.engine.run import deobfuscate
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            written = deobfuscate(source, out, clean=False, reports=False)
        error = None
    except Exception as exc:                          # noqa: BLE001 - one case must not
        written, error = None, f"{type(exc).__name__}: {exc}"
    elapsed = time.time() - started

    recovered = ""
    if written and os.path.isfile(written):
        recovered = open(written, encoding="utf-8", errors="surrogateescape").read()
    proof = None
    for name in sorted(os.listdir(out)) if os.path.isdir(out) else []:
        if name.endswith(".proof.json"):
            proof = json.load(open(os.path.join(out, name), encoding="utf-8"))
    tiers = (proof or {}).get("tiers") or {}
    layers = []
    for entry in (proof or {}).get("layers") or []:
        if isinstance(entry, dict):
            layers.append(entry.get("layer") or entry.get("backend") or "?")
        else:
            layers.append(str(entry))

    score = recall(payload, recovered)
    parsed = compiles(recovered)
    good = score >= 0.90 and parsed
    refused = truth["expect"] == "refuse"
    return {
        "family": truth["family"],
        "payload": truth["payload"],
        "expect": truth["expect"],
        "recall": round(score, 3),
        "compiles": parsed,
        "recovered": bool(recovered.strip()),
        # a refusal is only correct if nothing was invented: no payload tokens,
        # and no token the input did not already carry
        "correct": (score == 0.0 and tokens(recovered) <= tokens(source_text))
        if refused else good,
        "partial": (not refused) and parsed and 0.5 <= score < 0.9,
        "seconds": round(elapsed, 3),
        "layers_found": layers,
        "tiers": {key: len(value) for key, value in tiers.items()},
        "error": error,
    }


def collect(families: list[str] | None = None) -> list[dict]:
    rows: list[dict] = []
    for family in sorted(os.listdir(CORPUS)):
        folder = os.path.join(CORPUS, family)
        if not os.path.isdir(folder) or (families and family not in families):
            continue
        for case in sorted(os.listdir(folder)):
            case_folder = os.path.join(folder, case)
            if os.path.isfile(os.path.join(case_folder, "truth.json")):
                rows.append(evaluate_case(case_folder))
    return rows


def summarise(rows: list[dict]) -> dict:
    families: dict[str, dict] = {}
    for row in rows:
        entry = families.setdefault(row["family"], {"cases": 0, "correct": 0,
                                                    "partial": 0, "recall": 0.0,
                                                    "seconds": 0.0})
        entry["cases"] += 1
        entry["correct"] += 1 if row["correct"] else 0
        entry["partial"] += 1 if row["partial"] else 0
        entry["recall"] += row["recall"]
        entry["seconds"] += row["seconds"]
    for entry in families.values():
        entry["recall"] = round(entry["recall"] / entry["cases"], 3)
        entry["seconds"] = round(entry["seconds"], 2)
        entry["rate"] = round(entry["correct"] / entry["cases"], 3)
    total = len(rows)
    correct = sum(1 for row in rows if row["correct"])
    return {
        "cases": total,
        "correct": correct,
        "rate": round(correct / total, 3) if total else 0.0,
        "partial": sum(1 for row in rows if row["partial"]),
        "recall": round(sum(row["recall"] for row in rows) / total, 3) if total else 0.0,
        "seconds": round(sum(row["seconds"] for row in rows), 2),
        "families": families,
    }


def table(summary: dict) -> str:
    lines = ["family             cases  recovered   recall   seconds",
             "---------------------------------------------------------"]
    for name in sorted(summary["families"]):
        entry = summary["families"][name]
        bar = "x" * int(round(entry["rate"] * 10))
        lines.append(f"{name:<17} {entry['cases']:>5}  {entry['correct']}/{entry['cases']:<7} "
                     f"{entry['recall']:>6.2f}   {entry['seconds']:>6.2f}  {bar}")
    lines.append("---------------------------------------------------------")
    lines.append(f"{'all':<17} {summary['cases']:>5}  {summary['correct']}/{summary['cases']:<7} "
                 f"{summary['recall']:>6.2f}   {summary['seconds']:>6.2f}")
    return "\n".join(lines)


def markdown(summary: dict) -> str:
    lines = ["# pydecomp on its own corpus", "",
             f"{summary['correct']}/{summary['cases']} cases recovered "
             f"({summary['rate'] * 100:.1f}%), mean token recall "
             f"{summary['recall'] * 100:.1f}%, {summary['seconds']}s total.", "",
             "| family | cases | recovered | recall | seconds |",
             "|---|---|---|---|---|"]
    for name in sorted(summary["families"]):
        entry = summary["families"][name]
        lines.append(f"| `{name}` | {entry['cases']} | {entry['correct']}/{entry['cases']} | "
                     f"{entry['recall'] * 100:.0f}% | {entry['seconds']} |")
    lines.append("")
    lines.append("Generated by `tools/eval_corpus.py --md`. A case counts as recovered when the "
                 "written file compiles and keeps at least 90% of the payload's tokens.")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="measure against the corpus")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--md", dest="md_out")
    parser.add_argument("--family", action="append")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv[1:])

    if not os.path.isdir(CORPUS):
        print("no corpus: run python3 tools/make_corpus.py")
        return 2
    rows = collect(args.family)
    summary = summarise(rows)
    # --md/--json are outputs, not conversation: write them even in gate mode,
    # otherwise `--quiet --md docs/…` silently leaves a stale table behind
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump({"summary": summary, "cases": rows}, handle, indent=1, sort_keys=True)
            handle.write("\n")
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as handle:
            handle.write(markdown(summary))
    if args.quiet:
        # gate mode: say one thing, and fail when a case that used to be
        # recovered is not recovered any more
        misses = [row for row in rows if not row["correct"]]
        if misses:
            print(f"FAIL corpus {summary['correct']}/{summary['cases']} recovered")
            for row in misses[:8]:
                print(f"  {row['family']}/{row['payload']}: recall {row['recall']:.2f}")
            return 4
        print(f"ok corpus {summary['correct']}/{summary['cases']} cases recovered "
              f"({summary['rate'] * 100:.0f}%), {summary['seconds']}s")
        return 0
    if not args.quiet:
        print(table(summary))
        misses = [row for row in rows if not row["correct"]]
        if misses and args.verbose:
            print()
            for row in misses[:20]:
                detail = row["error"] or f"recall {row['recall']:.2f} compiles={row['compiles']}"
                print(f"  miss {row['family']}/{row['payload']}: {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
