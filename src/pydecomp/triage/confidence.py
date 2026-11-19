"""Per-function confidence, and hints for the shapes the lifter could not open.

A proof tier is per *unit*: the module may be `semantic` overall and still hold a
function that was only `syntactic`.  ``per_function`` reads the proof the run
already produced and marks every recovered definition with its own tier, so a
reader can see *which* function to trust instead of averaging the module.

``hints`` answers the other half of the question.  When a construct stops the
lifter, the recovered text carries a `# pydecomp: unsupported ...` note; the same
information is collected here as advice an analyst can act on: another engine,
another method, or the exact construct to reproduce by hand.  Hints are drawn
from the text and the run's own records - nothing is guessed about a payload.
"""
from __future__ import annotations

import ast
import re

#: `# pydecomp: unsupported CALL_FUNCTION_EX (line 12)` and friends
_NOTE = re.compile(r"pydecomp:\s*(unsupported[^\n]*)", re.IGNORECASE)

#: construct -> what to do about it.  Keys are matched loosely (substring).
ADVICE = {
    "MAKE_FUNCTION": "nested function shape — try --legacy, which lifts the statement flow directly",
    "CALL_FUNCTION_EX": "star-call — recover the call by hand; the emitter cannot express **kwargs here",
    "GEN_START": "generator body — read the yielded values from the disassembly (--disassemble)",
    "YIELD_FROM": "`yield from` — lift the inner iterable as its own unit",
    "MATCH_": "structural pattern matching — the emitter has no match statement; read the cases",
    "WITH_EXCEPT_START": "exception-group handling — keep the original try/except shape",
    "BEFORE_ASYNC_WITH": "async context manager — the awaits are preserved, the ordering is not proven",
    "LOAD_BUILD_CLASS": "class body built at runtime — check the class attributes from the names table",
    "IMPORT_STAR": "`from x import *` — the names table lists what it bound",
    "SETUP_FINALLY": "pre-3.11 block shape — rerun with the version matching the sample",
    "EXTENDED_ARG": "argument wider than one byte — truncated operand, read the raw bytes",
    "sealed": "the payload is encrypted — this is the loader; key material is not in the file",
    "encrypted": "the payload is encrypted — this is the loader; key material is not in the file",
}


def _tiers(proof: dict) -> dict[str, str]:
    tiers: dict[str, str] = {}
    for tier, names in (proof.get("tiers") or {}).items():
        for name in names:
            tiers.setdefault(name, tier)
    return tiers


def per_function(source: str, proof: dict, overall: str | None = None) -> list[dict]:
    """Every definition in the recovered source with its own proof tier.

    A unit the proof did not grade separately inherits the module's tier and says
    so — that is the honest reading, since the module body was compiled and
    compared as a whole.  ``overall`` is the proof's own ``worst`` tier.
    """
    tiers = _tiers(proof)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return []
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        tier = tiers.get(node.name)
        rows.append({
            "name": node.name,
            "kind": "class" if isinstance(node, ast.ClassDef) else "function",
            "lines": [node.lineno, getattr(node, "end_lineno", node.lineno)],
            "tier": tier or overall or "unmatched",
            "detail": ((proof.get("evidence") or {}).get(f"{node.name}:{tier}", "") if tier
                       else "not graded on its own; inherits the module tier"),
        })
    return sorted(rows, key=lambda row: (row["lines"][0], row["name"]))


def overall_tier(proof: dict) -> str:
    """The proof's own weakest tier, from its tier table."""
    for tier in ("unverified", "syntactic", "structural", "semantic", "perfect"):
        if (proof.get("tiers") or {}).get(tier):
            return tier
    return "unverified"


def render_functions(source: str, proof: dict) -> list[str]:
    rows = per_function(source, proof, overall_tier(proof))
    if not rows:
        return ["no definitions in the recovered source"]
    out = [f"{'tier':<12}{'kind':<10}{'lines':<12}name"]
    for row in rows:
        lines = f"{row['lines'][0]}-{row['lines'][1]}"
        out.append(f"{row['tier']:<12}{row['kind']:<10}{lines:<12}{row['name']}")
    return out


def hints(source: str, trace: list[str] | None = None,
          records: list[str] | None = None) -> list[str]:
    """Actionable advice for whatever the run could not open.

    ``trace`` is the layer trace, ``records`` the engine's own notes (the
    lift-quality detail, the IR report, a stall reason).  Nothing is inferred
    about a payload: every hint is keyed to something the run actually wrote.
    """
    found: list[str] = []
    seen: set[str] = set()
    noted = False

    def add(key: str, advice: str, construct: str = "") -> None:
        if key in seen:
            return
        seen.add(key)
        if construct and construct not in advice:
            advice = f"{advice} [{construct}]"
        found.append(advice)

    lines = source.splitlines() if source else []
    for line in lines:
        match = _NOTE.search(line)
        if not match:
            continue
        note = match.group(1).strip()
        noted = True
        for key, advice in ADVICE.items():
            if key.lower() in note.lower():
                add(key, advice, key)
                break
        else:
            add(note, f"unsupported construct reported: {note[:160]}")
    joined = " ".join([*(trace or []), *(records or [])])
    for key, advice in ADVICE.items():
        if key in joined:
            add(key, advice)
    lowered = joined.lower()
    for key in ("sealed", "encrypted"):
        if key in lowered:
            add(key, ADVICE[key])
    if not found:
        return []
    if noted:
        found.append("run --disassemble on a .pyc to see the instruction the lifter stopped on")
        found.append("or run --legacy, which lifts the statement flow without the SSA pass")
    return found
