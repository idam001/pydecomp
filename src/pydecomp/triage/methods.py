"""Recovery-method comparison: which engine answered, and how do they differ?

The same bytes usually have more than one honest answer — the SSA emitter, the
statement lifter, and (if the analyst ran it) an external method such as
PyLingual.  This module lines them up instead of asking a reader to trust the one
that got picked:

* :func:`engines` reports what pydecomp itself ran for this sample — the SSA
  report and the statement engine's verdict — with the tier each produced.
* :func:`against` compares the chosen recovery with another text (a `--legacy`
  run, a previous build, a PyLingual import) per function and per indicator.
* :func:`render` prints one table, so three candidates read as a table rather
  than three files.

Nothing here runs a sample.  A comparison is AST- and text-level only.
"""
from __future__ import annotations

from .compare import compare_text


def engines(lift_quality: dict | None) -> list[dict]:
    """The engines that took part, as rows: name, tier, detail."""
    quality = lift_quality or {}
    rows: list[dict] = []
    ir = quality.get("ir") or {}
    if ir:
        rows.append({"method": "ssa-ir", "tier": ir.get("tier") or "none",
                     "detail": ir.get("detail") or "",
                     "chosen": quality.get("engine") == "ssa-ir"})
    engine = quality.get("engine")
    if engine and engine != "ssa-ir":
        rows.append({"method": engine,
                     "tier": "proven" if quality.get("proven") else "unverified",
                     "detail": quality.get("error") or "",
                     "chosen": True})
    elif engine == "ssa-ir" and not ir:
        rows.append({"method": "ssa-ir", "tier": "proven" if quality.get("proven")
                     else "unverified", "detail": "", "chosen": True})
    if quality.get("error"):
        rows.append({"method": "error", "tier": "unverified",
                     "detail": str(quality["error"])[:200], "chosen": False})
    return rows


def against(own_source: str, other_source: str, other_name: str = "other") -> dict:
    """Compare the chosen recovery with a second method's answer."""
    return compare_text(own_source, other_source, "pydecomp", other_name)


def verdict(comparison: dict) -> str:
    """One sentence: which answer holds more, said without overclaiming."""
    functions = comparison.get("functions") or {}
    added = len(functions.get("added") or [])
    removed = len(functions.get("removed") or [])
    shared = len(functions.get("changed") or [])
    if comparison.get("same_text"):
        return "identical text — two independent methods agree"
    if added and not removed:
        return f"{_other(comparison)} has {added} definition(s) pydecomp does not"
    if removed and not added:
        return f"pydecomp has {removed} definition(s) {_other(comparison)} does not"
    return (f"same definitions, {shared} with a different body"
            if not added and not removed else
            f"{added} definition(s) only there, {removed} only here, "
            f"{shared} with a different body")


def _other(comparison: dict) -> str:
    name = str(comparison.get("right") or "the other method")
    return name.replace("_pylingual.py", " (PyLingual)").replace("_pylingual", " (PyLingual)")


def render(comparison: dict) -> list[str]:
    """The comparison as compact lines, for the console."""
    functions = comparison.get("functions") or {}
    lines = [f"pydecomp vs {comparison.get('right')}: {verdict(comparison)}"]
    for label in ("added", "removed", "changed"):
        names = functions.get(label) or []
        if names:
            lines.append(f"  functions {label}: {', '.join(names[:12])}"
                         + (" …" if len(names) > 12 else ""))
    iocs = comparison.get("iocs") or {}
    for kind, delta in sorted(iocs.items()):
        for side in ("added", "removed"):
            values = delta.get(side) or []
            if values:
                lines.append(f"  {kind} {side}: {', '.join(values[:6])}")
    return lines
