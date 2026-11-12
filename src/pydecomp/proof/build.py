"""pydecomp - build.

Turn one run's evidence into a :class:`~pydecomp.proof.model.Proof`.  The run
loop knows the trace, the fidelity verdict and the cleaning notes; this module
knows how those map onto the proof schema, so the schema stays in one place.
"""
from __future__ import annotations

import re

from ..limits import __version__
from ..proof.model import Proof, TIER_PREFIX
from ..proof.tiers import compare

_LAYER = re.compile(r"layer (\d+):\s*(.+)")
_ARROW = re.compile(r"^(.*?)\s*(?:→|->)\s*(.+)$")


def _split_chain(text: str) -> list[str]:
    """``base64 → zlib`` is two layers, not one."""
    parts = [part.strip() for part in re.split(r"\s*(?:→|->|\+)\s*", text)]
    return [part for part in parts if part]


def _layers_from_trace(trace: list[str]) -> list[tuple[str, str, str]]:
    """(transform, backend, detail) for each transformation the engine logged."""
    out: list[tuple[str, str, str]] = []
    for line in trace:
        found = _LAYER.match(str(line).strip())
        body = found.group(2) if found else str(line).strip()
        arrow = _ARROW.match(body)
        if arrow:
            left = arrow.group(1).strip()
            right = arrow.group(2).strip()
            left = re.sub(r"^(constant blob .*?|layer \d+)\s*", "", left)
            for step in _split_chain(left):
                out.append((step, "", ""))
            out.append(("decode", "", right))
            continue
        lowered = body.lower()
        if lowered.startswith("code object") or "marshal" in lowered:
            out.append(("parse code object", "bytecode.marshal_reader", body))
        elif "carved" in lowered:
            out.append(("carve", "engine.carve", body))
        elif lowered.startswith("inline integer stream"):
            out.append(("integer stream", "engine.dig", body))
    return out


def build(text: str, *, name: str, digest: str, size: int, kind: str,
          trace: list[str], reports: dict | None = None,
          notes: list[str] | None = None,
          backend: str | None = None,
          version: tuple | None = None,
          identity: bool = False) -> Proof:
    """Assemble the proof for one recovered file."""
    proof = Proof(f"pydecomp {__version__}", name, digest, size, kind)
    for transform, layer_backend, detail in _layers_from_trace(trace):
        proof.add_layer(transform, layer_backend, detail=detail)

    graded = ("identity" if identity else compare(text, None, version))
    if identity:
        proof.add_layer("none - input is the source", "engine.dig",
                        detail="byte-identical to the input")
        proof.mark("<module>", "semantic", "byte-identical to the input source")
    else:
        proof.add_layer("lift to source",
                        backend or "pydecomp.lift",
                        verified=graded["tier"] == "semantic",
                        target=(f"CPython {version[0]}.{version[1]}" if version else None),
                        detail=graded["detail"])
        for unit, (tier, detail) in graded["units"].items():
            proof.mark(unit, tier, detail)
    tier_now = "semantic" if identity else graded["tier"]
    if tier_now != "semantic":
        proof.infer("whole module",
                    "statement and expression boundaries were rebuilt from the "
                    "instruction stream", 0.85 if tier_now == "structural" else 0.6)
    for note in notes or []:
        low = note.lower()
        if "rename" in low or "fold" in low or "dead" in low:
            proof.infer("cleaned identifiers", note, 0.9)
        elif "opaque" in low or "predicate" in low:
            proof.infer("guarded branches", note, 0.95)
    proof.lose("comments - the bytecode does not carry them")
    proof.lose("source formatting, blank lines and quote style")
    if tier_now != "semantic":
        proof.lose("exact statement boundaries where the lifter had to choose")
    if kind == "strings":
        proof.lose("the program itself - only printable strings survived")
    if reports:
        fidelity = reports.get("fidelity") or {}
        if fidelity.get("kept") == "unverified":
            proof.notes.append("fidelity: " + str(fidelity.get("reason", "")))
        if reports.get("recovered", {}).get("complete") is False:
            proof.notes.append("payload sealed: the output is the loader, "
                               "not the program it would run")
    return proof


def prefix_for(proof: Proof) -> str:
    """The warning header a non-semantic file must carry (empty when proven)."""
    tier = proof.worst
    return "" if tier == "semantic" else TIER_PREFIX.get(tier, "")
