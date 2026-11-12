"""pydecomp - write.

Two side files per recovered artifact::

    sample_deob.py          the source
    sample_deob.proof.json  the machine-checkable proof
    sample_deob.proof.md    the same proof, readable

Nothing here can fail a run: a proof that cannot be written is reported in the
return dict, never raised into the middle of a recovery.
"""
from __future__ import annotations

import json
import os

from ..proof.model import Proof


def paths_for(output_path: str) -> tuple[str, str]:
    folder = os.path.dirname(os.path.abspath(output_path))
    stem = os.path.splitext(os.path.basename(output_path))[0]
    return (os.path.join(folder, stem + ".proof.json"),
            os.path.join(folder, stem + ".proof.md"))


def write(proof: Proof, output_path: str) -> dict:
    """Write ``.proof.json`` and ``.proof.md`` beside *output_path*."""
    written: dict = {}
    if not proof.output:
        proof.output = {"name": os.path.basename(output_path)}
    json_path, md_path = paths_for(output_path)
    try:
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(proof.as_dict(), handle, indent=2, sort_keys=True)
        written["proof_json"] = json_path
    except (OSError, TypeError, ValueError):
        pass
    try:
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write(proof.markdown())
        written["proof_md"] = md_path
    except OSError:
        pass
    return written


def failure(proof: Proof, require: str = "semantic") -> str | None:
    """``None`` when *proof* meets *require*, else the reason it does not."""
    order = ("semantic", "structural", "syntactic", "unverified")
    worst = proof.worst
    if order.index(worst) <= order.index(require):
        return None
    counts = proof.counts
    return (f"strict: {worst} output ({counts['semantic']} proven, "
            f"{counts['structural']} structural, {counts['syntactic']} syntactic, "
            f"{counts['unverified']} unverified) - nothing written")
