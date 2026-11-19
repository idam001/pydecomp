"""Conservative map from recovered definitions to proof units and layer trace."""
from __future__ import annotations

import ast
import hashlib
import json
import os


def build(source: str, proof: dict, trace: list[str]) -> dict:
    """Map output spans to proof tiers, without inventing original offsets."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        tree = None
    tiers = {}
    for tier, names in proof.get("tiers", {}).items():
        for name in names:
            tiers[name] = tier
    definitions = []
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                definitions.append({"name": node.name,
                                    "kind": type(node).__name__,
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, "end_lineno", node.lineno),
                                    "proof_tier": tiers.get(node.name, "unmatched")})
    raw = source.encode("utf-8", "surrogateescape")
    return {
        "schema": "pydecomp-source-map-v1",
        "output_sha256": hashlib.sha256(raw).hexdigest(),
        "definitions": sorted(definitions,
                              key=lambda item: (item["start_line"], item["name"])),
        "recovery_stages": list(trace),
        "attribution_note": ("definition spans refer to recovered output lines; the stage list "
                             "is whole-module provenance, not a guessed per-line original offset"),
    }


def write(output_path: str, source: str, proof: dict, trace: list[str]) -> str:
    folder = os.path.dirname(os.path.abspath(output_path))
    stem = os.path.splitext(os.path.basename(output_path))[0]
    path = os.path.join(folder, stem + ".sourcemap.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build(source, proof, trace), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
