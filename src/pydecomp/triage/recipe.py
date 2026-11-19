"""Reproducible provenance receipt for a static recovery."""
from __future__ import annotations

import hashlib
import json
import os

from ..limits import __version__


def build(input_bytes: bytes, output_text: str, trace: list[str]) -> dict:
    """Build a path-free receipt; intermediate bytes are not retained by engine."""
    output = output_text.encode("utf-8", "surrogateescape")
    return {
        "schema": "pydecomp-recipe-v1",
        "tool": f"pydecomp {__version__}",
        "guarantee": "static-only; the sample and recovered output were not executed",
        "input": {"bytes": len(input_bytes),
                  "sha256": hashlib.sha256(input_bytes).hexdigest()},
        "output": {"bytes": len(output), "sha256": hashlib.sha256(output).hexdigest()},
        "steps": [{"index": index, "description": str(step)}
                  for index, step in enumerate(trace, 1)],
    }


def write(output_path: str, input_bytes: bytes, output_text: str,
          trace: list[str]) -> str:
    folder = os.path.dirname(os.path.abspath(output_path))
    stem = os.path.splitext(os.path.basename(output_path))[0]
    path = os.path.join(folder, stem + ".recipe.json")
    data = build(input_bytes, output_text, trace)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
