"""pydecomp - save."""
from __future__ import annotations

import os

from ..output.paths import phone_dir, unique_path

def save(text: str, src_path: str, out_dir: str | None = None,
         suffix: str = "deob") -> str:
    if out_dir:
        folder = out_dir
        os.makedirs(folder, exist_ok=True)
    else:
        folder = (phone_dir() or os.path.dirname(os.path.abspath(src_path))
                  or os.getcwd())
    stem = os.path.splitext(os.path.basename(src_path))[0] or "sample"
    path = unique_path(folder, stem, suffix)
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)
    return path
