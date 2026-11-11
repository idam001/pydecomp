"""pydecomp - paths."""
from __future__ import annotations

import os


def phone_dir() -> str | None:
    """First *existing* writable Android/Termux download folder, else None.

    Nothing is created here: a missing /sdcard means storage access was never
    granted (Termux: `termux-setup-storage`), so we fall back instead of
    inventing directories on the user's filesystem.
    """
    candidates: list[str] = []
    ext = os.environ.get("EXTERNAL_STORAGE", "").strip().rstrip("/")
    if ext:
        if os.path.basename(ext) == "Download":
            candidates.append(ext)
        else:
            candidates.append(os.path.join(ext, "Download"))
            candidates.append(ext)
    candidates += [
        "/sdcard/Download",
        "/storage/emulated/0/Download",
        os.path.expanduser("~/storage/downloads"),
        "/sdcard",
    ]
    for cand in candidates:
        if cand and os.path.isdir(cand) and os.access(cand, os.W_OK):
            return cand
    return None

def unique_path(folder: str, stem: str) -> str:
    path = os.path.join(folder, f"{stem}_deob.py")
    n = 2
    while os.path.exists(path):
        path = os.path.join(folder, f"{stem}_deob_{n}.py")
        n += 1
    return path
