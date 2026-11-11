"""pydecomp - rot13."""
from __future__ import annotations


def _rot13_strict(blob: bytes) -> bytes:
    text = blob.decode("ascii")
    letters = sum(c.isalpha() for c in text)
    if letters / max(len(text), 1) < 0.85:
        raise ValueError("not rot13")
    return text.encode("rot13")
