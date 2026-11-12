"""pydecomp.protectors - named-protector front ends.

Each backend answers two questions: *is this mine* (:func:`detect`) and *what
does static recovery from it look like* (:func:`unpack`).  A backend that
cannot finish never fails the run - it returns what it proved and says what it
would need.
"""
from __future__ import annotations

from ..protectors import nuitka, pyarmor

BACKENDS = (pyarmor, nuitka)


def identify(data: bytes, head: str = "") -> str | None:
    """The protector this input came from, or ``None``."""
    for backend in BACKENDS:
        try:
            if backend.detect(data) or (head and backend.detect_source(head)):
                return backend.NAME
        except Exception:                            # noqa: BLE001 - detection is advisory
            continue
    return None


__all__ = ["BACKENDS", "identify", "nuitka", "pyarmor"]
