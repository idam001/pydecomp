"""pydecomp - backends base.

A backend is anything that turns *bytes* into *text*.  This build ships one -
its own - and the interface is kept because the IR pipeline and the stack
simulator are two backends of the same project, and the stronger one wins on
evidence:

    name        how it is named in the proof
    supports()  which interpreter versions it claims
    available() whether this machine can run it right now
    decompile() -> text or None

The orchestrator decides which answer to keep, and it decides with evidence:
every candidate is graded by :func:`pydecomp.proof.tiers.compare` against the
original code object, so a backend that produces prettier but wrong source
loses to one that produces the same instructions.
"""
from __future__ import annotations


class Backend:
    """Interface every decompiler backend implements."""

    name = "backend"
    kind = "native"
    #: interpreter versions this backend claims, inclusive
    versions: tuple = ((1, 0), (3, 99))

    def supports(self, version: tuple) -> bool:
        low, high = self.versions
        return tuple(version[:2]) >= low and tuple(version[:2]) <= high

    def available(self) -> bool:                      # pragma: no cover - interface
        return True

    def decompile(self, data: bytes, version: tuple) -> str | None:   # pragma: no cover
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.name} ({'ready' if self.available() else 'not installed'})"
