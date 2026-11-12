"""pydecomp - orchestrator.

Which backend's answer is kept?  Not the first one that returns text: the one
that comes closest to the *original instructions*.  Each candidate is graded
with :func:`pydecomp.proof.tiers.compare`, and the strongest tier wins; ties go
to the longer text, then to the earlier backend in the route.

The decision is recorded in :data:`LAST`, which the proof reads, so an output
file always says which backend made it and why it was preferred.
"""
from __future__ import annotations

from ..backends.base import Backend
from ..magic import parse_pyc
from ..marshal_reader import parse_marshal_blob

#: version -> backends worth trying, best first
ROUTES = (
    ((1, 0), (3, 8), ["uncompyle6", "decompyle3", "pydecomp.lift"]),
    ((3, 9), (3, 10), ["decompyle3", "pydecomp.lift"]),
    ((3, 11), (3, 13), ["pydecomp.lift", "pycdc-rs", "depyo", "pycdc"]),
    ((3, 14), (3, 15), ["pycdc-rs", "depyo", "pydecomp.lift", "pycdc"]),
)

LAST: dict = {"version": None, "backend": None, "tier": None, "tried": [],
              "reason": ""}

_ORDER = {"semantic": 0, "structural": 1, "syntactic": 2, "unverified": 3}


def route(version: tuple) -> list[str]:
    """Backend names to try for *version*, best first."""
    version = tuple(version[:2])
    for low, high, names in ROUTES:
        if low <= version <= high:
            return list(names)
    return ["pydecomp.lift"]


def pool() -> dict[str, Backend]:
    """Every backend known to this build, by name, without importing extras."""
    from ..backends.external import TOOLS, ExternalBackend
    from ..backends.native import NativeBackend
    known: dict[str, Backend] = {"pydecomp.lift": NativeBackend()}
    for name in TOOLS:
        known[name] = ExternalBackend(name)
    return known


def candidates(version: tuple) -> list[Backend]:
    """The backends to actually run: routed, available and installed."""
    known = pool()
    out = []
    for name in route(version):
        backend = known.get(name)
        if backend is None:
            continue
        try:
            if backend.available():
                out.append(backend)
        except Exception:                            # noqa: BLE001 - optional tool
            continue
    if not out:
        out = [known["pydecomp.lift"]]
    return out


def _grade(text: str, code, version: tuple) -> tuple:
    from ...proof.tiers import compare
    graded = compare(text, code, version)
    return _ORDER.get(graded["tier"], 9), graded["tier"], graded["detail"]


def decompile(data: bytes, version: tuple, code=None):
    """Best ``(text, backend, tier)`` for these bytes, or ``(None, None, None)``."""
    if code is None:
        _version, code = parse_pyc(data)
    if code is None:
        _version, code, _consumed = parse_marshal_blob(data)
    best = (None, None, None)
    tried = []
    for backend in candidates(version):
        try:
            text = backend.decompile(data, version)
        except Exception:                            # noqa: BLE001 - a backend may fail
            text = None
        tried.append(backend.name)
        if not text:
            continue
        rank, tier, detail = _grade(text, code, version)
        if best[0] is None or rank < best[3]:
            best = (text, backend.name, tier, rank, detail)
    LAST.update({"version": tuple(version[:2]) if version else None,
                 "backend": best[1], "tier": best[2], "tried": tried,
                 "reason": best[4] if len(best) > 4 else ""})
    if best[0] is None:
        return None, None, None
    return best[0], best[1], best[2]


def try_upgrade(data: bytes, code, version: tuple, native_text: str | None) -> str | None:
    """A better text than *native_text*, or ``None`` when the native one holds.

    Only an installed external backend can change the answer, and only when its
    output grades strictly stronger.  Without one this returns immediately, so
    the single-file build behaves exactly as before.
    """
    try:
        externals = [backend for backend in candidates(version)
                     if backend.kind == "external"]
    except Exception:                                # noqa: BLE001
        return None
    if not externals:
        return None
    base_rank = _ORDER["unverified"]
    if native_text:
        base_rank = _grade(native_text, code, version)[0]
    for backend in externals:
        try:
            text = backend.decompile(data, version)
        except Exception:                            # noqa: BLE001
            continue
        if not text:
            continue
        rank, tier, detail = _grade(text, code, version)
        if rank < base_rank:
            LAST.update({"version": tuple(version[:2]), "backend": backend.name,
                         "tier": tier, "tried": [backend.name], "reason": detail})
            return text
    return None
