"""pydecomp - the decompiler pipeline.

There is one engine and it is this project's own: marshal/pyc reader -> code
object -> lifter (and, from this release, the SSA IR pipeline) -> source.  No
subprocess, no optional package, no `pip install` of somebody else's decompiler,
because the single-file build has to work on a phone with no network and no
site-packages.

`decompile()` returns the text, the name of the pipeline that produced it, and
the tier it was proven at.  `LAST` records the decision so the proof can carry it.

    >>> from pydecomp.bytecode.backends import route, decompile
    >>> route((3, 9))
    ['pydecomp.lift']
"""
from __future__ import annotations

from ..backends.base import Backend
from ..backends.native import NativeBackend

#: every interpreter version this build reads, by the same route
ROUTES = (((1, 0), (3, 99), ["pydecomp.lift"]),)

VERSION_RANGES = tuple((low, high) for low, high, _names in ROUTES)

#: what the last :func:`decompile` did, for the proof to quote
LAST: dict = {"version": None, "backend": None, "tier": None, "tried": [],
              "reason": ""}

_ORDER = {"perfect": 0, "semantic": 1, "structural": 2,
          "syntactic": 3, "unverified": 4}


def route(version: tuple) -> list[str]:
    """The pipeline names for *version*, best first. Always the same answer."""
    return ["pydecomp.lift"]


def pool() -> dict[str, Backend]:
    return {"pydecomp.lift": NativeBackend()}


def candidates(version: tuple) -> list[Backend]:
    return [pool()[name] for name in route(version) if name in pool()]


def decompile(data: bytes, version: tuple) -> tuple[str | None, str | None, str | None]:
    """Decompile *data* with the bundled pipeline; return (text, name, tier)."""
    from ...proof import tiers

    from ..marshal_reader import parse_marshal_blob

    # grade against the code object the data actually holds, not against nothing:
    # a pipeline that reproduces the instructions has proven more than one that
    # merely compiles
    original = None
    try:
        parsed = parse_marshal_blob(data)
        original = parsed[1] if isinstance(parsed, tuple) else parsed
    except Exception:                            # noqa: BLE001
        original = None
    tried = []
    best: tuple[str | None, str | None, str | None] = (None, None, None)
    best_key = None
    for backend in candidates(version):
        tried.append(backend.name)
        try:
            text = backend.decompile(data, version)
        except Exception:                        # noqa: BLE001 - a pipeline may fail
            text = None
        if not text:
            continue
        tier = "syntactic"
        try:
            tier = tiers.grade(text, original, version)
        except Exception:                        # noqa: BLE001
            pass
        key = (_ORDER.get(tier, 3), -len(text))
        if best_key is None or key < best_key:
            best, best_key = (text, backend.name, tier), key
    LAST.update({"version": tuple(version[:2]), "backend": best[1],
                 "tier": best[2], "tried": tried,
                 "reason": "bundled pipeline" if best[1] else "nothing produced text"})
    return best


__all__ = ["Backend", "LAST", "NativeBackend", "ROUTES", "VERSION_RANGES",
           "candidates", "decompile", "pool", "route"]
