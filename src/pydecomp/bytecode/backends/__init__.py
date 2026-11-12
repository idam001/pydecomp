"""pydecomp.backends - decompiler backends and the orchestrator.

    >>> from pydecomp.bytecode.backends import route, candidates, decompile
    >>> route((3, 9))
    ['decompyle3', 'pydecomp.lift']

`route()` is pure: it says which backends *should* handle a version.  The
orchestrator then drops the ones this machine cannot run, grades what comes
back, and keeps the best - recording why in `LAST`, which the proof reads.
"""
from __future__ import annotations

from ..backends.base import Backend
from ..backends.native import NativeBackend
from ..backends.orchestrator import (LAST, ROUTES, candidates, decompile,
                                              pool, route, try_upgrade)

VERSION_RANGES = tuple((low, high) for low, high, _names in ROUTES)

__all__ = ["Backend", "LAST", "NativeBackend", "ROUTES", "VERSION_RANGES",
           "candidates", "decompile", "pool", "route", "try_upgrade"]
