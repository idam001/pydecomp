"""pydecomp - sentinel."""
from __future__ import annotations

from ..exceptions import _ExprCaptured, _ExprRefuse

class _ExecSentinel:
    """Stand-in for ``exec``/``eval``: being *called* is the capture point.

    A real builtin here would run the sample.  Every path that can reach one -
    direct name, ``globals()['exec']``, ``__builtins__``, a list or dict table,
    ``functools.partial``, ``map`` - is funnelled into this object instead, so
    the payload lands in the analyser and nowhere else.
    """

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __call__(self, *args, **kwargs):
        raise _ExprCaptured(args[0] if args else None)

    def __repr__(self) -> str:
        return f"<pydecomp {self.name}>"

    def __getattr__(self, item):
        raise _ExprRefuse(f"attribute {item} on {self.name}")

_EXEC_SENTINELS = {"exec": _ExecSentinel("exec"), "eval": _ExecSentinel("eval")}
