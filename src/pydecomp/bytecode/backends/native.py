"""pydecomp - native backend.

The bundled pipeline: marshal reader -> code object -> lifter.  It is the
default for every version the tool supports, and it never needs a subprocess,
a network or an installed package, which is why the single-file build keeps
working on a phone.
"""
from __future__ import annotations

from ..backends.base import Backend
from ..magic import parse_pyc
from ..marshal_reader import parse_marshal_blob


class NativeBackend(Backend):
    name = "pydecomp.lift"
    kind = "native"
    versions = ((3, 0), (3, 99))

    def decompile(self, data: bytes, version: tuple) -> str | None:
        from ...lift.module import lift_module
        _version, code = parse_pyc(data)
        if code is None:
            _version, code, _consumed = parse_marshal_blob(data)
        if code is None:
            return None
        try:
            text = lift_module(code, tuple(version[:2]) if version else (3, 13))
        except Exception:                            # noqa: BLE001 - a backend may fail
            return None
        return text or None
