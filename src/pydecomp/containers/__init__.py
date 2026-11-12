"""pydecomp.containers - freezer readers.

Order matters: the formats that carry a signature are tried before the ones
that guess from contents, and ``pyinstaller`` is first because its cookie is
unmistakable.  A reader that claims the bytes and returns nothing is a bug, not
a fallback: :func:`unpack` reports it instead of silently producing nothing.
"""
from __future__ import annotations

from ..containers.base import FreezerReader, zip_entries
from ..containers.pyinstaller import PyInstaller2Reader, PyInstallerReader
from ..containers.zipfreezers import (BriefcaseReader, CxFreezeReader, PexReader,
                                      Py2ExeReader, ShivReader)

READERS = (PyInstallerReader(), PyInstaller2Reader(), PexReader(), ShivReader(),
           BriefcaseReader(), Py2ExeReader(), CxFreezeReader())

#: names for the report
NAMES = tuple(reader.name for reader in READERS)


def match(data: bytes) -> FreezerReader | None:
    """The first reader that claims these bytes."""
    for reader in READERS:
        try:
            if reader.detect(data):
                return reader
        except Exception:                            # noqa: BLE001 - detection is advisory
            continue
    return None


def unpack(data: bytes, limit: int = 220) -> tuple[str, list[tuple[str, bytes]]]:
    """``(reader name, members)`` for a freezer, or ``("", [])``."""
    reader = match(data)
    if reader is None:
        return "", []
    try:
        members = reader.extract(data)
    except Exception:                                # noqa: BLE001 - never fail a run
        return reader.name, []
    return reader.name, members[:limit]


__all__ = ["FreezerReader", "NAMES", "READERS", "match", "unpack", "zip_entries"]
