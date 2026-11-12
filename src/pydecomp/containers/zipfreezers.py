"""pydecomp - zip-based freezers.

Five freezers put their program in a zip with a signature the tool can check
before it agrees to unpack:

* **shiv** - a zipapp: ``_bootstrap/`` plus ``site-packages/`` and a ``.shiv``
  marker;
* **pex** - a zip with ``PEX-INFO`` (JSON) beside ``.deps/`` and the wheels;
* **briefcase** - ``*.dist-info/`` plus an ``app_packages/`` tree;
* **cx_Freeze** - ``library.zip`` (often inside a ``lib/``) of ``.pyc`` modules;
* **py2exe** - the same ``library.zip``, embedded in a PE image instead.

All five are read the same way - claim the bytes, list the Python members,
hand the bytes to the engine - and each module exists so a new format is a new
file rather than another branch in a dispatcher.
"""
from __future__ import annotations

from ..containers.base import FreezerReader, zip_entries


class ShivReader(FreezerReader):
    name = "shiv"
    suffixes = (".py", ".pyc")

    def detect(self, data: bytes) -> bool:
        names = zip_entries(data)
        if not names:
            return False
        joined = "\n".join(names)
        return "_bootstrap/" in joined and ("site-packages/" in joined or ".shiv" in joined)

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        return self._from_zip(data, lambda name: "site-packages/" in name or
                              not name.startswith("_bootstrap/"))


class PexReader(FreezerReader):
    name = "pex"
    suffixes = (".py", ".pyc")

    def detect(self, data: bytes) -> bool:
        names = zip_entries(data)
        return any(name == "PEX-INFO" or name.endswith("/PEX-INFO") for name in names)

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        return self._from_zip(data, lambda name: not name.startswith(".bootstrap/"))


class BriefcaseReader(FreezerReader):
    name = "briefcase"
    suffixes = (".py", ".pyc")

    def detect(self, data: bytes) -> bool:
        names = zip_entries(data)
        if not names:
            return False
        return (any(name.endswith(".dist-info/METADATA") for name in names)
                and any(name.startswith(("app_packages/", "app/")) for name in names)
                and any("briefcase" in name.lower() for name in names))

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        return self._from_zip(data, lambda name: name.startswith(("app_packages/", "app/")))


class CxFreezeReader(FreezerReader):
    name = "cx_freeze"
    suffixes = (".pyc", ".py")

    def detect(self, data: bytes) -> bool:
        names = zip_entries(data)
        if not names:
            return False
        if any(name.endswith("library.zip") for name in names):
            return True
        # a bare library.zip: mostly .pyc, no package metadata
        pycs = [name for name in names if name.endswith(".pyc")]
        return len(pycs) >= 3 and len(pycs) * 2 >= len(names)

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        members = self._from_zip(data)
        if members:
            return members
        nested = _embedded_zip(data, "library.zip")
        return self._from_zip(nested) if nested else []


class Py2ExeReader(FreezerReader):
    name = "py2exe"
    suffixes = (".pyc", ".py")

    def detect(self, data: bytes) -> bool:
        if data[:2] != b"MZ":
            return False
        return b"python" in data[:1 << 20].lower() and _find_zip(data) is not None

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        inner = _find_zip(data)
        if inner is None:
            return []
        members = self._from_zip(inner)
        if members:
            return members
        return self._from_zip(_embedded_zip(inner, "library.zip") or b"")


def _find_zip(data: bytes) -> bytes | None:
    """The first zip appended to / embedded in a binary."""
    start = data.find(b"PK\x03\x04")
    if start < 0:
        return None
    end = data.rfind(b"PK\x05\x06")
    if end < 0 or end < start:
        return None
    return data[start:end + 22]


def _embedded_zip(data: bytes, wanted: str) -> bytes | None:
    """Pull a named zip member out of *data* as bytes."""
    from io import BytesIO
    import zipfile

    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.filename.endswith(wanted):
                    return archive.read(info.filename)
    except (zipfile.BadZipFile, OSError, KeyError, ValueError):
        return None
    return None
