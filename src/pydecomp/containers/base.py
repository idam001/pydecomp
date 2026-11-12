"""pydecomp - container base.

A freezer is a container that carries a Python program inside something else:
a zip, an appended archive, a PE resource.  A reader claims the bytes
(:meth:`FreezerReader.detect`) and hands back the members worth digging into
(:meth:`FreezerReader.extract`).  Everything it returns is *bytes* - the engine
recurses into them with :func:`pydecomp.engine.dig.dig`, so a freezer inside a
freezer still resolves.
"""
from __future__ import annotations

import io
import zipfile

#: never worth unpacking: build scaffolding, caches, native libraries
SKIP_SUFFIX = (".pyc.cache", ".so", ".pyd", ".dll", ".dylib", ".dist-info/RECORD",
               ".dist-info/WHEEL", ".dist-info/METADATA", ".dist-info/top_level.txt")
SKIP_DIRS = ("__pycache__/", ".git/", "node_modules/", "tests/", "test/")


class FreezerReader:
    """One freezer format."""

    name = "container"
    #: how many members the engine may recurse into (keeps a 10k-file wheel sane)
    limit = 220
    #: which members are Python payloads
    suffixes = (".py", ".pyc", ".pyz", ".pyo")

    def detect(self, data: bytes) -> bool:            # pragma: no cover - interface
        raise NotImplementedError

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:   # pragma: no cover
        raise NotImplementedError

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _zip(data: bytes):
        try:
            return zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError, ValueError):
            return None

    def _wanted(self, name: str) -> bool:
        if any(part in name for part in SKIP_DIRS):
            return False
        if name.endswith(SKIP_SUFFIX):
            return False
        return name.endswith(self.suffixes)

    def _from_zip(self, data: bytes, predicate=None) -> list[tuple[str, bytes]]:
        archive = self._zip(data)
        if archive is None:
            return []
        out: list[tuple[str, bytes]] = []
        try:
            for info in archive.infolist():
                if info.is_dir() or not self._wanted(info.filename):
                    continue
                if predicate and not predicate(info.filename):
                    continue
                try:
                    out.append((info.filename, archive.read(info.filename)))
                except (KeyError, zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                if len(out) >= self.limit:
                    break
        finally:
            archive.close()
        return out


def zip_entries(data: bytes) -> list[str]:
    """Member names of a zip anywhere in *data* (an embedded ``library.zip``)."""
    archive = FreezerReader._zip(data)
    if archive is None:
        return []
    try:
        return [info.filename for info in archive.infolist()]
    finally:
        archive.close()
