"""pydecomp - pyinstaller.

A one-file PyInstaller build is a self-extractor with a CArchive appended to it
(``MEI\\014\\013\\012\\013\\016`` cookie, a table of contents, then the members).
PyInstaller strips the 16-byte ``.pyc`` header from the code it stores and
compresses each module inside a ``PYZ``, which is itself a zlib-compressed
marshal table:

    cookie := magic(8) package_len(4) toc_offset(4) toc_len(4) pyver(4) pylib(64)
    entry  := entry_len(4) offset(4) compressed(4) uncompressed(4) flag(1) type(1) name
    PYZ    := zlib( marshal( [(name, (typecode, offset, length)), ...] ) )
    module := zlib( marshal( code object ) )

So the reader rebuilds a real ``.pyc`` for every module: the cookie's
interpreter version picks the magic number, and the module's own marshal stream
follows the 16-byte header.  The engine then decompiles them like any other
``.pyc``.
"""
from __future__ import annotations

import marshal
import struct
import zlib

from ..bytecode.magic import MAGIC_VERSIONS
from ..containers.base import FreezerReader

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE = struct.Struct("!8sIIII64s")
ENTRY = struct.Struct("!IIIIBc")


def _cookie(data: bytes):
    position = data.rfind(MAGIC)
    if position < 0 or position + COOKIE.size > len(data):
        return None
    found = COOKIE.unpack(data[position:position + COOKIE.size])
    magic, package_len, toc, toc_len, pyver, pylib = found
    if not package_len or package_len > len(data):
        return None
    start = position + COOKIE.size - package_len
    if start < 0:
        return None
    return {"start": start, "toc": start + toc, "toc_len": toc_len,
            "pyver": pyver, "pylib": pylib.rstrip(b"\x00").decode("latin-1"),
            "python": (pyver // 100, pyver % 100) if pyver else None}


def toc(data: bytes, cookie: dict) -> list[dict]:
    """Every entry in the archive's table of contents."""
    out = []
    cursor = cookie["toc"]
    end = cursor + cookie["toc_len"]
    while cursor + ENTRY.size <= end:
        try:
            entry_len, offset, compressed, uncompressed, flag, kind = \
                ENTRY.unpack(data[cursor:cursor + ENTRY.size])
        except struct.error:
            break
        if entry_len < ENTRY.size or cursor + entry_len > len(data):
            break
        name = data[cursor + ENTRY.size:cursor + entry_len].rstrip(b"\x00")
        out.append({"name": name.decode("latin-1"),
                    "offset": offset, "compressed": compressed,
                    "uncompressed": uncompressed, "flag": flag,
                    "kind": kind.decode("latin-1", "replace"),
                    "position": cursor})
        cursor += entry_len
    return out


def _member(data: bytes, cookie: dict, entry: dict) -> bytes:
    start = cookie["start"] + entry["offset"]
    # a compressed member occupies ``compressed`` bytes; an uncompressed one
    # occupies ``uncompressed``.  They differ, and reading the wrong field is
    # how a PYZ ends up being sliced into the middle of the next member.
    length = entry["compressed"] if entry["flag"] else entry["uncompressed"]
    length = length or max(entry["compressed"], entry["uncompressed"])
    raw = data[start:start + length]
    if entry["flag"]:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return b""
    return raw


def _pyc_header(python: tuple | None) -> bytes:
    """The 16-byte header PyInstaller stripped, for the interpreter it embedded."""
    for magic, version in MAGIC_VERSIONS.items():
        if python and version == tuple(python):
            return magic.to_bytes(2, "little") + b"\x00" * 14
    # unknown version: 3.13's magic is the safest guess for a stripped stream,
    # and the marshal reader decides on its own whether the body parses
    return (3571).to_bytes(2, "little") + b"\x00" * 14


class PyInstallerReader(FreezerReader):
    name = "pyinstaller"
    suffixes = (".pyz",)

    def detect(self, data: bytes) -> bool:
        return data.rfind(MAGIC) >= 0

    def extract(self, data: bytes) -> list[tuple[str, bytes]]:
        cookie = _cookie(data)
        if cookie is None:
            return []
        out: list[tuple[str, bytes]] = []
        for entry in toc(data, cookie):
            if entry["kind"] in ("z", "Z"):                     # a PYZ
                out.extend(self._from_pyz(data, cookie, entry))
            elif entry["kind"] in ("m", "M", "s", "S"):         # module / script
                payload = _member(data, cookie, entry)
                if payload:
                    out.append((entry["name"].replace("\\", "/") + ".pyc",
                                _pyc_header(cookie["python"]) + payload))
            if len(out) >= self.limit:
                break
        return out

    def _from_pyz(self, data: bytes, cookie: dict, entry: dict) -> list[tuple[str, bytes]]:
        # _member already inflates a compressed entry: what is left is the
        # marshalled table followed by the modules it points at.
        blob = _member(data, cookie, entry)
        if not blob:
            return []
        try:
            table = marshal.loads(blob)
        except (ValueError, EOFError, MemoryError, TypeError):
            try:
                table = marshal.loads(zlib.decompress(blob))
            except (zlib.error, ValueError, EOFError, MemoryError, TypeError):
                return []
        out: list[tuple[str, bytes]] = []
        if not isinstance(table, (list, tuple)):
            return out
        for item in table:
            try:
                name, packed = item
                _kind, offset, length = packed
            except (TypeError, ValueError):
                continue
            chunk = blob[offset:offset + length]
            try:
                code_bytes = zlib.decompress(chunk)
            except zlib.error:
                continue
            out.append((f"{name}.pyc", _pyc_header(cookie["python"]) + code_bytes))
            if len(out) >= self.limit:
                break
        return out


class PyInstaller2Reader(PyInstallerReader):
    """PyInstaller 2.0 wrote the cookie without the package length field."""

    name = "pyinstaller-2.0"

    def detect(self, data: bytes) -> bool:
        cookie = _cookie(data)
        return bool(cookie and cookie["start"] >= 0 and self._sane(data, cookie))

    @staticmethod
    def _sane(data: bytes, cookie: dict) -> bool:
        if not cookie["toc_len"] or cookie["toc"] > len(data):
            return False
        first = data[cookie["toc"]:cookie["toc"] + 4]
        if len(first) < 4:
            return False
        entry_len = int.from_bytes(first, "big")
        return 18 <= entry_len <= 4096
