"""pydecomp - pyinstaller.

A PyInstaller build is a native bootloader with a ``CArchive`` stapled to it.  A
cookie near the end of the file (``MEI\\014\\013\\012\\013\\016``) points at a table of
contents; the application's modules live either in the archive itself or in an
embedded ``PYZ-00.pyz``, which is a zlib-compressed module table of its own.

The layout, as every extractor since pyinstxtractor has parsed it::

    cookie  : magic(8) pkgLen(4) toc(4) tocLen(4) pyvers(4) pylibname(64)
    overlay : overlayPos = fileSize - (pkgLen + tailBytes)
    toc     : at overlayPos + toc, 'tocLen' bytes
    entry   : entrySize(4) entryPos(4) cmprsd(4) uncmprsd(4) flag(1) type(1) name…
              (entrySize counts its own 4-byte field; entryPos is overlay-relative)
    pyz     : 'PYZ\\0' magic(4) tocPos(4) …  toc = marshal([(name,(type,pos,len))])

Everything is data, so it is read, never run.  ``--key`` builds store encrypted
PYZ payloads: those entries are named and reported, and every readable module is
still recovered - a partial answer beats a refusal.
"""
from __future__ import annotations

import marshal
import struct
import zlib

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYZ_MAGIC = b"PYZ\x00"

_COOKIE_LEGACY = 24
_COOKIE_MODERN = 88
_ENTRY_HEADER = 18            # entrySize(4) + pos(4) + cmprsd(4) + uncmprsd(4) + flag(1) + type(1)


def is_carchive(data: bytes) -> bool:
    if len(data) < _COOKIE_LEGACY:
        return False
    position = data.rfind(MAGIC)
    return position != -1 and position > len(data) - 8192


def _cookie_info(data: bytes) -> dict | None:
    position = data.rfind(MAGIC)
    if position == -1:
        return None
    tail = data[position:]
    for fmt in ("!8sIIii64s", "!8siiii64s", "!8sIIii", "!8siiii"):
        size = struct.calcsize(fmt)
        if len(tail) < size:
            continue
        try:
            fields = struct.unpack(fmt, tail[:size])
        except struct.error:
            continue
        package_len, toc, toc_len = fields[1], fields[2], fields[3]
        if not (0 < toc_len <= len(data)) or package_len <= 0:
            continue
        pylib = ""
        if len(fields) > 5:
            pylib = fields[5].split(b"\x00")[0].decode("ascii", "replace")
        tail_bytes = len(data) - position - size
        overlay_size = package_len + tail_bytes
        overlay_pos = len(data) - overlay_size
        if overlay_pos < 0:
            overlay_pos = 0
        return {"cookie_pos": position, "cookie_size": size,
                "package_len": package_len, "toc": toc, "toc_len": toc_len,
                "pyvers": fields[4], "pylib": pylib,
                "overlay_pos": overlay_pos,
                "toc_pos": overlay_pos + toc}
    return None


def carchive_entries(data: bytes) -> list[tuple[str, bytes, str]]:
    """Return ``(name, payload, typecode)`` for every readable CArchive entry."""
    info = _cookie_info(data)
    if info is None:
        return []
    out: list[tuple[str, bytes, str]] = []
    position = info["toc_pos"]
    end = min(position + info["toc_len"], len(data))
    guard = 0
    while position < end and guard < 100_000:
        guard += 1
        try:
            (entry_size,) = struct.unpack("!i", data[position:position + 4])
        except struct.error:
            break
        if entry_size < _ENTRY_HEADER or position + entry_size > len(data):
            break
        blob = data[position + 4:position + entry_size]
        try:
            entry_pos, cmprsd, uncmprsd, flag, typecode = struct.unpack(
                "!iiiBc", blob[:_ENTRY_HEADER - 4])
        except struct.error:
            break
        name = blob[_ENTRY_HEADER - 4:].decode("utf-8", "replace").rstrip("\x00")
        position += entry_size
        if entry_pos < 0 or cmprsd <= 0:
            continue
        start = info["overlay_pos"] + entry_pos
        payload = data[start:start + cmprsd]
        if not payload:
            continue
        if flag:
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                out.append((name, b"", "encrypted"))
                continue
        out.append((name, payload, typecode.decode("ascii", "replace")))
    return out


def is_pyz(data: bytes) -> bool:
    return data[:4] == PYZ_MAGIC


def pyz_modules(data: bytes) -> list[tuple[str, bytes]]:
    """Read a ``PYZ-00.pyz`` table.  Modules come back as raw marshal bodies."""
    if not is_pyz(data) or len(data) < 12:
        return []
    try:
        (toc_pos,) = struct.unpack("!i", data[8:12])
    except struct.error:
        return []
    if not 0 < toc_pos < len(data):
        return []
    try:
        toc = marshal.loads(data[toc_pos:])
    except Exception:                                  # noqa: BLE001 - bad table
        return []
    if not isinstance(toc, (list, tuple)):
        return []
    modules: list[tuple[str, bytes]] = []
    for item in toc:
        try:
            name, spec = item
            _typ, position, length = spec
        except (TypeError, ValueError):
            continue
        if not isinstance(position, int) or not isinstance(length, int):
            continue
        blob = data[position:position + length]
        if not blob:
            continue
        try:
            blob = zlib.decompress(blob)
        except zlib.error:
            modules.append((name, blob))       # --key build: payload stays closed
            continue
        modules.append((name, blob))
    return modules


def entry_script(entries) -> tuple[str, bytes] | None:
    """Pick the program itself out of a CArchive's entry list."""
    runtime_prefixes = ("pyi-", "pyiboot", "pyimod", "struct")
    candidates = []
    for name, blob, typecode in entries:
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        if typecode not in ("s", "m", "M"):
            continue
        if base.startswith(runtime_prefixes) or not blob:
            continue
        candidates.append((base, blob))
    if not candidates:
        for name, blob, typecode in entries:
            if blob and not name.endswith((".dll", ".so", ".pyd", ".dylib")):
                candidates.append((name.replace("\\", "/").rsplit("/", 1)[-1], blob))
    if not candidates:
        return None
    for base, blob in reversed(candidates):
        if base != "__init__.pyc":
            return base, blob
    return candidates[-1]


def walk(data: bytes, limit: int = 24) -> list[tuple[str, bytes]]:
    """Every Python payload we can pull out of a PyInstaller build."""
    found: list[tuple[str, bytes]] = []
    entries = carchive_entries(data) if is_carchive(data) else []
    for name, blob, typecode in entries[:limit]:
        if not blob:
            continue
        if typecode in ("z", "Z") or blob[:4] == PYZ_MAGIC:
            for module_name, module_blob in pyz_modules(blob)[:limit]:
                found.append((f"{name}:{module_name}", module_blob))
    if not found:
        chosen = entry_script(entries) if entries else None
        if chosen:
            found.append(chosen)
    return found


def describe(entries) -> dict:
    """A one-line summary for the trace."""
    readable = [item for item in entries if item[1]]
    encrypted = [item[0] for item in entries if item[2] == "encrypted"]
    return {"entries": len(entries), "readable": len(readable),
            "encrypted": encrypted}
