"""zlib, the raw deflate stream inside it, and gzip - three headers, one codec."""

from __future__ import annotations

import zlib
import gzip

from ..spec import Backend
from ....decoders.limits import ExpansionLimit, gzip_bytes, raw_deflate_bytes, zlib_bytes


def _inflate(data: bytes, opener) -> bytes | None:
    try:
        return opener(data) or None
    except ExpansionLimit:
        raise                       # the caller reports this rather than hiding it
    except Exception:                                 # noqa: BLE001
        return None


def _open_zlib(blob: bytes) -> bytes | None:
    if not blob.startswith((b"x\x01", b"x\x9c", b"x\xda", b"x\x5e")):
        return None
    return _inflate(bytes(blob), zlib_bytes)


def _open_raw(blob: bytes) -> bytes | None:
    # a deflate stream with no header at all: try it only on a first byte that
    # is a valid block header, so this costs nothing on ordinary data
    if not blob or (blob[0] & 0x0F) not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                            13, 14, 15):
        return None
    return _inflate(bytes(blob), raw_deflate_bytes)


def _open_gzip(blob: bytes) -> bytes | None:
    if not blob.startswith(b"\x1f\x8b"):
        return None
    return _inflate(bytes(blob), gzip_bytes)


def _forge_raw(payload: bytes) -> bytes:
    machine = zlib.compressobj(9, zlib.DEFLATED, -15)
    return machine.compress(payload) + machine.flush()


BACKENDS = [
    Backend("zlib", "compress", 0, _open_zlib, None, "zlib stream",
            forge=zlib.compress),
    Backend("gzip", "compress", 0, _open_gzip, None, "gzip member",
            forge=lambda payload: gzip.compress(payload, mtime=0)),
    Backend("rawdeflate", "compress", 1, _open_raw, None,
            "deflate with the zlib header stripped"),
]
