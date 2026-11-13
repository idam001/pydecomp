"""zlib, the raw deflate stream inside it, and gzip - three headers, one codec."""

from __future__ import annotations

import zlib

from ..spec import Backend


def _inflate(data: bytes, wbits: int) -> bytes | None:
    machine = zlib.decompressobj(wbits)
    out = machine.decompress(data, 64 << 20)
    out += machine.flush()
    return out or None


def _open_zlib(blob: bytes) -> bytes | None:
    if not blob.startswith((b"x\x01", b"x\x9c", b"x\xda", b"x\x5e")):
        return None
    return _inflate(bytes(blob), zlib.MAX_WBITS)


def _open_raw(blob: bytes) -> bytes | None:
    # a deflate stream with no header at all: try it only on a first byte that
    # is a valid block header, so this costs nothing on ordinary data
    if not blob or (blob[0] & 0x0F) not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                            13, 14, 15):
        return None
    return _inflate(bytes(blob), -zlib.MAX_WBITS)


def _open_gzip(blob: bytes) -> bytes | None:
    if not blob.startswith(b"\x1f\x8b"):
        return None
    return _inflate(bytes(blob), zlib.MAX_WBITS | 32)


BACKENDS = [
    Backend("zlib", "compress", 0, _open_zlib, None, "zlib stream"),
    Backend("gzip", "compress", 0, _open_gzip, None, "gzip member"),
    Backend("rawdeflate", "compress", 1, _open_raw, None,
            "deflate with the zlib header stripped"),
]
