"""How much one layer may expand to.

A layer is data a loader unpacked, and the pipeline reads every layer it finds.
Compressed data can claim any size it likes, and a file that says "64 MB of
zeros" is a way to make a reader spend that much on nothing.  Expansion stops at
this limit and says so; the bytes past it are not read and not reported as read.
"""
from __future__ import annotations

import bz2
import lzma
import zlib

#: bytes one layer may expand to
MAX_EXPANSION = 8 << 20


class ExpansionLimit(Exception):
    """Raised when a layer expands past :data:`MAX_EXPANSION`."""


def _finish(engine, blob: bytes, limit: int) -> bytes:
    out = engine.decompress(bytes(blob), limit)
    # the two families report "there is more" differently: zlib keeps the tail
    # it did not read, bz2 and lzma just are not at the end yet
    if getattr(engine, "unconsumed_tail", b"") or (
            hasattr(engine, "eof") and not engine.eof and len(out) >= limit):
        raise ExpansionLimit(f"layer expands past {limit} bytes")
    flush = getattr(engine, "flush", None)
    if flush is not None:
        out += flush()
    return out


def zlib_bytes(blob: bytes, limit: int = MAX_EXPANSION) -> bytes:
    return _finish(zlib.decompressobj(), blob, limit)


def raw_deflate_bytes(blob: bytes, limit: int = MAX_EXPANSION) -> bytes:
    return _finish(zlib.decompressobj(-15), blob, limit)


def gzip_bytes(blob: bytes, limit: int = MAX_EXPANSION) -> bytes:
    return _finish(zlib.decompressobj(16 + zlib.MAX_WBITS), blob, limit)


def bz2_bytes(blob: bytes, limit: int = MAX_EXPANSION) -> bytes:
    return _finish(bz2.BZ2Decompressor(), blob, limit)


def lzma_bytes(blob: bytes, limit: int = MAX_EXPANSION) -> bytes:
    return _finish(lzma.LZMADecompressor(), blob, limit)
