"""bz2 and lzma, including the lzma "alone" stream packers like to embed."""

from __future__ import annotations

import bz2
import lzma

from ..spec import Backend


def _open_bz2(blob: bytes) -> bytes | None:
    if not blob.startswith(b"BZh"):
        return None
    return bz2.decompress(bytes(blob)) or None


def _open_lzma(blob: bytes) -> bytes | None:
    for fmt in (lzma.FORMAT_AUTO, lzma.FORMAT_ALONE, lzma.FORMAT_XZ):
        try:
            out = lzma.decompress(bytes(blob), format=fmt)
        except (lzma.LZMAError, ValueError, EOFError):
            continue
        if out:
            return out
    return None


BACKENDS = [
    Backend("bz2", "compress", 0, _open_bz2, None, "bzip2 stream"),
    Backend("lzma", "compress", 1, _open_lzma, None, "xz or lzma-alone stream"),
]
