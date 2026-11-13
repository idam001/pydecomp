"""bz2 and lzma, including the lzma "alone" stream packers like to embed."""

from __future__ import annotations

import bz2
import lzma

from ..spec import Backend
from ....decoders.limits import ExpansionLimit, bz2_bytes, lzma_bytes


def _open_bz2(blob: bytes) -> bytes | None:
    if not blob.startswith(b"BZh"):
        return None
    try:
        return bz2_bytes(bytes(blob)) or None
    except ExpansionLimit:
        raise                        # a layer this large is reported, not hidden
    except Exception:                                # noqa: BLE001
        return None


def _open_lzma(blob: bytes) -> bytes | None:
    for opener in (lzma_bytes, lambda data: lzma.decompress(data, format=lzma.FORMAT_ALONE)):
        try:
            out = opener(bytes(blob))
        except ExpansionLimit:
            raise
        except (lzma.LZMAError, ValueError, EOFError):
            continue
        if out:
            return out
    return None


BACKENDS = [
    Backend("bz2", "compress", 0, _open_bz2, None, "bzip2 stream",
            forge=bz2.compress),
    Backend("lzma", "compress", 1, _open_lzma, None, "xz or lzma-alone stream",
            forge=lzma.compress),
]
