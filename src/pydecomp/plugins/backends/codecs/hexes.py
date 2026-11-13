"""Hex, and the escape spelling of the same bytes."""

from __future__ import annotations

import binascii
import codecs

from ..spec import Backend
from .._share import HEX, share


def _open_hex(blob: bytes) -> bytes | None:
    cleaned = bytes(blob).replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
    if cleaned[:2] in (b"0x", b"0X"):
        cleaned = cleaned[2:]
    if len(cleaned) < 8 or len(cleaned) % 2:
        return None
    return binascii.unhexlify(cleaned)


def _open_escapes(blob: bytes) -> bytes | None:
    if b"\\x" not in blob and b"\\u" not in blob:
        return None
    text = blob.decode("latin-1")
    out = codecs.decode(text, "unicode_escape")
    return out.encode("latin-1", "ignore") if isinstance(out, str) else out


def _sniff_hex(blob: bytes) -> float:
    return 0.95 * share(blob, HEX) if len(blob) >= 16 else 0.0


def _sniff_escapes(blob: bytes) -> float:
    return 0.9 if b"\\x" in blob or b"\\u" in blob else 0.0


BACKENDS = [
    Backend("hex", "codec", 0, _open_hex, _sniff_hex, "hex text, 0x prefix optional",
            forge=lambda payload: payload.hex().encode()),
    Backend("escapes", "codec", 2, _open_escapes, _sniff_escapes,
            "python escape text turned back into bytes"),
]
