"""pydecomp - base62_codec."""
from __future__ import annotations

from ..decoders.hex_loose import _strip_separators

def _base62(data: bytes) -> bytes:
    table = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    text = _strip_separators(data)
    if not text or any(ch not in table for ch in text):
        raise ValueError("not base62")
    value = 0
    for ch in text:
        value = value * 62 + table.index(ch)
    blob = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return blob.lstrip(b"\x00") if blob[:1] == b"\x00" else blob
