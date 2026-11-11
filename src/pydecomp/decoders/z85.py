"""pydecomp - z85."""
from __future__ import annotations

from ..decoders.hex_loose import _strip_separators

def _base85_z85(data: bytes) -> bytes:
    table = (b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
             b".-:+=^!/*?&<>()[]{}@%$#")
    text = _strip_separators(data)
    if not text or any(ch not in table for ch in text):
        raise ValueError("not z85")
    if len(text) % 5:
        raise ValueError("z85 length")
    out = bytearray()
    for i in range(0, len(text), 5):
        value = 0
        for ch in text[i:i + 5]:
            value = value * 85 + table.index(ch)
        out.extend(value.to_bytes(4, "big"))
    return bytes(out)
