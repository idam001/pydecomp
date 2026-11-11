"""pydecomp - base91_codec."""
from __future__ import annotations


B91_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")

_B91_TABLE = {char: index for index, char in enumerate(B91_ALPHABET)}

_B91_ALLOWED = bytes(0 if chr(code) in _B91_TABLE else 1 for code in range(256))

def _b91_plausible(blob: bytes) -> bool:
    return blob[:4096].translate(_B91_ALLOWED).count(1) == 0

def b91decode(blob):
    text = blob.strip().decode("ascii") if isinstance(blob, (bytes, bytearray)) else blob.strip()
    table = _B91_TABLE
    out = bytearray()
    queue = 0
    bits = 0
    for char in text:
        if char not in table:
            continue
        queue |= table[char] << bits
        bits += 13
        if bits > 13:
            value = queue & 8191
            if value > 88:
                queue >>= 13
                bits -= 13
            else:
                value = queue & 16383
                queue >>= 14
                bits -= 14
            out.append(value & 0xFF)
            out.append((value >> 8) & 0xFF)
    if bits:
        out.append(queue & 0xFF)
        if bits > 7:
            out.append((queue >> 8) & 0xFF)
    return bytes(out)
