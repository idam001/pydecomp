"""pydecomp - base45_codec."""
from __future__ import annotations


B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

def b45decode(blob):
    text = blob.strip().decode("ascii") if isinstance(blob, (bytes, bytearray)) else blob.strip()
    out = bytearray()
    for index in range(0, len(text) - len(text) % 3, 3):
        chunk = text[index:index + 3]
        value = (B45_ALPHABET.index(chunk[0]) + B45_ALPHABET.index(chunk[1]) * 45
                 + B45_ALPHABET.index(chunk[2]) * 45 * 45)
        # RFC 9285: the high byte comes first, and a group can only hold two
        # bytes - a value above 0xFFFF means the input is not base45 at all
        if not 0 <= value <= 0xFFFF:
            raise ValueError("base45 group out of range")
        out.extend((value // 256, value % 256))
    if len(text) % 3 == 2:
        chunk = text[-2:]
        value = B45_ALPHABET.index(chunk[0]) + B45_ALPHABET.index(chunk[1]) * 45
        out.append(value & 0xFF)
    return bytes(out)
