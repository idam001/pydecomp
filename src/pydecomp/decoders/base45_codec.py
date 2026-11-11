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
        out.extend(divmod(value, 256)[::-1])
    if len(text) % 3 == 2:
        chunk = text[-2:]
        value = B45_ALPHABET.index(chunk[0]) + B45_ALPHABET.index(chunk[1]) * 45
        out.append(value & 0xFF)
    return bytes(out)
