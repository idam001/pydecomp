"""pydecomp - base58_codec."""
from __future__ import annotations


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(blob):
    text = blob.strip().decode("ascii") if isinstance(blob, (bytes, bytearray)) else blob.strip()
    number = 0
    for char in text:
        number = number * 58 + B58_ALPHABET.index(char)
    padding = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * padding + body
