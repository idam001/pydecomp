"""Payloads spelled as bits.

Three spellings, all of them in samples: a run of "01001000" per byte, five-bit
groups (the Bacon alphabet, which some droppers use because it survives being
pasted as text), and the same with zero-width characters standing in for the two
bits.  The first two decode to bytes; the third is what a loader does when it
wants a payload nobody can see.
"""

from __future__ import annotations

from ..spec import Backend

ZERO_WIDTH = {"\u200b": "0", "\u200c": "1"}
ALSO_ZERO = {"\u200d": "1", "\u2060": "0"}


def _bits_from_text(text: str) -> str | None:
    table = {**ZERO_WIDTH, **ALSO_ZERO}
    if any(char in table for char in text):
        bits = "".join(table[char] for char in text if char in table)
        return bits or None
    stripped = "".join(char for char in text if char in "01")
    if stripped and len(stripped) != len(text.strip()):
        if set(text.strip()) - set("01 \n\r\t"):
            return None
    return stripped or None


def _open_bits(blob: bytes) -> bytes | None:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return None
    bits = _bits_from_text(text)
    if not bits or len(bits) % 8:
        return None
    return bytes(int(bits[index:index + 8], 2)
                 for index in range(0, len(bits), 8)) or None


def _open_bacon(blob: bytes) -> bytes | None:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return None
    letters = [char.lower() for char in text if char.isalpha()]
    if len(letters) < 16 or len(letters) % 5:
        return None
    out = bytearray()
    for index in range(0, len(letters), 5):
        group = letters[index:index + 5]
        value = 0
        for char in group:
            value = (value << 1) | (0 if char in "ab" else 1)
        out.append(value)
    return bytes(out) or None


def _sniff_bits(blob: bytes) -> float:
    if len(blob) < 32:
        return 0.0
    sample = blob[:4096]
    allowed = sum(1 for byte in sample if byte in b"01 \n\r\t")
    return 0.9 if allowed / len(sample) > 0.95 else 0.0


def _sniff_zw(blob: bytes) -> float:
    if not blob:
        return 0.0
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    marks = sum(1 for char in text if char in ZERO_WIDTH or char in ALSO_ZERO)
    return 0.95 if marks >= 64 else 0.0


def _sniff_bacon(blob: bytes) -> float:
    if len(blob) < 64:
        return 0.0
    sample = blob[:4096]
    letters = sum(1 for byte in sample if chr(byte).isalpha() or byte in b" \n\r\t")
    return 0.7 if letters / len(sample) > 0.97 else 0.0


BACKENDS = [
    Backend("bits", "codec", 1, _open_bits, _sniff_bits,
            "eight-bit groups spelled 0 and 1, including zero-width spellings"),
    Backend("bacon", "codec", 2, _open_bacon, _sniff_bacon,
            "five-bit groups hidden in a run of letters"),
]
