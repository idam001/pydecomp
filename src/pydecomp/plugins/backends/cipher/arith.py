"""Add, subtract and rotate: the arithmetic ciphers that are not XOR.

Each is a small key space, so each is a loop.  The same structural rule applies:
plaintext has to look like something before it counts.
"""

from __future__ import annotations

from ..spec import Backend
from .._share import rank, structured


def _shift(blob: bytes, delta: int) -> bytes:
    return bytes((byte + delta) & 0xFF for byte in blob)


def _rotate(blob: bytes, bits: int) -> bytes:
    return bytes(((byte << bits) | (byte >> (8 - bits))) & 0xFF for byte in blob)


MAX_CANDIDATES = 8


def _each_shift(blob: bytes, direction: int):
    found = [_shift(blob, direction * delta) for delta in range(1, 256)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


def _each_rotate(blob: bytes, direction: int):
    found = [_rotate(blob, (direction * bits) % 8) for bits in range(1, 8)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


BACKENDS = [
    Backend("addconst", "cipher", 3, None, None,
            "every byte shifted by one constant", each=lambda blob: _each_shift(blob, -1)),
    Backend("subconst", "cipher", 3, None, None,
            "the same, in the other direction", each=lambda blob: _each_shift(blob, 1)),
    Backend("rotl", "cipher", 3, None, None,
            "bit rotation, 7 directions", each=lambda blob: _each_rotate(blob, 1)),
    Backend("rotr", "cipher", 3, None, None,
            "bit rotation, the other way", each=lambda blob: _each_rotate(blob, -1)),
]
