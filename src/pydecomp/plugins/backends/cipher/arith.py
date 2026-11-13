"""Add, subtract and rotate: the arithmetic ciphers that are not XOR.

Each is a small key space, so each is a loop.  The same structural rule applies:
plaintext has to look like something before it counts.
"""

from __future__ import annotations

from ..spec import Backend
from .._share import add_table, rank, rotate_table, structured

#: The scan is 255 candidates over the whole blob, so the constant is the cost.
#: Past this size a per-byte constant is not what a loader wrote, and the
#: backend declines rather than spending the file's whole budget here.
MAX_SCAN = 32 << 10


def _shift(blob: bytes, delta: int) -> bytes:
    return bytes(blob).translate(add_table(delta))


def _rotate(blob: bytes, bits: int) -> bytes:
    return bytes(blob).translate(rotate_table(bits))


MAX_CANDIDATES = 8


def _each_shift(blob: bytes, direction: int):
    if len(blob) > MAX_SCAN:
        return
    found = [_shift(blob, direction * delta) for delta in range(1, 256)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


def _each_rotate(blob: bytes, direction: int):
    if len(blob) > MAX_SCAN:
        return
    found = [_rotate(blob, (direction * bits) % 8) for bits in range(1, 8)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


BACKENDS = [
    Backend("addconst", "cipher", 3, None, None,
            "every byte shifted by one constant", each=lambda blob: _each_shift(blob, -1),
            forge=lambda payload: _shift(payload, 0x37)),
    Backend("subconst", "cipher", 3, None, None,
            "the same, in the other direction", each=lambda blob: _each_shift(blob, 1),
            forge=lambda payload: _shift(payload, -0x37)),
    Backend("rotl", "cipher", 3, None, None,
            "bit rotation, 7 directions", each=lambda blob: _each_rotate(blob, 1),
            forge=lambda payload: _rotate(payload, 3)),
    Backend("rotr", "cipher", 3, None, None,
            "bit rotation, the other way", each=lambda blob: _each_rotate(blob, -1),
            forge=lambda payload: _rotate(payload, 5)),
]
