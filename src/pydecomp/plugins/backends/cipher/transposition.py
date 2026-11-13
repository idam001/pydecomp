"""Layer-only ciphers: rail fence and columnar transposition.

Neither changes a byte, so neither can be found by looking at values - only at
order.  Both are small parameter searches (rails 2..8, columns 2..16), and both
are validated the same way as everything else here: the result has to look like
a layer before the search continues with it.
"""

from __future__ import annotations

from .._share import rank, structured
from ..spec import Backend

MAX_CANDIDATES = 4

#: 15 permutations of the whole blob, each a list of its length; past this size
#: the work is the blob rather than the cipher
MAX_SCAN = 64 << 10


def rail_fence_decode(blob: bytes, rails: int) -> bytes:
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    order = [pattern[index % len(pattern)] for index in range(len(blob))]
    rows: list[list[int]] = [[] for _ in range(rails)]
    position = 0
    for rail in order:
        rows[rail].append(position)
        position += 1
    out = bytearray(len(blob))
    index = 0
    for rail in range(rails):
        for slot in rows[rail]:
            out[slot] = blob[index]
            index += 1
    return bytes(out)


def columnar_decode(blob: bytes, columns: int) -> bytes:
    height = -(-len(blob) // columns)
    padded = height * columns
    short_rows = padded - len(blob)
    order = list(range(columns))
    lengths = [height - (1 if column >= columns - short_rows else 0)
               for column in order]
    out = bytearray(len(blob))
    index = 0
    for column, length in zip(order, lengths):
        for row in range(length):
            out[row * columns + column] = blob[index]
            index += 1
    return bytes(out)


def _rail_fence_encode(payload: bytes, rails: int) -> bytes:
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows: list[list[int]] = [[] for _ in range(rails)]
    for index, byte in enumerate(payload):
        rows[pattern[index % len(pattern)]].append(byte)
    return bytes(byte for row in rows for byte in row)


def _columnar_encode(payload: bytes, columns: int) -> bytes:
    rows = [payload[index:index + columns] for index in range(0, len(payload), columns)]
    out = bytearray()
    for column in range(columns):
        for row in rows:
            if column < len(row):
                out.append(row[column])
    return bytes(out)


def _each_rail(blob: bytes):
    if len(blob) > MAX_SCAN:
        return
    found = [rail_fence_decode(blob, rails) for rails in range(2, 9)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


def _each_columnar(blob: bytes):
    if len(blob) > MAX_SCAN:
        return
    found = [columnar_decode(blob, columns) for columns in range(2, 17)]
    yield from rank([out for out in found if structured(out)], MAX_CANDIDATES)


BACKENDS = [
    Backend("railfence", "cipher", 2, None, None,
            "rail fence, 2 to 8 rails", each=_each_rail,
            forge=lambda payload: _rail_fence_encode(payload, 5)),
    Backend("columnar", "cipher", 2, None, None,
            "columnar transposition, 2 to 16 columns", each=_each_columnar,
            forge=lambda payload: _columnar_encode(payload, 7)),
]
