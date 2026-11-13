"""Two byte-level swaps that are their own inverse.

Reversing the eight bits of a byte and swapping its two nibbles both look like
noise in a hex dump and both are one table.  They are cheap enough that the
search can afford them on every candidate, and because each is its own inverse
a single function serves both directions - which is also how the matrix checks
them.
"""

from __future__ import annotations

from .._share import structured
from ..spec import Backend

BIT_REVERSE = bytes(int(f"{byte:08b}"[::-1], 2) for byte in range(256))
NIBBLE_SWAP = bytes(((byte & 0x0F) << 4) | (byte >> 4) for byte in range(256))


def _open_bitrev(blob: bytes) -> bytes | None:
    out = bytes(blob).translate(BIT_REVERSE)
    return out if structured(out) else None


def _open_nibble(blob: bytes) -> bytes | None:
    out = bytes(blob).translate(NIBBLE_SWAP)
    return out if structured(out) else None


BACKENDS = [
    Backend("bitrev", "cipher", 2, _open_bitrev, None,
            "every byte's eight bits written backwards",
            forge=lambda payload: bytes(payload).translate(BIT_REVERSE)),
    Backend("nibbleswap", "cipher", 2, _open_nibble, None,
            "every byte's two halves exchanged",
            forge=lambda payload: bytes(payload).translate(NIBBLE_SWAP)),
]
