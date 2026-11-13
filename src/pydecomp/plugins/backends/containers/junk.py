"""Data with something stuck to it: a preamble to cut, a trailer to drop.

Packers pad.  A gzip stream that starts fourteen bytes in is still a gzip
stream, and a base64 body followed by a block of zeroes is still base64.  Both
openers refuse to cut when more than one cut would work - an ambiguous trim is
a guess about which bytes belong to the file.
"""

from __future__ import annotations

from ..spec import Backend

MARKERS = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"x\x9c", b"x\xda", b"PK\x03\x04",
           b"\x28\xb5\x2f\xfd")

#: how far in a marker may sit before cutting it is not a trim but a hunt
REACH = 4096
#: a trailer this long or shorter, made only of these bytes, is padding
PAD = frozenset(b"\x00\xff \n\r\t")


def _cut_prefix(blob: bytes) -> bytes | None:
    if any(blob.startswith(marker) for marker in MARKERS):
        return None
    found = [blob.index(marker) for marker in MARKERS
             if marker in blob[:REACH] and blob.index(marker) > 0]
    if len(found) != 1:
        return None
    return bytes(blob[found[0]:]) or None


def _drop_trailer(blob: bytes) -> bytes | None:
    end = len(blob)
    while end and blob[end - 1] in PAD:
        end -= 1
    if end == len(blob) or end == 0:
        return None
    return bytes(blob[:end])


BACKENDS = [
    Backend("junkprefix", "container", 1, _cut_prefix, None,
            "cut to a compression header that is not at the start"),
    Backend("junktrail", "container", 0, _drop_trailer, None,
            "drop padding bytes after the data"),
]
