"""Carving: the payload is somewhere inside these bytes, not at their start.

A dropper that appends its payload to a picture, or prepends a banner to a zip,
leaves the payload intact at an offset.  The scanner walks the blob once for the
magics a layer can start with and offers what follows each one, nearest first.
It stops at a fixed reach and a fixed number of hits, because a scan that turns
up two hundred candidates has told you nothing about which one matters.
"""

from __future__ import annotations

from ..spec import Backend

#: marker, and what it means for the rest of the blob
MAGICS = (
    (b"\x1f\x8b", "gzip"),                 # gzip
    (b"BZh9", "bz2"),
    (b"\xfd7zXZ", "xz"),
    (b"PK\x03\x04", "zip"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
)

REACH = 1 << 20          # how far into the blob a marker is worth considering
MAX_HITS = 4


def _each_carve(blob: bytes):
    data = bytes(blob)[:REACH]
    taken = 0
    for marker, _name in MAGICS:
        start = data.find(marker)
        while start > 0 and taken < MAX_HITS:
            yield data[start:]
            taken += 1
            start = data.find(marker, start + 1)


BACKENDS = [
    Backend("carve", "container", 2, None, None,
            "a layer that starts partway in, found by its magic",
            each=_each_carve),
]
