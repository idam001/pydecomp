"""A payload wearing the spelling of the web.

`data:` URIs pack the bytes and base64 together in one string, so a loader can
paste a payload into an attribute and decode it without ever naming a codec.
The percent-encoded form does the same with the bytes spelled out.
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse

from ..spec import Backend

PREFIX = b"data:"


def _open_data_uri(blob: bytes) -> bytes | None:
    text = bytes(blob).strip()
    if not text.startswith(PREFIX):
        return None
    head, _, body = text.partition(b",")
    if not body:
        return None
    try:
        if head.endswith(b";base64") or b";base64;" in head:
            return base64.b64decode(body + b"=" * (-len(body) % 4), validate=False) or None
        return urllib.parse.unquote_to_bytes(body) or None
    except (binascii.Error, ValueError):
        return None


def _sniff_data_uri(blob: bytes) -> float:
    return 0.95 if bytes(blob).lstrip().startswith(PREFIX) else 0.0


BACKENDS = [
    Backend("datauri", "codec", 0, _open_data_uri, _sniff_data_uri,
            "a data: URI, base64 or percent-encoded",
            forge=lambda payload: b"data:application/octet-stream;base64,"
            + base64.b64encode(payload)),
]
