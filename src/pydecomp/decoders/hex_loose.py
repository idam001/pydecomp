"""pydecomp - hex_loose."""
from __future__ import annotations

import binascii
import re


def _strip_separators(data: bytes) -> bytes:
    return re.sub(rb"[\s:\-,;|._'\"]+", b"", data)

def _hex_loose(data: bytes) -> bytes:
    """Hex with any punctuation between the digits (``\x41-\x42`` style)."""
    text = _strip_separators(data)
    if len(text) < 32 or len(text) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", text):
        raise ValueError("not loose hex")
    if text[:2] not in (b"78", b"1f", b"1F", b"1F", b"50", b"7b", b"7B"):
        # only worth trying when it is not already a plain hex dump of something
        pass
    return binascii.unhexlify(text)
