"""pydecomp - base16_codec."""
from __future__ import annotations

import binascii


def _hex_strict(blob: bytes) -> bytes:
    packed = b"".join(blob.split())
    if not packed or any(c not in b"0123456789abcdefABCDEF" for c in packed):
        raise ValueError("not hex")
    return binascii.unhexlify(packed)
