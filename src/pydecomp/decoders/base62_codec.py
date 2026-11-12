"""pydecomp - base62_codec.

Base62 is a positional encoding, so decoding is one big-integer parse: O(n) per
digit over a value that grows to n digits, i.e. quadratic in the payload.  That
is fine for the handful of kilobytes these loaders really carry and ruinous for
a megabyte of text dropped in the same slot - so the codec is bounded, and the
bound is stated instead of hanging.
"""
from __future__ import annotations

from ..decoders.hex_loose import _strip_separators

ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_VALUE = bytearray(62)
for _index, _char in enumerate(ALPHABET):
    _VALUE[_index] = _char
#: char -> digit value, 255 for "not base62"
_LUT = bytearray([255]) * 256 if False else bytearray(256)
for _code in range(256):
    _LUT[_code] = ALPHABET.find(bytes([_code])) if bytes([_code]) in ALPHABET else 255
_LUT = bytes(_LUT)

#: no real payload is this large; past it the decode is refused, not attempted
MAX_CHARS = 32_768


def _base62(data: bytes) -> bytes:
    text = _strip_separators(data)
    if not text or len(text) > MAX_CHARS:
        raise ValueError("not base62")
    values = text.translate(_LUT)
    if 255 in values:
        raise ValueError("not base62")
    value = 0
    for digit in values:
        value = value * 62 + digit
    if not value:
        return b"\x00"
    blob = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return blob.lstrip(b"\x00") if blob[:1] == b"\x00" else blob
