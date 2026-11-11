"""pydecomp - registry."""
from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import lzma
import zlib

from ..decoders.base16_codec import _hex_strict
from ..decoders.base45_codec import b45decode
from ..decoders.base58_codec import b58decode
from ..decoders.base62_codec import _base62
from ..decoders.base91_codec import _b91_plausible, b91decode
from ..decoders.compression.zlib_codec import _zlib_stream
from ..decoders.escapes import _escaped_bytes
from ..decoders.hex_loose import _hex_loose
from ..decoders.rot13 import _rot13_strict
from ..decoders.z85 import _base85_z85

TRANSFORMS = {
    "base64": lambda b: base64.b64decode(b, validate=False),
    "b64url": lambda b: base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4)),
    "base32": lambda b: base64.b32decode(b + b"=" * (-len(b) % 8)),
    "base16": _hex_strict,
    "base85": lambda b: base64.b85decode(b),
    "zlib": lambda b: zlib.decompress(b),
    "gzip": lambda b: gzip.decompress(b),
    "bz2": lambda b: bz2.decompress(b),
    "lzma": lambda b: lzma.decompress(b),
    "deflate": lambda b: zlib.decompress(b, -15),
    "reverse": lambda b: b[::-1],
    "rot13": _rot13_strict,
    "base58": b58decode,
    "base45": b45decode,
    "base91": b91decode,
    "ascii85": lambda b: base64.a85decode(b, adobe=False),
    "uu": lambda b: binascii.a2b_uu(b),
}

TRANSFORMS = {
    "base64": lambda b: base64.b64decode(b, validate=False),
    "b64url": lambda b: base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4)),
    "base32": lambda b: base64.b32decode(b + b"=" * (-len(b) % 8)),
    "base16": _hex_strict,
    "hexloose": _hex_loose,
    "base85": lambda b: base64.b85decode(b),
    "z85": _base85_z85,
    "base62": _base62,
    "zlib": lambda b: zlib.decompress(b),
    "zlib-stream": _zlib_stream,
    "gzip": lambda b: gzip.decompress(b),
    "bz2": lambda b: bz2.decompress(b),
    "lzma": lambda b: lzma.decompress(b),
    "deflate": lambda b: zlib.decompress(b, -15),
    "reverse": lambda b: b[::-1],
    "rot13": _rot13_strict,
    "base58": b58decode,
    "base45": b45decode,
    "base91": b91decode,
    "ascii85": lambda b: base64.a85decode(b, adobe=False),
    "uu": lambda b: binascii.a2b_uu(b),
    "escapes": _escaped_bytes,
}

_PRINT_TABLE = bytes(1 if (32 <= code < 127 or code in (9, 10, 13)) else 0
                     for code in range(256))

def _printable_count(data: bytes, window: int = 2048) -> int:
    return data[:window].translate(_PRINT_TABLE).count(1)

def _mostly_text(data: bytes, ratio: float = 0.9) -> bool:
    window = data[:2048]
    if not window:
        return False
    return _printable_count(window) >= len(window) * ratio

_TEXT_ONLY = {"base64", "b64url", "base32", "base16", "hexloose", "base85",
              "z85", "base62", "ascii85", "base58", "base45", "base91", "rot13",
              "uu", "escapes"}

_BINARY_CODECS = {"zlib", "gzip", "bz2", "lzma", "deflate", "zlib-stream"}

def _transform_allowed(name: str, data: bytes, is_text: bool | None = None) -> bool:
    if name in _TEXT_ONLY:
        return _mostly_text(data, 0.88) if is_text is None else is_text
    if name == "base91":
        return _b91_plausible(data)
    if name == "lzma":
        return data[:6] == b"\xfd7zXZ\x00" or data[:3] == b"\x5d\x00\x00"
    if name == "b64url":
        return b"-" in data or b"_" in data
    return True
