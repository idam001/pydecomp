"""Bytes spelled as numbers in text.

Loaders write the payload out in whatever separator was easiest: a comma list, a
space list, hex pairs with dashes, octal with backslashes, or a JSON array.  Each
is a parse and a bytearray, and none of them needs to know anything about the
code around it.
"""

from __future__ import annotations

import json
import re

from ..spec import Backend

_SPLIT = re.compile(rb"[\s,;:|]+")


def _numbers(blob: bytes) -> list[int] | None:
    tokens = [token for token in _SPLIT.split(bytes(blob).strip()) if token]
    if len(tokens) < 8:
        return None
    values = []
    for token in tokens:
        try:
            values.append(int(token, 10))
        except ValueError:
            return None
    return values


def _open_decimal(blob: bytes) -> bytes | None:
    values = _numbers(blob)
    if not values or any(value < 0 or value > 255 for value in values):
        return None
    return bytes(values) or None


def _open_octal(blob: bytes) -> bytes | None:
    tokens = [token for token in _SPLIT.split(bytes(blob).strip()) if token]
    if len(tokens) < 8 or not all(token.startswith(b"\\") or token.startswith(b"0o")
                                 for token in tokens):
        return None
    values = []
    for token in tokens:
        body = token[2:] if token.startswith(b"0o") else token[1:]
        try:
            values.append(int(body, 8))
        except ValueError:
            return None
    if any(value > 255 for value in values):
        return None
    return bytes(values) or None


def _open_json_array(blob: bytes) -> bytes | None:
    text = bytes(blob).strip()
    if not text.startswith(b"[") or not text.endswith(b"]"):
        return None
    try:
        values = json.loads(text.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if (not isinstance(values, list) or len(values) < 8
            or not all(isinstance(value, int) and 0 <= value <= 255 for value in values)):
        return None
    return bytes(values) or None


def _open_hex_pairs(blob: bytes) -> bytes | None:
    text = bytes(blob).strip()
    compact = text.replace(b":", b"").replace(b"-", b"").replace(b" ", b"")
    if not compact or len(compact) % 2 or not all(
            byte in b"0123456789abcdefABCDEF" for byte in compact):
        return None
    if b":" not in text and b"-" not in text:
        return None                      # plain hex belongs to the hex backend
    return bytes.fromhex(compact.decode("ascii")) or None


def _sniff_digits(blob: bytes) -> float:
    if len(blob) < 24:
        return 0.0
    sample = blob[:2048]
    allowed = sum(1 for byte in sample if byte in b"0123456789 ,;:\n\r\t[]")
    return 0.85 if allowed / len(sample) > 0.95 else 0.0


BACKENDS = [
    Backend("decimal", "codec", 1, _open_decimal, _sniff_digits,
            "byte values written out in decimal, any separator"),
    Backend("octal", "codec", 2, _open_octal, None,
            "byte values as octal escapes"),
    Backend("jsonints", "codec", 1, _open_json_array, _sniff_digits,
            "a JSON array of byte values"),
    Backend("hexpairs", "codec", 1, _open_hex_pairs, _sniff_digits,
            "hex pairs with : or - between them"),
]
