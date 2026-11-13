"""Layers that move bytes instead of recoding them: reverse, rot13, percent, uu."""

from __future__ import annotations

import binascii
import codecs
import urllib.parse

from ..spec import Backend
from .._share import text_score


def _open_reverse(blob: bytes) -> bytes | None:
    out = bytes(blob)[::-1]
    return out if out != blob else None


def _open_rot13(blob: bytes) -> bytes | None:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return codecs.encode(text, "rot13").encode("utf-8")


def _open_percent(blob: bytes) -> bytes | None:
    if b"%" not in blob:
        return None
    out = urllib.parse.unquote_to_bytes(bytes(blob).replace(b"+", b" "))
    return out if out != blob else None


def _open_uu(blob: bytes) -> bytes | None:
    lines = [line for line in bytes(blob).splitlines() if line.strip()]
    if not lines or not lines[0].startswith(b"begin "):
        return None
    out = bytearray()
    try:
        # each line states its own length, so joining them and decoding once
        # returns the first line's worth and quietly drops the rest
        for line in lines[1:]:
            if line.strip() in (b"`", b"end"):
                break
            out.extend(binascii.a2b_uu(line))
    except binascii.Error:
        return None
    return bytes(out) or None


def _sniff_text(blob: bytes) -> float:
    return text_score(blob) * (0.9 if len(blob) >= 16 else 0.0)


def _forge_uu(payload: bytes) -> bytes:
    lines = [binascii.b2a_uu(payload[index:index + 45])
             for index in range(0, len(payload), 45)]
    return b"begin 644 payload.py\n" + b"".join(lines) + b"`\nend\n"


BACKENDS = [
    Backend("reverse", "codec", 0, _open_reverse, None, "the blob read backwards",
            forge=lambda payload: bytes(payload)[::-1]),
    Backend("rot13", "codec", 0, _open_rot13, _sniff_text, "rot13 over utf-8 text",
            forge=lambda payload: bytes(payload).translate(
                bytes.maketrans(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))),
    Backend("percent", "codec", 1, _open_percent, _sniff_text, "percent-escaped text",
            forge=lambda payload: b"".join(b"%%%02X" % byte for byte in payload)),
    Backend("uu", "codec", 2, _open_uu, None, "uuencoded body with a begin line",
            forge=lambda payload: _forge_uu(payload)),
]
