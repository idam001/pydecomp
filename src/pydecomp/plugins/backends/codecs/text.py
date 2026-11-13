"""The base64 family, and the two base85 dialects that are not the same thing."""

from __future__ import annotations

import base64
import binascii

from ..spec import Backend
from .._share import B32, B64, B64URL, B85, share


def _pad(blob: bytes, block: int) -> bytes:
    missing = (-len(blob)) % block
    return blob + b"=" * missing


def _open_b64(blob: bytes) -> bytes | None:
    out = base64.b64decode(_pad(blob.replace(b"\n", b"").replace(b"\r", b""), 4),
                           validate=False)
    return out or None


def _open_b64url(blob: bytes) -> bytes | None:
    return base64.urlsafe_b64decode(_pad(blob.replace(b"\n", b""), 4)) or None


def _open_b32(blob: bytes) -> bytes | None:
    cleaned = blob.replace(b"\n", b"").replace(b"\r", b"")
    return base64.b32decode(_pad(cleaned.upper(), 8)) or None


def _open_b85(blob: bytes) -> bytes | None:
    return base64.b85decode(bytes(blob)) or None


def _open_a85(blob: bytes) -> bytes | None:
    cleaned = bytes(blob).replace(b"<~", b"").replace(b"~>", b"")
    return base64.a85decode(cleaned, adobe=False, ignorechars=b" \t\n\r\v") or None


def _sniff_b64(blob: bytes) -> float:
    return 0.9 * share(blob, B64) if len(blob) >= 12 else 0.0


def _sniff_b64url(blob: bytes) -> float:
    return 0.9 * share(blob, B64URL) if len(blob) >= 12 else 0.0


def _sniff_b32(blob: bytes) -> float:
    return 0.9 * share(blob, B32) if len(blob) >= 16 else 0.0


def _sniff_b85(blob: bytes) -> float:
    return 0.9 * share(blob, B85) if len(blob) >= 16 else 0.0


BACKENDS = [
    Backend("b64", "codec", 0, _open_b64, _sniff_b64, "standard base64, padding repaired",
            forge=base64.b64encode),
    Backend("b64url", "codec", 1, _open_b64url, _sniff_b64url, "url-safe base64",
            forge=base64.urlsafe_b64encode),
    Backend("b32", "codec", 1, _open_b32, _sniff_b32, "base32, case and padding repaired",
            forge=base64.b32encode),
    Backend("b85", "codec", 1, _open_b85, _sniff_b85, "b85 (python dialect)",
            forge=base64.b85encode),
    Backend("a85", "codec", 2, _open_a85, _sniff_b85, "a85, adobe delimiters optional",
            forge=base64.a85encode),
]
