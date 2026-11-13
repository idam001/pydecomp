"""Base64 with the alphabet moved around, which defeats a plain b64decode.

Three rearrangements are worth trying, because all three are in the wild and all
three cost one table each:

    reversed     the alphabet written backwards
    shifted      rotated so that it starts at an arbitrary letter
    sorted       letters and digits in plain ASCII order, which is neither

Each candidate is decoded and handed on; the explorer's structural check decides
whether it was a real rearrangement.  No permutation is brute-forced.
"""

from __future__ import annotations

import base64

from ..spec import Backend
from .._share import B64

STANDARD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _alphabet_variants() -> list[tuple[str, bytes]]:
    variants = [("reversed", STANDARD[::-1])]
    variants.append(("sorted", bytes(sorted(STANDARD))))
    for shift in (1, 13, 26, 32, 48):
        variants.append((f"shift{shift}", STANDARD[shift:] + STANDARD[:shift]))
    return variants


TABLES = _alphabet_variants()


def _decode_with(blob: bytes, alphabet: bytes) -> bytes | None:
    cleaned = bytes(blob).replace(b"\n", b"").replace(b"\r", b"").replace(b"=", b"")
    cleaned += b"=" * ((-len(cleaned)) % 4)
    if not cleaned:
        return None
    translated = cleaned.translate(bytes.maketrans(alphabet, STANDARD))
    return base64.b64decode(translated, validate=False) or None


def _opener(name: str):
    alphabet = dict(TABLES)[name]

    def open_with_alphabet(blob: bytes) -> bytes | None:
        return _decode_with(blob, alphabet)

    return open_with_alphabet


def _sniff(blob: bytes) -> float:
    if len(blob) < 16:
        return 0.0
    return sum(1 for byte in blob if byte in B64) / len(blob) * 0.85


def _forger(name: str):
    alphabet = dict(TABLES)[name]

    def forge(payload: bytes) -> bytes:
        standard = base64.b64encode(payload)
        return standard.translate(bytes.maketrans(STANDARD, alphabet))

    return forge


BACKENDS = [
    Backend(f"b64{alphabet_name}", "codec", 2, _opener(alphabet_name), _sniff,
            f"base64 with a {alphabet_name} alphabet",
            forge=_forger(alphabet_name))
    for alphabet_name, _alphabet in TABLES
]
