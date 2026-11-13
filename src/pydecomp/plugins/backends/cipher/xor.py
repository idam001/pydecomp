"""XOR with a key the loader did not tell us, and the two key layouts to try.

A single byte of key is 256 candidates, which is not a search - it is a lookup
with a structural check.  A key written in front of its own ciphertext is one
candidate per plausible key length.  Both are the same rule: no candidate is
reported unless the plaintext *is* something - a compression header, or text
with words in it.
"""

from __future__ import annotations

from ..spec import Backend
from .._share import rank, structured

KEY_LENGTHS = (4, 6, 8, 12, 16, 24, 32)


#: how many candidates one backend may hand over.  A single-byte key space is
#: small enough to enumerate the structured ones; the explorer checks them all.
MAX_CANDIDATES = 8


def _xor_single_candidates(blob: bytes):
    found = []
    for key in range(1, 256):
        out = bytes(byte ^ key for byte in blob)
        if structured(out):
            found.append(out)
    yield from rank(found, MAX_CANDIDATES)


def _xor_header_key(blob: bytes) -> bytes | None:
    for length in KEY_LENGTHS:
        if len(blob) <= length + 8:
            continue
        key, body = bytes(blob[:length]), bytes(blob[length:])
        out = bytes(byte ^ key[index % length] for index, byte in enumerate(body))
        if structured(out):
            return out
    return None


def _xor_repeat_self(blob: bytes) -> bytes | None:
    # the key is written once and the body repeats it: key = blob[:n], guessed
    # by looking for the length at which the body starts repeating itself
    for length in (8, 16, 32):
        if len(blob) < length * 3:
            continue
        body = bytes(blob)
        if body[length:length * 2] != body[:length]:
            continue
        rest = bytes(byte ^ body[index % length] for index, byte in enumerate(body))
        if structured(rest):
            return rest
    return None


def _forge_header_key(payload: bytes, length: int) -> bytes:
    key = bytes((index * 29 + 7) % 251 for index in range(length))
    body = bytes(byte ^ key[index % length] for index, byte in enumerate(payload))
    return key + body


BACKENDS = [
    Backend("xor1", "cipher", 3, None, None,
            "single-byte XOR, 255 candidates, kept only if the plaintext is real",
            each=_xor_single_candidates,
            forge=lambda payload: bytes(byte ^ 0x5A for byte in payload)),
    Backend("xorhead", "cipher", 2, _xor_header_key, None,
            "key stored in front of its own ciphertext",
            forge=lambda payload: _forge_header_key(payload, 16)),
    Backend("xorself", "cipher", 2, _xor_repeat_self, None,
            "the key repeated as its own key stream"),
]
