"""RC4 with the key shipped in the file, which is how hand-rolled loaders do it.

No library: the key schedule is fourteen lines, and writing it here means the
backend tree has no dependency a Termux phone cannot install.
"""

from __future__ import annotations

from ..spec import Backend
from .._share import structured

#: key lengths worth trying when the key is carried in front of the ciphertext.
#: Small on purpose: this is a layout guess, not a key search, and a key longer
#: than the body cannot be in front of it.
KEY_SIZES = tuple(range(4, 33))


def _ksa(key: bytes) -> list[int]:
    box = list(range(256))
    index = 0
    for position in range(256):
        index = (index + box[position] + key[position % len(key)]) & 0xFF
        box[position], box[index] = box[index], box[position]
    return box


def _prga(box: list[int], length: int) -> bytes:
    out = bytearray(length)
    first = second = 0
    for position in range(length):
        first = (first + 1) & 0xFF
        second = (second + box[first]) & 0xFF
        box[first], box[second] = box[second], box[first]
        out[position] = box[(box[first] + box[second]) & 0xFF]
    return bytes(out)


def rc4(data: bytes, key: bytes) -> bytes:
    stream = _prga(_ksa(key), len(data))
    return bytes(byte ^ pad for byte, pad in zip(data, stream))


def _open_rc4(blob: bytes) -> bytes | None:
    for size in KEY_SIZES:
        if len(blob) <= size + 8:
            continue
        key, body = bytes(blob[:size]), bytes(blob[size:])
        if len(set(key)) < 3:            # a key of one repeated byte is xor1's job
            continue
        out = rc4(body, key)
        if structured(out):
            return out
    return None


def _forge_rc4(payload: bytes) -> bytes:
    key = b"k3y-with-enough-distinct-bytes"
    return key + rc4(payload, key)


BACKENDS = [
    Backend("rc4head", "cipher", 3, _open_rc4, None,
            "RC4 with the key carried in front of the ciphertext",
            forge=_forge_rc4),
]
