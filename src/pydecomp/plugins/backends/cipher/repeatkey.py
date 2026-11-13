"""Repeating-key XOR when the key is nowhere in the file.

The key never appears, so it has to be recovered from the ciphertext.  Two
things make that possible without guessing:

* a column of the ciphertext was XORed with a single byte, and one byte has 256
  values, so each column is a small exhaustive search scored by whether its
  bytes land in the character sets a text format uses;
* the layers under these are nearly always base64 of something compressed, and
  those have known first characters.  A triple of b64 text starting ``eJ`` is a
  zlib header, ``H4sI`` is gzip, ``Qlpo`` is bzip2, ``XQAA`` is lzma, ``UEsD``
  is a zip.  Those few bytes pin the start of the key, which is often enough to
  pin the whole of it.

Every candidate still has to survive the structural check before the search
continues with it, so a wrong solve costs a branch, not an answer.
"""
from __future__ import annotations

from .._share import rank, structured
from ..spec import Backend

#: key lengths worth trying; a column of fewer than this many bytes cannot
#: decide a key, and deciding from six bytes is a guess dressed as a recovery
MIN_COLUMN = 24
MAX_KEY = 32
MAX_CANDIDATES = 6

#: the first characters of base64 text that is hiding a compressed stream
CRIBS = (b"eJ", b"eJy", b"eNq", b"eNr", b"H4sI", b"Qlpo", b"XQAA", b"UEsDBA")

STRONG = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
WEAK = frozenset(b"+/=-_.,:;()[]{}\"' \t\r\n")


def _column_key(column: bytes) -> int:
    best_key, best_score = 0, -1.0
    for key in range(256):
        strong = weak = 0
        for byte in column:
            plain = byte ^ key
            if plain in STRONG:
                strong += 1
            elif plain in WEAK:
                weak += 1
        score = (strong + 0.5 * weak) / len(column)
        if score > best_score:
            best_key, best_score = key, score
    return best_key


def _keys(blob: bytes, length: int) -> bytearray:
    return bytearray(_column_key(blob[offset::length]) for offset in range(length))


def _apply(blob: bytes, keys) -> bytes:
    return bytes(byte ^ keys[index % len(keys)] for index, byte in enumerate(blob))


def _solve(blob: bytes, length: int) -> bytes:
    return _apply(blob, _keys(blob, length))


def _each_repeating_key(blob: bytes):
    if len(blob) > 256 << 10:
        return                      # a payload that size is not keyed like this
    ceiling = min(MAX_KEY, len(blob) // MIN_COLUMN)
    if ceiling < 2:
        return
    found = []
    for length in range(2, ceiling + 1):
        plain = _solve(blob, length)
        if structured(plain):
            found.append(plain)
        for crib in CRIBS:
            if len(crib) > length:
                continue
            keys = _keys(blob, length)
            for index, char in enumerate(crib):
                keys[index % length] = blob[index] ^ char
            plain = _apply(blob, keys)
            if structured(plain):
                found.append(plain)
    yield from rank(found, MAX_CANDIDATES)


BACKENDS = [
    Backend("xorrepeat", "cipher", 3, None, None,
            "repeating-key XOR, key recovered column by column with known prefixes",
            each=_each_repeating_key),
]
