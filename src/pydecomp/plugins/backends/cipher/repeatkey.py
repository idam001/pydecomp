"""Repeating-key XOR when the key is nowhere in the file.

The key never appears, so it has to be recovered from the ciphertext.  Three
things make that possible without guessing:

* the layers under these are nearly always base64 of something compressed, and
  those have known first characters.  Base64 text starting ``eJ`` is a zlib
  header, ``H4sI`` is gzip, ``Qlpo`` is bzip2, ``XQAA`` is lzma, ``UEsD`` is a
  zip - and a payload XORed straight into source starts ``def `` or ``import``.
  Those few bytes pin the start of the key, and every later column is decided
  by which key byte turns the most of it back into the alphabet the format
  uses;
* where that leaves two answers, both are tried rather than one being picked;
* every candidate still has to survive the structural check before the search
  continues with it, so a wrong solve costs a branch, not an answer.

What it does with a ciphertext too short or too wide to decide: it stays out.
A column has to be at least ``MIN_COLUMN`` bytes before a key byte is claimed,
and the whole search is capped by how many bytes it is allowed to touch.
"""
from __future__ import annotations

import ast

from .._share import layer_evidence, rank, structured
from ..spec import Backend

#: key lengths worth trying; a column of fewer than this many bytes cannot
#: decide a key, and deciding from six bytes is a guess dressed as a recovery
MIN_COLUMN = 24
MAX_KEY = 32
MAX_CANDIDATES = 6
MAX_OPTIONS = 3
MAX_BRANCHES = 64
MAX_COMBINATIONS = 256

#: bytes this backend may touch before it stops; a 64 KiB blob times thirty key
#: lengths times every variation is more than an answer is worth on a phone
MAX_WORK = 24_000_000

#: the first characters of base64 text hiding a compressed stream, and of the
#: source a payload is when it was XORed without being encoded first
CRIBS = (b"eJ", b"eNq", b"eNr", b"H4sI", b"Qlpo", b"XQAA", b"UEsDBA",
         b"def ", b"import ", b"from ", b"class ", b"#!")
SOURCE_CRIBS = frozenset({b"def ", b"import ", b"from ", b"class ", b"#!"})

BASE64 = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
TEXT = frozenset(BASE64 | frozenset(b".,:;()[]{}\"' \t\r\n"))


def _apply(blob: bytes, keys: bytes) -> bytes:
    if not keys:
        return bytes(blob)
    pattern = (keys * (len(blob) // len(keys) + 1))[:len(blob)]
    scrambled = (int.from_bytes(blob, "big")
                 ^ int.from_bytes(pattern, "big"))
    return scrambled.to_bytes(len(blob), "big")


def _options(column: bytes) -> list[int]:
    """Key bytes this column could have come from, best first.

    The first bytes rule out almost everything; what survives is ordered by how
    much of the whole column it turns back into the alphabet a format uses,
    which is the difference between a key that works for eight bytes and one
    that works throughout.
    """
    allowed = set(range(256))
    for byte in column[:8]:
        allowed &= {byte ^ char for char in TEXT}
        if not allowed:
            return []
    if len(allowed) == 1:
        return [(allowed.pop(), 1.0)]

    def share(key: int) -> float:
        plain = [byte ^ key for byte in column]
        base64 = sum(1 for byte in plain if byte in BASE64) / len(plain)
        text = sum(1 for byte in plain if byte in TEXT) / len(plain)
        return max(base64, text)

    scored = sorted(((key, share(key)) for key in allowed), key=lambda item: -item[1])
    ceiling = scored[0][1]
    return [item for item in scored if item[1] >= ceiling - 0.02] + scored


def _keys(blob: bytes, length: int, crib: bytes) -> list[bytes]:
    """Key candidates for one length, starting from what the crib says."""
    pinned: list[int | None] = [None] * length
    for index, char in enumerate(crib):
        slot = index % length
        guess = blob[index] ^ char
        if pinned[slot] is not None and pinned[slot] != guess:
            return []                        # the crib contradicts itself here
        pinned[slot] = guess
    ranked: dict[int, list[int]] = {}
    for slot in range(length):
        if pinned[slot] is not None:
            continue
        ranked[slot] = _options(blob[slot::length])
        if not ranked[slot]:
            return []                        # undecidable column, so no claim
    base = [pinned[slot] if pinned[slot] is not None else ranked[slot][0][0]
            for slot in range(length)]
    # every combination of the first two answers for the columns that have them,
    # because one ambiguous column is common and two together is not rare
    close = [slot for slot in ranked if len(ranked[slot]) > 1]
    if len(close) > 4:
        return [bytes(base)]                 # the best of each column, and no more
    variants = [base]
    for slot in close:
        grown = []
        for variant in variants:
            for option, _share in ranked[slot][:2]:
                candidate = list(variant)
                candidate[slot] = option
                grown.append(candidate)
                if len(grown) >= MAX_COMBINATIONS:
                    break
            if len(grown) >= MAX_COMBINATIONS:
                break
        variants = grown
    return [bytes(variant) for variant in variants]


def _blind_keys(column: bytes) -> int:
    """The one key byte that puts the most of this column into text."""
    best_key, best = 0, -1.0
    for key in range(256):
        strong = weak = 0
        for byte in column:
            plain = byte ^ key
            if plain in BASE64:
                strong += 1
            elif plain in TEXT:
                weak += 1
        weight = (strong + 0.5 * weak) / len(column)
        if weight > best:
            best_key, best = key, weight
    return best_key


def _holds(plain: bytes, crib: bytes) -> bool:
    """Text is not enough: the recovered layer has to be one that opens.

    A key that is right in most columns and wrong in one still reads as text,
    which is exactly the shape of a wrong answer.  The layers this backend is
    aimed at either begin with a compressed stream's magic or are the source of
    a program, and both of those can be checked without running anything.
    """
    if not structured(plain):
        return False
    if layer_evidence(plain) >= 1.0:
        return True
    if crib in SOURCE_CRIBS:
        try:
            ast.parse(plain.decode("utf-8"))
        except (SyntaxError, ValueError, UnicodeDecodeError):
            return False
        return True
    return False


def _each_repeating_key(blob: bytes):
    if len(blob) > 256 << 10:
        return                      # a payload that size is not keyed like this
    printable = sum(1 for byte in blob[:4096]
                    if byte in b"\t\n\r" or 32 <= byte <= 126) / min(len(blob), 4096)
    if printable > 0.98:
        return                      # this is already text, not a ciphertext
    ceiling = min(MAX_KEY, len(blob) // MIN_COLUMN)
    if ceiling < 2:
        return
    found: list[bytes] = []
    work = 0
    for length in range(2, ceiling + 1):
        work += len(blob) * len(CRIBS) * 4
        if work > MAX_WORK:
            break
        for crib in CRIBS:
            settled = False
            for keys in _keys(blob, length, crib):
                plain = _apply(blob, keys)
                if plain.startswith(crib) and _holds(plain, crib):
                    found.append(plain)
                    settled = True
            if settled:
                break                # the first prefix that works answers the length
    if not found and len(blob) <= 1 << 10:
        # no known prefix: score each column against every one of the 256 values
        for length in range(2, min(ceiling, 16) + 1):
            keys = bytes(_blind_keys(blob[slot::length]) for slot in range(length))
            plain = _apply(blob, keys)
            if structured(plain):
                found.append(plain)
    yield from rank(found, MAX_CANDIDATES)


BACKENDS = [
    Backend("xorrepeat", "cipher", 3, None, None,
            "repeating-key XOR, key recovered column by column with known prefixes",
            each=_each_repeating_key),
]
