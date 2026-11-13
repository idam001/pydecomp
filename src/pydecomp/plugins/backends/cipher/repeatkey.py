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
import base64
import bz2
import lzma
import zlib

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
MAX_OPTIONS_SCORED = 48

#: bytes this backend may touch before it stops; a 64 KiB blob times thirty key
#: lengths times every variation is more than an answer is worth on a phone
MAX_WORK = 12_000_000
MAX_COMBINATION_WORK = 4_000_000

#: the first characters of base64 text hiding a compressed stream, and of the
#: source a payload is when it was XORed without being encoded first
CRIBS = (b"eJ", b"eNq", b"eNr", b"H4sI", b"Qlpo", b"XQAA", b"UEsDBA",
         b"def ", b"import ", b"from ", b"class ", b"#!")
SOURCE_CRIBS = frozenset({b"def ", b"import ", b"from ", b"class ", b"#!"})

BASE64 = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
TEXT = frozenset(BASE64 | frozenset(b".,:;()[]{}\"' \t\r\n"))


def _flag_tables(alphabet: frozenset) -> tuple[bytes, ...]:
    """For each key byte, a translation table that marks the bytes it frees.

    Scoring a column used to loop over it in Python, once per key, which is the
    whole cost of this backend on a large blob.  XOR with a constant is a table
    lookup, so all 256 of them are built once and the column is counted by
    ``translate`` in C.
    """
    flags = bytes(1 if byte in alphabet else 0 for byte in range(256))
    return tuple(bytes(flags[byte ^ key] for byte in range(256)) for key in range(256))


BASE64_FLAGS = _flag_tables(BASE64)
TEXT_FLAGS = _flag_tables(TEXT)


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
    for byte in column[:12]:
        allowed &= {byte ^ char for char in TEXT}
        if not allowed:
            return []
    if len(allowed) == 1:
        return [(allowed.pop(), 1.0)]
    if len(allowed) > MAX_OPTIONS_SCORED:
        allowed = set(sorted(allowed)[:MAX_OPTIONS_SCORED])
    window = column[:512]
    scale = 1.0 / len(window)

    def share(key: int) -> float:
        base64 = sum(window.translate(BASE64_FLAGS[key])) * scale
        text = sum(window.translate(TEXT_FLAGS[key])) * scale
        return base64 if base64 > text else text

    scored = sorted(((key, share(key)) for key in allowed), key=lambda item: -item[1])
    ceiling = scored[0][1]
    return [item for item in scored if item[1] >= ceiling - 0.02] + scored


def _keys(blob: bytes, length: int, crib: bytes, limit: int = MAX_COMBINATIONS) -> list[bytes]:
    """Key candidates for one length, starting from what the crib says.

    ``limit`` of one means the best answer for each column and nothing else,
    which is the cheap first pass: most ciphertexts are decided by it, and the
    combinations only exist for the columns that could not be.
    """
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
    if limit <= 1 or len(close) > 6:
        return [bytes(base)]                 # the best of each column, and no more
    variants = [base]
    for slot in close:
        grown = []
        for variant in variants:
            for option, _share in ranked[slot][:MAX_OPTIONS]:
                candidate = list(variant)
                candidate[slot] = option
                grown.append(candidate)
                if len(grown) >= limit:
                    break
            if len(grown) >= limit:
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


def _opens(plain: bytes) -> bool:
    """Does this base64 text actually hold a compressed stream?

    Checking only the first bytes is not enough: the known prefix pins the front
    of the key, so every candidate starts with a valid header and the wrong ones
    diverge in the middle.  A stream that decompresses is the only candidate
    that is right all the way through, and a wrong key breaks it at the first
    byte it got wrong.
    """
    padded = bytes(plain) + b"=" * (-len(plain) % 4)
    try:
        body = base64.b64decode(padded, validate=False)
    except Exception:                                 # noqa: BLE001
        return False
    if not body:
        return False
    for opener in (zlib.decompress, bz2.decompress, lzma.decompress):
        try:
            opener(body)
        except Exception:                             # noqa: BLE001
            continue
        return True
    return False


def _holds(plain: bytes, crib: bytes) -> bool:
    """Text is not enough: the recovered layer has to be one that opens.

    A key that is right in most columns and wrong in one still reads as text,
    which is exactly the shape of a wrong answer.  The layers this backend is
    aimed at either decompress or parse as source, and both of those can be
    checked without running anything.
    """
    if not structured(plain):
        return False
    if crib not in SOURCE_CRIBS:
        return _opens(plain)
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
    head = blob[:4096]
    printable = sum(1 for byte in head
                    if byte in b"\t\n\r" or 32 <= byte <= 126) / len(head)
    if printable > 0.98:
        return                      # this is already text, not a ciphertext
    if len(set(head)) < 8:
        return                      # a constant cannot carry a key
    ceiling = min(MAX_KEY, len(blob) // MIN_COLUMN)
    if ceiling < 2:
        return
    found: list[bytes] = []
    # two allowances, because the two passes cost different things: the first
    # answer for each column is one apply per prefix, and the combinations are
    # a few hundred.  Spending the cheap one on every key length is worth it.
    base_work = combo_work = 0
    for length in range(2, ceiling + 1):
        base_work += len(blob) * len(CRIBS)
        settled = False
        for crib in CRIBS:
            for keys in _keys(blob, length, crib, 1):
                plain = _apply(blob, keys)
                if plain.startswith(crib) and _holds(plain, crib):
                    found.append(plain)
                    settled = True
        if not settled:
            # a small blob has few columns, so more combinations are affordable
            # and each one is cheap; a large one has already decided most of
            # its columns by the time the first answer per column was tried
            budget = max(16, 512 // length) if len(blob) <= 2 << 10 else max(4, 64 // length)
            combo_work += len(blob) * len(CRIBS) * budget
            if combo_work <= MAX_COMBINATION_WORK:
                for crib in CRIBS:
                    for keys in _keys(blob, length, crib, budget):
                        plain = _apply(blob, keys)
                        if plain.startswith(crib) and _holds(plain, crib):
                            found.append(plain)
                            settled = True
        if base_work > MAX_WORK // 4:
            break
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
            each=_each_repeating_key,
            forge=lambda payload: bytes(
                byte ^ b"\x9d\x2f\x51\x6b"[index % 4]
                for index, byte in enumerate(payload))),
]
