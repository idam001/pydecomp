"""Both halves of the "does this blob look like that" question."""

from __future__ import annotations

B64 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B64URL = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
B32 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
B85 = frozenset(range(33, 118))
HEX = frozenset(b"0123456789abcdefABCDEF")


def share(blob: bytes, allowed) -> float:
    """Fraction of bytes inside ``allowed``; 0.0 for an empty blob."""
    if not blob:
        return 0.0
    return sum(1 for byte in blob if byte in allowed) / len(blob)


def text_score(blob: bytes) -> float:
    """How much this reads as text - the usual sign that a layer decoded."""
    if not blob:
        return 0.0
    good = sum(1 for byte in blob if byte in b"\n\r\t" or 32 <= byte <= 126)
    return good / len(blob)


MAGIC = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"x\x9c", b"x\xda", b"x\x01",
         b"PK\x03\x04", b"ustar", b"\x28\xb5\x2f\xfd")


def structured(blob: bytes) -> bool:
    """Evidence that a candidate is a real layer and not noise.

    A compression header or a word-bearing text.  This is what keeps a
    brute-force backend honest: a key that produces 60 random bytes is not an
    answer, however few candidates there were.
    """
    if not blob:
        return False
    if any(blob.startswith(magic) for magic in MAGIC):
        return True
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    if printable / len(text) < 0.97:
        return False
    return any(char.isalpha() for char in text)


def evidence(blob: bytes) -> float:
    """How much a candidate looks like it is worth another step, 0.0 to 1.0.

    Independent of the caller's check: this only orders and prunes the search,
    so a wrong prune costs a chain, never a wrong answer.
    """
    if not blob:
        return 0.0
    if any(blob.startswith(magic) for magic in MAGIC):
        return 1.0
    if blob[:2] in (b"\r\n", b"\n\r"):
        return 0.8                     # a pyc header names its own version
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    if printable / len(text) < 0.95:
        return 0.0
    letters = sum(1 for char in text if char.isalnum())
    return 0.4 + 0.4 * min(1.0, letters / len(text))


CLEAN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  "+/=:._- \n\r\t")


def score(blob: bytes) -> float:
    """Evidence, plus how much the bytes read like a codec's own output."""
    weight = evidence(blob)
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return weight
    if not text:
        return weight
    clean = sum(1 for char in text if char in CLEAN) / len(text)
    return weight + 0.5 * clean


def rank(candidates, limit: int = 8) -> list[bytes]:
    """Keep the candidates that look most like a layer, not the first ones found.

    Ordering by key value is the trap here: with a blob that is already mostly
    text, every key produces printable bytes, so "the first eight" is arbitrary
    and the right key is usually just past the cut.
    """
    scored = [(score(candidate), candidate) for candidate in candidates]
    scored.sort(key=lambda pair: -pair[0])
    return [candidate for _weight, candidate in scored[:limit]]
