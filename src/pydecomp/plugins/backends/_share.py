"""Both halves of the "does this blob look like that" question."""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache

#: How much of a blob an opinion is formed from.  These functions order and
#: prune a search, so a sample answers the question they are asked; reading
#: every byte of a 300 KB literal once per candidate is what turned one hostile
#: file into a minute of work.
WINDOW = 16 << 10

B64 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B64URL = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
B32 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
B85 = frozenset(range(33, 118))
HEX = frozenset(b"0123456789abcdefABCDEF")


@lru_cache(maxsize=1024)
def xor_table(key: int) -> bytes:
    """``blob.translate(xor_table(k))`` is ``blob`` XORed with one byte."""
    return bytes(byte ^ key for byte in range(256))


@lru_cache(maxsize=1024)
def add_table(delta: int) -> bytes:
    """``blob.translate(add_table(d))`` adds ``d`` to every byte, mod 256."""
    return bytes((byte + delta) & 0xFF for byte in range(256))


@lru_cache(maxsize=64)
def rotate_table(bits: int) -> bytes:
    """``blob.translate(rotate_table(b))`` rotates every byte left by ``b``."""
    return bytes(((byte << bits) | (byte >> (8 - bits))) & 0xFF for byte in range(256))


def xor_cyclic(blob: bytes, key: bytes) -> bytes:
    """XOR with a key repeated over the blob, done as one big-integer XOR."""
    if not key:
        return bytes(blob)
    pattern = (bytes(key) * (len(blob) // len(key) + 1))[:len(blob)]
    return (int.from_bytes(blob, "big")
            ^ int.from_bytes(pattern, "big")).to_bytes(len(blob), "big")


def sample(blob: bytes) -> bytes:
    """A bounded window of the blob: most of the front, some of the back.

    Structure at either end matters - a preamble at the front, padding at the
    back - and nothing in between changes a fraction by more than noise.
    """
    if len(blob) <= WINDOW:
        return bytes(blob)
    tail = WINDOW // 4
    return bytes(blob[:WINDOW - tail]) + bytes(blob[-tail:])


def share(blob: bytes, allowed) -> float:
    """Fraction of bytes inside ``allowed``; 0.0 for an empty blob."""
    if not blob:
        return 0.0
    window = sample(blob)
    return sum(1 for byte in window if byte in allowed) / len(window)


PRINTABLE_FLAGS = bytes(1 if byte in b"\n\r\t" or 32 <= byte <= 126 else 0
                       for byte in range(256))
ALNUM_FLAGS = bytes(1 if (48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122)
                    else 0 for byte in range(256))


def text_score(blob: bytes) -> float:
    """How much this reads as text - the usual sign that a layer decoded."""
    if not blob:
        return 0.0
    window = sample(blob)
    return sum(window.translate(PRINTABLE_FLAGS)) / len(window)


#: characters that may appear in text without making it less like text
_TAINT = {code: None for code in range(0x20) if chr(code) not in "\n\r\t"}
_TAINT[0x7F] = None


def _mostly_printable(text: str) -> bool:
    """``str.isprintable`` is C and fast; this is the slower question it excludes.

    Tabs and newlines are text, and ``isprintable`` says they are not, so a
    document with them in it has to be counted the long way - but only when the
    fast answer was "no".
    """
    kept = len(text.translate(_TAINT))
    return kept / len(text) >= 0.95


MAGIC = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"x\x9c", b"x\xda", b"x\x01",
         b"PK\x03\x04", b"ustar", b"\x28\xb5\x2f\xfd")


def _opens_compressed(blob: bytes) -> bool:
    """Check that a compression header leads to output, without inflating a bomb."""
    import bz2
    import lzma
    import zlib

    try:
        if blob.startswith(b"\x1f\x8b"):
            return bool(zlib.decompressobj(31).decompress(blob, 64))
        if blob.startswith((b"x\x9c", b"x\xda", b"x\x01")):
            return bool(zlib.decompressobj().decompress(blob, 64))
        if blob.startswith(b"BZh"):
            return bool(bz2.BZ2Decompressor().decompress(blob, max_length=64))
        if blob.startswith(b"\xfd7zXZ"):
            return bool(lzma.LZMADecompressor().decompress(blob, max_length=64))
    except (EOFError, OSError, ValueError, zlib.error, lzma.LZMAError):
        return False
    return False


def _magic_evidence(blob: bytes) -> bool:
    if not blob:
        return False
    if blob.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ",
                        b"x\x9c", b"x\xda", b"x\x01")):
        return _opens_compressed(blob)
    if blob.startswith(b"PK\x03\x04"):
        try:
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                return bool(archive.namelist())
        except (OSError, ValueError, zipfile.BadZipFile):
            return False
    if blob.startswith(b"ustar"):
        try:
            import io
            import tarfile
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as archive:
                return bool(archive.getmembers())
        except (OSError, ValueError, tarfile.TarError):
            return False
    return blob.startswith(b"\x28\xb5\x2f\xfd")


def structured(blob: bytes) -> bool:
    """Evidence that a candidate is a real layer and not noise.

    A compression header or a word-bearing text.  This is what keeps a
    brute-force backend honest: a key that produces 60 random bytes is not an
    answer, however few candidates there were.
    """
    if not blob:
        return False
    if _magic_evidence(blob):
        return True
    try:
        text = sample(blob).decode("utf-8", "ignore")
    except UnicodeDecodeError:                       # pragma: no cover - ignored
        return False
    if not text:
        return False
    if not text.isprintable() and not _mostly_printable(text):
        return False
    return any(char.isalpha() for char in text)


def evidence(blob: bytes) -> float:
    """How much a candidate looks like it is worth another step, 0.0 to 1.0.

    Independent of the caller's check: this only orders and prunes the search,
    so a wrong prune costs a chain, never a wrong answer.
    """
    if not blob:
        return 0.0
    if _magic_evidence(blob):
        return 1.0
    if blob[:2] in (b"\r\n", b"\n\r"):
        return 0.8                     # a pyc header names its own version
    try:
        text = sample(blob).decode("utf-8", "ignore")
    except UnicodeDecodeError:                       # pragma: no cover - ignored
        return 0.0
    if not text:
        return 0.0
    if not text.isprintable() and not _mostly_printable(text):
        return 0.0
    letters = sum(map(str.isalnum, text))
    return 0.4 + 0.4 * min(1.0, letters / len(text))


CLEAN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  "+/=:._- \n\r\t")


def score(blob: bytes) -> float:
    """Evidence, plus how much the bytes read like a codec's own output."""
    weight = layer_evidence(blob)
    try:
        text = sample(blob).decode("utf-8", "ignore")
    except UnicodeDecodeError:                       # pragma: no cover - ignored
        return weight
    if not text:
        return weight
    dirty = {ord(char): None for char in text
             if char not in CLEAN} if len(text) <= 4096 else None
    if dirty is None:
        clean = sum(1 for char in text if char in CLEAN) / len(text)
    else:
        clean = len(text.translate(dirty)) / len(text)
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


def promise(blob: bytes) -> float:
    """Evidence now, plus half of what the step after it would see.

    Two candidates can read equally like text and still not be equally
    interesting: base64 of base64 opens into another layer, and the same bytes
    after rot13 open into noise.  One decode is cheap enough to ask.
    """
    score_now = layer_evidence(blob)
    if score_now >= 1.0 or not blob:
        return score_now
    window = sample(blob)
    padded = window + b"=" * (-len(window) % 4)
    best = 0.0
    for opener in (lambda data: base64.b64decode(data, validate=False),
                   lambda data: binascii.unhexlify(data)):
        try:
            opened = opener(padded)
        except Exception:                             # noqa: BLE001
            continue
        if opened:
            best = max(best, layer_evidence(opened))
    return score_now + 0.5 * best


def layer_evidence(blob: bytes) -> float:
    """Evidence that this candidate is a *layer* - something a decoder can open.

    Printability alone cannot order candidates: a wrong XOR key produces text as
    readable-looking as the right base64.  What separates them is that the right
    one opens - base64 whose bytes begin with a zlib header, hex whose bytes do,
    text that a codec recognises.  This is a ranking hint, never an acceptance.
    """
    base = evidence(blob)
    if base >= 1.0:
        return 1.6                                    # a readable compression/container header
    if not blob:
        return 0.0
    window = sample(blob)
    padded = window + b"=" * (-len(window) % 4)
    for opener in (lambda data: base64.b64decode(data, validate=False),
                   lambda data: binascii.unhexlify(data)):
        try:
            opened = opener(padded)
        except Exception:                             # noqa: BLE001
            continue
        if opened and _magic_evidence(opened):
            return 1.5
    return base
