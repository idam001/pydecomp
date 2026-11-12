"""pydecomp - learned features.

Everything here is computed from the bytes in hand.  No file is opened, nothing
is decoded ahead of time, and the whole vector is integers so the trained model
can be stored as integers too.
"""
from __future__ import annotations

import math

B64 = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B32 = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
HEX = set(b"0123456789abcdefABCDEF")
A85 = set(bytes(range(33, 118)))
UU = set(bytes(range(32, 96)))
DIGITS = set(b"0123456789")

FEATURE_NAMES = (
    "log2_len",        # 0..32
    "entropy_x10",     # 0..80
    "printable_pct",   # 0..100
    "b64_pct",         # share of bytes in the base64 alphabet
    "b32_pct",
    "hex_pct",
    "a85_pct",
    "digits_pct",
    "high_pct",        # share of bytes >= 0x80
    "newlines",        # 0/1
    "distinct_q",      # distinct bytes bucketed 0..16
    "zlib_magic",
    "gzip_magic",
    "bz2_magic",
    "lzma_magic",
    "pyc_magic",
    "pad_tail",        # ends with '=' padding, the base64 tell
    "escape_tell",     # contains a run of \\xNN escapes
    "xor_tell",        # high entropy with a flat byte histogram
    "reverse_tell",    # reversing raises the printable share
    "len_mod4",        # base64 needs whole quads
    "len_mod8",        # base32 needs whole blocks of eight
    "pure_b64_set",    # every byte is in the base64 alphabet
    "even_hex",        # even length and nothing but hex digits
)


def _percent(count: int, total: int) -> int:
    return int(round(100 * count / total)) if total else 0


def vector(blob: bytes) -> tuple[int, ...]:
    """A fixed-length integer description of a blob."""
    size = len(blob)
    if not size:
        return tuple([0] * len(FEATURE_NAMES))
    sample = blob[:65536]
    counts = [0] * 256
    printable = 0
    b64 = b32 = hexed = a85 = uu = digits = high = 0
    for byte in sample:
        counts[byte] += 1
        if 32 <= byte < 127 or byte in (9, 10, 13):
            printable += 1
        if byte in B64:
            b64 += 1
        if byte in B32:
            b32 += 1
        if byte in HEX:
            hexed += 1
        if byte in A85:
            a85 += 1
        if byte in UU:
            uu += 1
        if byte in DIGITS:
            digits += 1
        if byte >= 0x80:
            high += 1
    total = len(sample)
    entropy = 0.0
    for count in counts:
        if count:
            share = count / total
            entropy -= share * math.log2(share)
    reversed_printable = sum(
        1 for byte in sample[:4096][::-1] if 32 <= byte < 127 or byte in (9, 10, 13))
    flatness = len([count for count in counts[:128] if count]) / 128
    head = sample[:6]
    return (
        min(32, int(math.log2(max(size, 1)))),
        int(round(entropy * 10)),
        _percent(printable, total),
        _percent(b64, total),
        _percent(b32, total),
        _percent(hexed, total),
        _percent(a85, total),
        _percent(digits, total),
        _percent(high, total),
        1 if b"\n" in sample else 0,
        min(16, len([count for count in counts if count]) // 16),
        1 if head[:1] == b"\x78" else 0,
        1 if head[:2] == b"\x1f\x8b" else 0,
        1 if head[:3] == b"BZh" else 0,
        1 if head[:6] == b"\xfd7zXZ\x00" else 0,
        1 if head[:2] in (b"\x42\x0d", b"\x55\x0d", b"\x6f\x0d", b"\x03\xf3") else 0,
        1 if sample.rstrip(b"\n")[-2:] in (b"==", b"=") else 0,
        1 if b"\\x" in sample[:4096] else 0,
        1 if entropy > 7.0 and flatness > 0.8 else 0,
        1 if _percent(reversed_printable, min(total, 4096)) > _percent(
            sum(1 for byte in sample[:4096] if 32 <= byte < 127), min(total, 4096)) else 0,
        1 if size % 4 == 0 else 0,
        1 if size % 8 == 0 else 0,
        1 if b64 == total else 0,
        1 if size % 2 == 0 and hexed == total else 0,
    )
