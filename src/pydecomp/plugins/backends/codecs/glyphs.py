"""Text that looks like the text it is not.

Two substitutions keep a payload out of a grep and out of an eye: the wide forms
of ASCII that CJK input produces, and Cyrillic or Greek letters that render like
Latin ones.  Both are single code point maps, so both are exact - either every
character maps or the backend stays out of the way.
"""

from __future__ import annotations

from ..spec import Backend

#: fullwidth and halfwidth ASCII, then the ideographic space
WIDE = {0xFF01 + offset: 0x21 + offset for offset in range(94)}
#: a flat offset of 0xFEE0, which is how most of these are produced, lands the
#: space on FF00 and the ideographic space on 3000
WIDE[0xFF00] = 0x20
WIDE[0x3000] = 0x20

#: letter -> Latin letter it renders as.  Only the ones that are truly identical
#: in a monospace font are here; a lookalike that a reader could tell apart is
#: not a homoglyph, it is a different letter.
HOMO = {
    0x0410: ord("A"), 0x0412: ord("B"), 0x0415: ord("E"), 0x041A: ord("K"),
    0x041C: ord("M"), 0x041D: ord("H"), 0x041E: ord("O"), 0x0420: ord("P"),
    0x0421: ord("C"), 0x0422: ord("T"), 0x0423: ord("Y"), 0x0425: ord("X"),
    0x0430: ord("a"), 0x0435: ord("e"), 0x043E: ord("o"), 0x0440: ord("p"),
    0x0441: ord("c"), 0x0443: ord("y"), 0x0445: ord("x"), 0x0455: ord("s"),
    0x0456: ord("i"), 0x0458: ord("j"), 0x04CF: ord("l"),
    0x0391: ord("A"), 0x0392: ord("B"), 0x0395: ord("E"), 0x0396: ord("Z"),
    0x0397: ord("H"), 0x0399: ord("I"), 0x039A: ord("K"), 0x039C: ord("M"),
    0x039D: ord("N"), 0x039F: ord("O"), 0x03A1: ord("P"), 0x03A4: ord("T"),
    0x03A5: ord("Y"), 0x03A7: ord("X"), 0x03BF: ord("o"), 0x03BD: ord("v"),
}


def _map_text(blob: bytes, table: dict[int, int]) -> bytes | None:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return None
    hits = sum(1 for character in text if ord(character) in table)
    if not hits:
        return None
    return "".join(chr(table.get(ord(character), ord(character)))
                   for character in text).encode("utf-8")


def _open_wide(blob: bytes) -> bytes | None:
    return _map_text(blob, WIDE)


def _open_homoglyph(blob: bytes) -> bytes | None:
    return _map_text(blob, HOMO)


def _sniff_wide(blob: bytes) -> float:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    wide = sum(1 for character in text if ord(character) in WIDE)
    return 0.9 if wide / len(text) > 0.5 else 0.0


def _sniff_homoglyph(blob: bytes) -> float:
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    outside = sum(1 for character in text if ord(character) > 0x7F)
    if not outside:
        return 0.0
    return 0.85 if outside / len(text) < 0.25 else 0.0


BACKENDS = [
    Backend("fullwidth", "codec", 0, _open_wide, _sniff_wide,
            "wide forms of ASCII folded back to ASCII"),
    Backend("homoglyph", "codec", 0, _open_homoglyph, _sniff_homoglyph,
            "Cyrillic and Greek letters that render as Latin"),
]
