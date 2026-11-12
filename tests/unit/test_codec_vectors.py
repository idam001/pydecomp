"""Spectrum codecs against their published vectors.

These two decoders were wrong in ways only a vector catches.  base45 read the
high and low byte of a triple in the wrong order, so every payload it produced
was byte-swapped and a legitimate input could raise "byte must be in range".
z85 passed its input through the separator stripper, and Z85's own alphabet
contains '.', '-', ':', '+' and '=', so the stripper ate the encoding itself.
Both are fixed; these tests are the reason they stay fixed.
"""
from __future__ import annotations

import pytest

from pydecomp.decoders.registry import TRANSFORMS
from pydecomp.decoders.z85 import _base85_z85


# RFC 9285, Appendix B
BASE45_VECTORS = [
    (b"BB8", b"AB"),
    (b"%69 VD92EX0", b"Hello!!"),
    (b"UJCLQE7W581", b"base-45"),
    (b"QED8WEX0", b"ietf!"),
]


@pytest.mark.parametrize("encoded,plain", BASE45_VECTORS)
def test_base45_matches_rfc_9285(encoded, plain):
    assert TRANSFORMS["base45"](encoded) == plain


def test_base45_triple_is_high_byte_first():
    """"AB" is 0x4142: one triple, and the 0x41 half must come out first."""
    assert TRANSFORMS["base45"](b"BB8") == b"AB"
    # a swapped read would give b"BA"
    assert TRANSFORMS["base45"](b"BB8") != b"BA"


def test_base45_tail_group_is_one_byte():
    assert TRANSFORMS["base45"](b"QED8WEX0") == b"ietf!"


def test_base45_rejects_an_impossible_group():
    with pytest.raises((ValueError, IndexError)):
        TRANSFORMS["base45"](b":::")


# Z85 reference implementation, test vector from the Z85 specification
def test_z85_matches_the_reference_vector():
    assert _base85_z85(b"nm=QNz.92Pz/PV8") == b"Hello, world"


def test_z85_keeps_its_own_punctuation():
    """'.', '-', ':', '+' and '=' are symbols in the alphabet, not separators.

    The old separator strip removed the '.' here and the length stopped being a
    multiple of five - the decoder then refused input it had just been handed.
    """
    encoded = b"nm=QNz.92Pz/PV8"
    assert _base85_z85(encoded) == b"Hello, world"
    without_dot = encoded.replace(b".", b"")
    assert without_dot != encoded
    with pytest.raises(ValueError):
        _base85_z85(without_dot)


def test_z85_round_trips_the_corpus_encoder():
    alphabet = (b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                b".-:+=^!/*?&<>()[]{}@%$#")
    payload = b"def add(a, b):\n    return a + b\n"
    padded = payload + b"\x00" * (-len(payload) % 4)
    out = bytearray()
    for index in range(0, len(padded), 4):
        value = int.from_bytes(padded[index:index + 4], "big")
        chunk = bytearray()
        for _ in range(5):
            value, rest = divmod(value, 85)
            chunk.append(alphabet[rest])
        out.extend(reversed(chunk))
    assert _base85_z85(bytes(out)).rstrip(b"\x00") == payload
