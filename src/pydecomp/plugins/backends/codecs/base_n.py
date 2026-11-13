"""The bases with no stdlib codec: 58, 62, 45 and 85's z-machine spelling.

A loader that carries one of these has to spell the alphabet out, and the
decoders in ``pydecomp.decoders`` already own the arithmetic.  This tree only
names the backend and gives the explorer a charset opinion.
"""

from __future__ import annotations

from ..spec import Backend
from .._share import share

ALPHABETS = {
    "b58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "b62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "b45": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:",
    "z85": ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            ".-:+=^!/*?&<>()[]{}@%$#"),
}


#: the decoder registry spells these out; a backend name is the short form
REGISTRY_NAME = {"b58": "base58", "b62": "base62", "b45": "base45", "z85": "z85"}


def _opener(codec: str):
    def open_with_table(blob: bytes) -> bytes | None:
        from ....decoders.registry import TRANSFORMS
        decode = TRANSFORMS.get(REGISTRY_NAME.get(codec, codec))
        if decode is None:
            return None
        return decode(bytes(blob))

    return open_with_table


def _sniffer(codec: str):
    allowed = frozenset(ALPHABETS[codec].encode())

    def sniff(blob: bytes) -> float:
        if len(blob) < 16:
            return 0.0
        return 0.9 * share(blob, allowed)

    return sniff


def _forger(codec: str):
    alphabet = ALPHABETS[codec].encode()

    def forge(payload: bytes) -> bytes:
        number = int.from_bytes(payload, "big") or 0
        base = len(alphabet)
        digits = bytearray()
        while number:
            number, remainder = divmod(number, base)
            digits.append(alphabet[remainder])
        return bytes(digits[::-1]) or bytes(alphabet[:1])

    return forge


BACKENDS = [
    Backend(codec, "codec", 1, _opener(codec), _sniffer(codec),
            f"{codec} with its documented alphabet",
            forge=_forger(codec) if codec in ("b58", "b62") else None)
    for codec in ("b58", "b62", "b45", "z85")
]
