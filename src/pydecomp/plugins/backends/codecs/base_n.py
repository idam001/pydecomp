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


#: 58 and 62 divide a big integer, so the work grows with the square of the
#: blob: a 300 KB literal costs minutes and is not a base-N payload
MAX_BASE_TEXT = 64 << 10

#: the decoder registry spells these out; a backend name is the short form
REGISTRY_NAME = {"b58": "base58", "b62": "base62", "b45": "base45", "z85": "z85"}


def _opener(codec: str):
    def open_with_table(blob: bytes) -> bytes | None:
        if len(blob) > MAX_BASE_TEXT:
            return None
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


#: RFC 9285's alphabet, in the order the decoder indexes it
B45_ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

#: ZeroMQ's alphabet
Z85_ALPHABET = (b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                b".-:+=^!/*?&<>()[]{}@%$#")


def _forge_b45(payload: bytes) -> bytes:
    out = bytearray()
    for index in range(0, len(payload) - len(payload) % 2, 2):
        value = payload[index] * 256 + payload[index + 1]
        out.extend((B45_ALPHABET[value % 45],
                    B45_ALPHABET[(value // 45) % 45],
                    B45_ALPHABET[value // 2025]))
    if len(payload) % 2:
        out.extend((B45_ALPHABET[payload[-1] % 45], B45_ALPHABET[payload[-1] // 45]))
    return bytes(out)


def _forge_z85(payload: bytes) -> bytes:
    padded = payload + b"\x00" * (-len(payload) % 4)
    out = bytearray()
    for index in range(0, len(padded), 4):
        value = int.from_bytes(padded[index:index + 4], "big")
        group = bytearray(5)
        for slot in range(4, -1, -1):
            value, digit = divmod(value, 85)
            group[slot] = Z85_ALPHABET[digit]
        out.extend(group)
    return bytes(out)


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
            forge={"b58": _forger("b58"), "b62": _forger("b62"),
                   "b45": _forge_b45, "z85": _forge_z85}[codec])
    for codec in ("b58", "b62", "b45", "z85")
]
