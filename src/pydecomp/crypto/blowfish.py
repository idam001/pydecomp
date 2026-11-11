"""pydecomp - blowfish."""
from __future__ import annotations

from ..crypto.des import _des_block, _des_subkeys
from ..crypto.modes import _unpad

_PI_WORDS = None

def _pi_hex_words(count: int) -> list[int]:
    """The first ``count`` 32-bit words of pi's fractional hex expansion."""
    prec = 32 * count + 96
    one = 1 << prec

    def atan_inv(x: int) -> int:
        total = term = one // x
        n, x2, sign = 1, x * x, 1
        while term:
            term //= x2
            n += 2
            sign = -sign
            total += sign * (term // n)
        return total

    pi = 4 * (4 * atan_inv(5) - atan_inv(239))       # Machin's formula
    frac = pi - 3 * one
    return [(frac >> (prec - 32 * (index + 1))) & 0xFFFFFFFF for index in range(count)]

class Blowfish:
    """Blowfish (Schneier 1993) in ECB, enough for obfuscator payloads."""

    def __init__(self, key: bytes):
        global _PI_WORDS
        if _PI_WORDS is None:
            _PI_WORDS = _pi_hex_words(1042)
        words = list(_PI_WORDS)
        self.p = words[:18]
        self.s = [words[18:18 + 256], words[274:274 + 256],
                  words[530:530 + 256], words[786:786 + 256]]
        key = bytes(key) or b"\x00"
        index = 0
        for position in range(18):
            value = 0
            for _ in range(4):
                value = (value << 8) | key[index % len(key)]
                index += 1
            self.p[position] ^= value
        left = right = 0
        for position in range(0, 18, 2):
            left, right = self._encrypt_pair(left, right)
            self.p[position], self.p[position + 1] = left, right
        for box in range(4):
            for position in range(0, 256, 2):
                left, right = self._encrypt_pair(left, right)
                self.s[box][position], self.s[box][position + 1] = left, right

    def _f(self, value: int) -> int:
        s = self.s
        return (((s[0][(value >> 24) & 0xFF] + s[1][(value >> 16) & 0xFF]) & 0xFFFFFFFF)
                ^ s[2][(value >> 8) & 0xFF]) + s[3][value & 0xFF] & 0xFFFFFFFF

    def _encrypt_pair(self, left: int, right: int) -> tuple[int, int]:
        for index in range(16):
            left ^= self.p[index]
            right ^= self._f(left)
            left, right = right, left
        left, right = right, left
        right ^= self.p[16]
        left ^= self.p[17]
        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    def _decrypt_pair(self, left: int, right: int) -> tuple[int, int]:
        for index in range(17, 1, -1):
            left ^= self.p[index]
            right ^= self._f(left)
            left, right = right, left
        left, right = right, left
        right ^= self.p[1]
        left ^= self.p[0]
        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    def encrypt_block(self, block: bytes) -> bytes:
        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:8], "big")
        left, right = self._encrypt_pair(left, right)
        return left.to_bytes(4, "big") + right.to_bytes(4, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:8], "big")
        left, right = self._decrypt_pair(left, right)
        return left.to_bytes(4, "big") + right.to_bytes(4, "big")

def blowfish_cbc_decrypt(key: bytes, iv: bytes, data: bytes, unpad: bool = True) -> bytes:
    cipher = Blowfish(key)
    previous = (bytes(iv) + b"\x00" * 8)[:8]
    out = bytearray()
    for offset in range(0, len(data) - len(data) % 8, 8):
        block = data[offset:offset + 8]
        plain = cipher.decrypt_block(block)
        out.extend(bytes(a ^ b for a, b in zip(plain, previous)))
        previous = block
    return _unpad(bytes(out)) if unpad and out else bytes(out)

def blowfish_ecb_decrypt(key: bytes, data: bytes, unpad: bool = True) -> bytes:
    cipher = Blowfish(key)
    out = b"".join(cipher.decrypt_block(data[offset:offset + 8])
                   for offset in range(0, len(data) - len(data) % 8, 8))
    return _unpad(out) if unpad and out else out

def des_ecb_decrypt(key: bytes, data: bytes, unpad: bool = True) -> bytes:
    subkeys = _des_subkeys(key)
    out = b"".join(_des_block(data[o:o + 8], subkeys, True)
                   for o in range(0, len(data) - len(data) % 8, 8))
    return _unpad(out) if unpad and out else out
