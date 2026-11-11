"""pydecomp - aes."""
from __future__ import annotations


"""Pure-python AES (128/192/256) core: key schedule + block encrypt/decrypt."""

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

INV_SBOX = bytes(SBOX.index(bytes([i])) if False else 0 for i in range(256))

INV = bytearray(256)

for _i, _v in enumerate(SBOX):
    INV[_v] = _i

INV_SBOX = bytes(INV)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D]

def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a

def _mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out

MUL = {k: [_mul(i, k) for i in range(256)] for k in (2, 3, 9, 11, 13, 14)}

class AES:
    """Minimal AES block cipher.  Key may be 16, 24 or 32 bytes."""

    def __init__(self, key):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16/24/32 bytes, got {len(key)}")
        self.nk = len(key) // 4
        self.rounds = self.nk + 6
        self.round_keys = self._expand(key)

    def _expand(self, key):
        nk, nr = self.nk, self.rounds
        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        total = 4 * (nr + 1)
        for i in range(nk, total):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        return words

    def encrypt_block(self, block):
        s = [b ^ k for b, k in zip(block, self._flat(0))]
        for rnd in range(1, self.rounds):
            s = [SBOX[b] for b in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]     # ShiftRows
            if rnd != self.rounds:
                s = self._mix(s)
            keys = self._flat(rnd)
            s = [b ^ k for b, k in zip(s, keys)]
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        return bytes(b ^ k for b, k in zip(s, self._flat(self.rounds)))

    def _flat(self, rnd):
        out = []
        for w in self.round_keys[4 * rnd:4 * rnd + 4]:
            out.extend(w)
        return out

    @staticmethod
    def _mix(s):
        m2, m3 = MUL[2], MUL[3]
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            out[4 * c + 0] = m2[a0] ^ m3[a1] ^ a2 ^ a3
            out[4 * c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
            out[4 * c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
            out[4 * c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
        return out

    def decrypt_block(self, block):
        s = [b ^ k for b, k in zip(block, self._flat(self.rounds))]
        for rnd in range(self.rounds - 1, 0, -1):
            s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]      # InvShiftRows
            s = [INV_SBOX[b] for b in s]
            s = [b ^ k for b, k in zip(s, self._flat(rnd))]
            s = self._inv_mix(s)
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]
        s = [INV_SBOX[b] for b in s]
        return bytes(b ^ k for b, k in zip(s, self._flat(0)))

    @staticmethod
    def _inv_mix(s):
        m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            out[4 * c + 0] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
            out[4 * c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
            out[4 * c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
            out[4 * c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
        return out
