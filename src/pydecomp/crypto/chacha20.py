"""pydecomp - chacha20."""
from __future__ import annotations


def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def _chacha_block(key, counter, nonce, rounds=20):
    import struct as _struct
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(_struct.unpack("<8I", key))
    if len(nonce) == 12:                       # RFC 8439: 32-bit counter, 96-bit nonce
        state += [counter & 0xFFFFFFFF]
        state += list(_struct.unpack("<3I", nonce))
    else:                                      # original ChaCha: 64-bit counter, 64-bit nonce
        state += [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]
        state += list(_struct.unpack("<2I", nonce))

    def qr(a, b, c, d):
        x = list(s)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 7)
        for i, v in enumerate(x):
            s[i] = v

    s = list(state)
    for _ in range(rounds // 2):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    out = [(a + b) & 0xFFFFFFFF for a, b in zip(s, state)]
    return _struct.pack("<16I", *out)

def chacha20_xor(key, nonce, data, counter=0):
    out = bytearray()
    for off in range(0, len(data), 64):
        block = _chacha_block(key, counter + off // 64, nonce)
        out.extend(a ^ b for a, b in zip(data[off:off + 64], block))
    return bytes(out)
