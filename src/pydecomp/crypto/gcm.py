"""pydecomp - gcm."""
from __future__ import annotations

from ..crypto.aes import AES
from ..crypto.modes import ctr_xor

def _gf_mult(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z

def _ghash(h, data):
    y = 0
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        if len(block) < 16:
            block = block + b"\0" * (16 - len(block))
        y = _gf_mult(y ^ int.from_bytes(block, "big"), h)
    return y

def _gcm_tag(cipher, nonce, ciphertext, aad=b""):
    h = int.from_bytes(cipher.encrypt_block(b"\0" * 16), "big")
    if len(nonce) == 12:
        j0 = nonce + b"\0\0\0\1"
    else:
        padded = nonce + b"\0" * ((16 - len(nonce) % 16) % 16)
        j0 = _ghash(h, padded + (0).to_bytes(8, "big") + (len(nonce) * 8).to_bytes(8, "big")).to_bytes(16, "big")
    payload = aad + b"\0" * ((16 - len(aad) % 16) % 16)
    payload += ciphertext + b"\0" * ((16 - len(ciphertext) % 16) % 16)
    payload += (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    mask = int.from_bytes(cipher.encrypt_block(j0), "big")
    return (mask ^ _ghash(h, payload)).to_bytes(16, "big"), j0

def gcm_decrypt(key, nonce, data, aad=b""):
    """AES-GCM open: data is ciphertext||tag; raises ValueError on a bad tag."""
    cipher = AES(key)
    if len(data) < 16:
        raise ValueError("GCM data shorter than the 16-byte tag")
    ciphertext, tag = data[:-16], data[-16:]
    expected, j0 = _gcm_tag(cipher, nonce, ciphertext, aad)
    if expected != tag:
        raise ValueError("GCM authentication failed")
    ctr_nonce = j0[:12]
    out = ctr_xor(cipher, ctr_nonce, ciphertext, start=2)
    return out

def gcm_encrypt(key, nonce, plaintext, aad=b""):
    """Only used by the gates to build vectors."""
    cipher = AES(key)
    j0 = nonce + b"\0\0\0\1" if len(nonce) == 12 else None
    if j0 is None:
        raise ValueError("gates use 96-bit nonces")
    ciphertext = ctr_xor(cipher, nonce, plaintext, start=2)
    tag, _ = _gcm_tag(cipher, nonce, ciphertext, aad)
    return ciphertext + tag
