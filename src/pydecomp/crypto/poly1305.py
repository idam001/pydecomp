"""pydecomp - poly1305."""
from __future__ import annotations

from ..crypto.chacha20 import _chacha_block, chacha20_xor

def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    prime = (1 << 130) - 5
    acc = 0
    for off in range(0, len(msg), 16):
        block = msg[off:off + 16]
        acc = ((acc + int.from_bytes(block + b"\x01", "little")) * r) % prime
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def _chacha20poly1305_keys(key, nonce):
    one_time = _chacha_block(key, 0, nonce)[:32]
    return one_time

def chacha20poly1305_open(key, nonce, data, aad=b""):
    if len(data) < 16:
        raise ValueError("AEAD data shorter than the tag")
    ciphertext, tag = data[:-16], data[-16:]
    otk = _chacha20poly1305_keys(key, nonce)
    mac_data = aad + b"\0" * ((16 - len(aad) % 16) % 16)
    mac_data += ciphertext + b"\0" * ((16 - len(ciphertext) % 16) % 16)
    mac_data += len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    if poly1305_mac(mac_data, otk) != tag:
        raise ValueError("ChaCha20-Poly1305 authentication failed")
    return chacha20_xor(key, nonce, ciphertext, counter=1)

def chacha20poly1305_seal(key, nonce, plaintext, aad=b""):
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    otk = _chacha20poly1305_keys(key, nonce)
    mac_data = aad + b"\0" * ((16 - len(aad) % 16) % 16)
    mac_data += ciphertext + b"\0" * ((16 - len(ciphertext) % 16) % 16)
    mac_data += len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    return ciphertext + poly1305_mac(mac_data, otk)
