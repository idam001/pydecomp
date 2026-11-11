"""pydecomp - fernet."""
from __future__ import annotations

from ..crypto.modes import cbc_decrypt

def fernet_decrypt(token, key):
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac

    if isinstance(token, str):
        token = token.encode()
    if isinstance(key, str):
        key = key.encode()
    raw = _b64.urlsafe_b64decode(token + b"=" * (-len(token) % 4))
    if isinstance(key, str) or len(key) != 32:
        key = _b64.urlsafe_b64decode(key + b"=" * (-len(key) % 4)) if isinstance(key, (str, bytes)) and len(key) != 32 else key
    if len(raw) < 9 + 16 + 32 or raw[0] != 0x80:
        raise ValueError("not a Fernet token")
    signing, enc = key[:16], key[16:]
    signature = raw[-32:]
    expected = _hmac.new(signing, raw[:-32], _hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, signature):
        raise ValueError("Fernet HMAC mismatch")
    return cbc_decrypt(enc, raw[9:25], raw[25:-32])
