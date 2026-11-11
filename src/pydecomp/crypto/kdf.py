"""pydecomp - kdf.

PBKDF2-HMAC-SHA256, the key derivation every "encrypted payload" packer reaches
for.  ``hashlib.pbkdf2_hmac`` exists on CPython 3, but this module keeps a pure
implementation so the tool behaves identically on builds where OpenSSL is
missing (and so the iteration count is visible in one place).

Packers we have seen in the wild and the counts they use:

    pyobfuscate.com v2     PBKDF2(password, salt16, 1_000_000, sha256, 32)
    pyconcrete            PBKDF2(passphrase, salt8, 100_000, sha256, 32)
    hand-rolled loaders   10_000 - 200_000
"""
from __future__ import annotations

import hashlib
import hmac


def pbkdf2_hmac_sha256(password, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8", "surrogateescape")
    iterations = max(int(iterations), 1)
    if dklen <= 0:
        return b""
    try:                                     # C implementation when available
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)
    except (AttributeError, ValueError):     # pragma: no cover - pure fallback
        return _pure_pbkdf2(password, salt, iterations, dklen)


def _pure_pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    blocks = (dklen + 31) // 32
    out = bytearray()
    for index in range(1, blocks + 1):
        message = salt + index.to_bytes(4, "big")
        u = hmac.new(password, message, hashlib.sha256).digest()
        acc = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha256).digest()
            acc ^= int.from_bytes(u, "big")
        out.extend(acc.to_bytes(32, "big"))
    return bytes(out[:dklen])
