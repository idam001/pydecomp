"""pydecomp - pyobfuscate.com.

The paid tier of pyobfuscate.com ships a payload that no pattern matcher gets
through: the source is AES-GCM encrypted, base85 encoded, and the password sits
in the same file buried among look-alike ``l``/``I`` identifiers.

The wrapper is small and rigid::

    pyobfuscate({'pyc': \"\"\"<b85>\"\"\", 'pye': \"\"\"<b85>\"\"\", 'lIlIIl': \"\"\"…\"\"\"})

and the key schedule, worked out by the analysts who reversed it, is::

    blob  = b85decode(pyc + pye)
    key   = PBKDF2(password, blob[:16], sha256, 1_000_000, dklen=32)
    nonce = blob[16:32]      tag = blob[32:48]      ciphertext = blob[48:]
    source = AESGCM(key).decrypt(nonce, ciphertext || tag, None)

That is a *key schedule*, not a secret: everything it needs is in the file, so
pydecomp can derive the same key offline and decrypt without ever running the
sample.  Older/alternative builds wrap the same blob in PBKDF2 + AES-CBC, so both
layouts are attempted and the result is validated (printable, and it parses or
decompresses) before it is trusted.

Note the honesty rule: if the password is not in the file - some builds take it
from a server - the ciphertext is emitted for the analyst and the report says so.
"""
from __future__ import annotations

import base64
import re
import zlib

from ..crypto.gcm import gcm_decrypt
from ..crypto.kdf import pbkdf2_hmac_sha256
from ..crypto.modes import cbc_decrypt, ecb_decrypt

_KEYS = ("pyc", "pye")
_DICT = re.compile(r"pyobfuscate\s*\(\s*\{(.*)\}\s*\)", re.DOTALL)
_FIELD = re.compile(r"['\"]?(pyc|pye|key|pass|password|licence|license)['\"]?\s*:\s*"
                    r"(\"\"\"(?:.*?)\"\"\"|'''(?:.*?)'''|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")",
                    re.DOTALL)
_WORD = re.compile(r"['\"]([lI]{4,})['\"]")

_ITERATIONS = (1_000_000, 100_000, 200_000, 10_000)
_LAYOUTS = ("gcm", "cbc", "ecb")


def is_pyobfuscate(text: str) -> bool:
    return "pyobfuscate(" in text and ("'pyc'" in text or '"pyc"' in text)


def _unquote(literal: str) -> str:
    if literal[:3] in ('"""', "'''"):
        return literal[3:-3]
    return literal[1:-1]


def _fields(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for name, literal in _FIELD.findall(text):
        value = _unquote(literal)
        found.setdefault(name, value)
        if name in ("key", "pass", "password"):
            found.setdefault("password", value)
    return found


def _password(text: str) -> str | None:
    for candidate in _WORD.findall(text):
        return candidate
    return None


def _b85(blob: str) -> bytes | None:
    cleaned = "".join(blob.split())
    try:
        return base64.b85decode(cleaned.encode("ascii", "ignore"))
    except Exception:                                  # noqa: BLE001
        try:
            return base64.b85decode(cleaned.encode("ascii", "ignore") + b"Y")
        except Exception:                              # noqa: BLE001
            return None


def _plausible(payload: bytes) -> bool:
    if not payload or len(payload) < 8:
        return False
    head = payload[:2]
    if head == b"\x1f\x8b" or head in (b"x\x9c", b"x\xda", b"x\x01"):
        try:
            zlib.decompress(payload)
            return True
        except zlib.error:
            pass
    sample = payload[:4096]
    printable = sum(1 for byte in sample if 9 <= byte <= 13 or 32 <= byte < 127)
    return printable >= len(sample) * 0.85


def _try(payload: bytes) -> str | bytes | None:
    if payload[:2] == b"\x1f\x8b":
        try:
            import gzip
            return gzip.decompress(payload)
        except Exception:                              # noqa: BLE001
            pass
    for prefix in (b"x\x9c", b"x\xda", b"x\x01"):
        if payload[:2] == prefix:
            try:
                return zlib.decompress(payload)
            except zlib.error:
                break
    return payload if _plausible(payload) else None        # noqa: BLE001


def decrypt(text: str) -> tuple[bytes | None, dict]:
    """Try every documented layout.  Returns (plaintext, facts)."""
    facts: dict = {"layout": None, "iterations": None, "reason": ""}
    fields = _fields(text)
    if not all(key in fields for key in _KEYS):
        facts["reason"] = "pyc/pye fields not found"
        return None, facts
    blob = _b85(fields["pyc"] + fields["pye"])
    if blob is None or len(blob) < 48:
        facts["reason"] = "payload is not valid base85"
        return None, facts
    password = fields.get("password") or _password(text)
    if not password:
        facts["reason"] = "no password literal in the file (fetched at runtime?)"
        facts["blob"] = blob
        return None, facts
    salt, nonce, tag, ciphertext = blob[:16], blob[16:32], blob[32:48], blob[48:]
    for iterations in _ITERATIONS:
        key = pbkdf2_hmac_sha256(password, salt, iterations, 32)
        candidate = None
        try:                                           # AES-GCM (current builds)
            candidate = gcm_decrypt(key, nonce, ciphertext + tag)
            facts["layout"] = "aes-gcm"
        except Exception:                              # noqa: BLE001
            candidate = None
        if not candidate:
            for layout in ("cbc", "ecb"):
                try:                                   # older PBKDF2 + AES-CBC
                    if layout == "cbc":
                        candidate = cbc_decrypt(key, nonce, ciphertext)
                    else:
                        candidate = ecb_decrypt(key, ciphertext)
                    facts["layout"] = f"aes-{layout}"
                except Exception:                      # noqa: BLE001
                    candidate = None
                if candidate:
                    break
        if not candidate:
            continue
        recovered = _try(candidate)
        if recovered is None:
            continue
        facts["iterations"] = iterations
        if isinstance(recovered, str):
            recovered = recovered.encode("utf-8", "surrogateescape")
        return recovered, facts
    facts["reason"] = "ciphertext did not open with any documented key schedule"
    facts["blob"] = blob
    return None, facts


def note(facts: dict) -> str:
    if facts.get("layout"):
        return (f"pyobfuscate.com payload decrypted statically · {facts['layout']} · "
                f"PBKDF2-SHA256 × {facts['iterations']:,}")
    return f"pyobfuscate.com container: {facts.get('reason', 'not opened')}"
