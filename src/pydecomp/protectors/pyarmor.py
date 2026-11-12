"""pydecomp - pyarmor static unpack.

PyArmor 8/9 replaces a module with a bootstrap that hands a blob to the native
runtime::

    from pyarmor_runtime_005724 import __pyarmor__
    __pyarmor__(__name__, __file__, b'PY005724\\x00\\x03\\x0b\\x00...')

The blob is ``PY`` + six digits (or ``PYARMOR`` on 7 and earlier), a packed
header, and AES-CTR ciphertext that holds a marshal stream of code objects.
The key is baked into ``pyarmor_runtime_*.so/.pyd``.

This module recovers it statically and, crucially, *verifies* the recovery:

* the header fields (serial, interpreter version, protection type, nonce) are
  parsed with bounds checks, not from assumptions;
* candidate keys are carved from the runtime library, from ``--pyarmor-key``,
  and from 12-byte nonces XORed against a payload nonce;
* every candidate is accepted only if what comes out of AES-CTR **parses as a
  marshal stream containing a code object**.  A wrong key cannot pass that, so
  a hit is proof, not a guess.

Nothing is imported or executed: the plaintext is parsed by the bundled marshal
reader and lifted by the bundled lifter, both of which only ever read bytes.
"""
from __future__ import annotations

import os
import re

from ..bytecode.marshal_reader import parse_marshal_blob
from ..crypto.aes import AES
from ..crypto.modes import ctr_xor

TAG = re.compile(rb"^(PY[A-Za-z0-9]{6}|PYARMOR)\x00?")
_HEX32 = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])")

#: header offsets, from the public research on 8.x/9.x (see docs/pyarmor.md).
_OFF_VERSION = 9          # python major at 9, minor at 10
_OFF_PROTECT = 0x14       # 0x09 = BCC, 0x08 = normal
_OFF_NONCE = 0x2C         # 12-byte AES-CTR nonce
_HEADER = 0x40            # the ciphertext starts at or after this

#: a runtime library is not huge; never let a wrong file cost a run
MAX_RUNTIME = 96 * 1024 * 1024
MAX_TRIES = 6000


class Unpacked:
    """What came out of one blob, and how it was proven."""

    def __init__(self) -> None:
        self.codes: list[tuple[tuple, object]] = []   # [(version, CodeObj)]
        self.key: bytes | None = None
        self.nonce: bytes | None = None
        self.offset = 0
        self.counter_start = 1
        self.tries = 0
        self.runtime = ""
        self.source = ""
        self.note = ""

    @property
    def recovered(self) -> bool:
        return bool(self.codes)

    def summary(self) -> str:
        if not self.recovered:
            return self.note or "no key verified against the payload"
        version = self.codes[0][0]
        return (f"{len(self.codes)} code object(s) recovered · key "
                f"{self.key.hex()[:8]}… verified by marshal structure · "
                f"CPython {version[0]}.{version[1]} · {self.key_source()}"
                f" · {self.tries} candidate(s) tried")

    def key_source(self) -> str:
        return self.source or "key"


def parse_header(blob: bytes) -> dict:
    """Tag, serial, interpreter version, protection type and nonce."""
    info: dict = {"tag": "", "serial": "", "version": None, "protection": "normal",
                  "nonce": b"", "header": b"", "bcc": False, "family": ""}
    match = TAG.match(blob)
    if not match:
        return info
    raw_tag = match.group(1)
    info["tag"] = raw_tag.decode("ascii", "replace")
    info["family"] = "7-" if raw_tag == b"PYARMOR" else "8+"
    tail = raw_tag[2:].decode("ascii", "replace")
    info["serial"] = tail if tail.isdigit() else ""
    end = match.end()
    info["header"] = blob[end:end + _HEADER]
    if info["family"] == "8+" and len(blob) > _OFF_VERSION + 1:
        major, minor = blob[_OFF_VERSION], blob[_OFF_VERSION + 1]
        if 2 <= major <= 4 and 0 <= minor <= 40:
            info["version"] = (major, minor)
    if len(blob) > _OFF_PROTECT:
        info["bcc"] = blob[_OFF_PROTECT] == 0x09
        info["protection"] = "bcc" if info["bcc"] else "normal"
    if len(blob) > _OFF_NONCE + 12:
        info["nonce"] = blob[_OFF_NONCE:_OFF_NONCE + 12]
    return info


NAME = "pyarmor"


def is_pyarmor(blob: bytes) -> bool:
    return bool(TAG.match(blob or b""))


def detect(data: bytes) -> bool:
    """Bytes from a PyArmor build: the tag, or the bootstrap that carries it."""
    if not data:
        return False
    return is_pyarmor(data) or b"__pyarmor__" in data[:8192]


def detect_source(text: str) -> bool:
    return "__pyarmor__" in text or "pyarmor_runtime" in text


def candidate_nonces(blob: bytes, header: dict) -> list[bytes]:
    """Every 12-byte window that a runtime could be using as the counter nonce."""
    out: list[bytes] = []
    if header.get("nonce"):
        out.append(header["nonce"])
    for offset in (0x2C, 0x30, 0x34, 0x38, 0x3C, 0x20, 0x24, 0x28, 0x18):
        window = blob[offset:offset + 12]
        if len(window) == 12 and window not in out:
            out.append(window)
    tail = blob[-12:]
    if len(tail) == 12 and tail not in out:
        out.append(tail)
    zero = bytes(12)
    if zero not in out:
        out.append(zero)
    return out


def _carved_keys(data: bytes, limit: int = 4096) -> list[bytes]:
    """AES keys hiding in a native runtime: hex text and raw byte windows."""
    if not data:
        return []
    keys: list[bytes] = []
    for match in _HEX32.finditer(data[:MAX_RUNTIME]):
        try:
            keys.append(bytes.fromhex(match.group(1).decode("ascii")))
        except ValueError:
            continue
        if len(keys) >= limit:
            return keys
    # raw 16-byte runs that look like a key: high entropy, not run-of-the-mill
    window = data[:MAX_RUNTIME]
    step = 1 if len(window) <= 65536 else 4
    for offset in range(0, max(len(window) - 16, 0), step):
        chunk = window[offset:offset + 16]
        if len(set(chunk)) >= 12 and chunk not in keys:
            keys.append(chunk)
        if len(keys) >= limit:
            break
    return keys


def candidate_keys(blob: bytes, runtime: bytes = b"",
                   key: bytes | None = None) -> list[tuple[bytes, str]]:
    """(key, where it came from) pairs worth trying, best first."""
    out: list[tuple[bytes, str]] = []
    if key:
        out.append((key, "supplied key"))
    for match in _HEX32.finditer(blob[:4096]):
        try:
            out.append((bytes.fromhex(match.group(1).decode("ascii")), "in the loader"))
        except ValueError:
            continue
    for found in _carved_keys(runtime):
        out.append((found, "carved from the runtime"))
    seen = set()
    unique = []
    for value, source in out:
        if len(value) in (16, 24, 32) and value not in seen:
            seen.add(value)
            unique.append((value, source))
    return unique


def _decrypt(cipher: bytes, key: bytes, nonce: bytes, start: int) -> bytes:
    return ctr_xor(AES(key), nonce, cipher, counter_bits=32, start=start)


def _looks_like_marshal(plain: bytes) -> bool:
    if not plain:
        return False
    return plain[0] in (0x63, 0xE3, 0x29, 0x28, 0x5B, 0x7B)   # code / tuple / list / dict


def unpack(blob: bytes, runtime: bytes = b"", key: bytes | None = None,
           max_tries: int = MAX_TRIES) -> Unpacked:
    """Recover code objects from an encrypted PyArmor 8/9 blob, statically."""
    result = Unpacked()
    header = parse_header(blob)
    if not is_pyarmor(blob):
        result.note = "not a PyArmor blob"
        return result
    if header["family"] == "7-":
        result.note = ("PyArmor 7 and earlier: the payload is protected by the "
                       "runtime's own encoder, not an AES-CTR stream - carved "
                       "strings and the bootstrap are what the file holds")
        return result
    if not runtime and not key:
        result.note = ("PyArmor 8+ blob: supply the matching runtime library "
                       "(or --pyarmor-key) and the code objects come out")
        return result

    keys = candidate_keys(blob, runtime, key)
    nonces = candidate_nonces(blob, header)
    versions = [header["version"]] if header["version"] else []
    versions += [(3, 13), (3, 12), (3, 14), (3, 11), (3, 10), (3, 9), (3, 8), (3, 15)]
    body = blob[len(blob) - len(blob[_HEADER:]):]
    offsets = [len(blob) - len(body)]
    for extra in (0, 4, 8, 12, 16, 0x20):
        candidate = len(blob) - len(body) + extra
        if candidate < len(blob) and candidate not in offsets:
            offsets.append(candidate)

    for guess_key, where in keys:
        for nonce in nonces:
            for start in (1, 0):
                tries = 0
                for offset in offsets:
                    for length in (len(blob) - offset,):
                        cipher = blob[offset:offset + length]
                        if len(cipher) < 32:
                            continue
                        tries += 1
                        probe = _decrypt(cipher[:32], guess_key, nonce, start)
                        if not _looks_like_marshal(probe):
                            continue
                        plain = _decrypt(cipher, guess_key, nonce, start)
                        version, code, _score = parse_marshal_blob(plain)
                        result.tries += 1
                        if code is None:
                            continue
                        result.codes.append((version, code))
                        result.key, result.nonce = guess_key, nonce
                        result.offset, result.counter_start = offset, start
                        result.source = where
                        result.note = "verified by marshal structure"
                        return result
                result.tries += tries
                if result.tries > max_tries:
                    result.note = (f"stopped after {result.tries:,} candidate(s) - "
                                   "no key opened this payload; pass --pyarmor-key")
                    return result
    result.note = (f"{result.tries:,} key/nonce combination(s) tried, none "
                   "produced a marshal stream; pass --pyarmor-key with the "
                   "runtime key, or --pyarmor-runtime with the library")
    return result


# --------------------------------------------------------------- runtime hunt
_RUNTIME_NAME = re.compile(r"pyarmor[_-]?runtime", re.IGNORECASE)
_RUNTIME_EXT = (".so", ".pyd", ".dylib", ".dll", ".bin", "")


def find_runtime(start: str | os.PathLike | None, depth: int = 3) -> str | None:
    """The nearest ``pyarmor_runtime_*`` library to the sample."""
    if not start:
        return None
    folder = os.path.abspath(os.fspath(start))
    if os.path.isfile(folder):
        folder = os.path.dirname(folder)
    for _ in range(depth + 1):
        try:
            entries = sorted(os.listdir(folder))
        except OSError:
            break
        for entry in entries:
            path = os.path.join(folder, entry)
            if _RUNTIME_NAME.search(entry) and os.path.isfile(path) \
                    and entry.lower().endswith(_RUNTIME_EXT):
                return path
            if _RUNTIME_NAME.search(entry) and os.path.isdir(path):
                try:
                    for inner in sorted(os.listdir(path)):
                        candidate = os.path.join(path, inner)
                        if os.path.isfile(candidate) and inner.lower().endswith(_RUNTIME_EXT):
                            return candidate
                except OSError:
                    continue
        parent = os.path.dirname(folder)
        if parent == folder:
            break
        folder = parent
    return None


def read_runtime(path: str | None) -> bytes:
    if not path:
        return b""
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_RUNTIME)
    except OSError:
        return b""


# ------------------------------------------------------------------ context
_CONTEXT: dict = {"runtime": b"", "key": None, "runtime_path": ""}


def set_context(path: str | None = None, runtime_path: str | None = None,
                key: bytes | None = None) -> None:
    """Point the engine at the runtime library for the sample being read.

    The library is looked for beside the sample when it is not named: that is
    where a real build puts it (``pyarmor_runtime_000000/`` next to the
    scripts), so the operator never has to hunt for it.
    """
    _CONTEXT["key"] = key
    _CONTEXT["runtime"] = b""
    _CONTEXT["runtime_path"] = ""
    if runtime_path:
        _CONTEXT["runtime_path"] = runtime_path
        _CONTEXT["runtime"] = read_runtime(runtime_path)
        return
    found = find_runtime(path, depth=2) if path else None
    if found:
        _CONTEXT["runtime_path"] = found
        _CONTEXT["runtime"] = read_runtime(found)


def context() -> dict:
    return dict(_CONTEXT)


# ------------------------------------------------------------ mixed strings
def decrypt_strings(consts, key: bytes, nonce: bytes) -> list[str]:
    """PyArmor's 'mixed' constants: ``b'\\x81' + AES-CTR ciphertext``."""
    out: list[str] = []
    if not key:
        return out
    for const in consts or ():
        if not isinstance(const, (bytes, bytearray)) or len(const) < 4:
            continue
        if const[0] not in (0x81, 0x01):
            continue
        plain = _decrypt(bytes(const[1:]), key, nonce, 1)
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.isprintable() and text not in out:
            out.append(text)
    return out


def note(header: dict) -> str:
    """One line describing the protection, for the trace and the report."""
    family = header.get("family") or "8+"
    if family == "7-":
        return "PyArmor 7 or earlier (PYARMOR header) - runtime-encoded payload"
    bits = [f"PyArmor {family} blob", f"serial {header.get('serial') or '?'}"]
    if header.get("version"):
        version = header["version"]
        bits.append(f"CPython {version[0]}.{version[1]}")
    if header.get("bcc"):
        bits.append("BCC (C functions)")
    bits.append("AES-CTR across the code objects")
    return " · ".join(bits)
