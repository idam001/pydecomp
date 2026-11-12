"""pydecomp - magic."""
from __future__ import annotations

import sys

from ..bytecode.codeobj import CodeObj
from ..bytecode.marshal_reader import MarshalReader

MAGIC_VERSIONS_BYTES = frozenset(
    m.to_bytes(2, "little") for m in
    (3413, 3425, 3439, 3495, 3531, 3571, 3627, 3666))

MAGIC_VERSIONS = {
    3413: (3, 8), 3425: (3, 9), 3439: (3, 10), 3495: (3, 11),
    3531: (3, 12), 3571: (3, 13), 3627: (3, 14), 3666: (3, 15),
}

def parse_pyc(data: bytes):
    """(version, module CodeObj) for a .pyc blob, or (None, None)."""
    if len(data) < 17:
        return None, None
    magic = int.from_bytes(data[:2], "little")
    version = MAGIC_VERSIONS.get(magic)
    if version is None:
        return None, None
    for skip in (16, 12, 8):                             # 3.7+ / 3.3-3.6 / older
        try:
            reader = MarshalReader(data[skip:], version)
            obj = reader.object()
            if isinstance(obj, CodeObj):
                return version, obj
        except Exception:
            continue
    return version, None

def host_version() -> tuple:
    return sys.version_info[:2]


# --------------------------------------------------------------- interpreters
#: Not every Python is CPython.  A signature table beats guessing from contents:
#: each entry is the smallest thing that identifies the writer of these bytes.
IMPLEMENTATIONS = {
    "pypy": (b"\x0a\x0d\x0d\x0a", b"\x00\x0a\x0d\x0a"),
    "micropython": (b"M\x00", b"M\x01", b"M\x02", b"M\x03", b"M\x04",
                    b"M\x05", b"M\x06"),
    "jython": (b"\xca\xfe\xba\xbe",),
    "brython": (b"__BRYTHON__",),
}

#: what a lift from each one can honestly claim
APPROXIMATION = {
    "cpython": "",
    "pypy": "lifted with the closest CPython table - approximate",
    "micropython": "MicroPython .mpy: strings and structure only",
    "jython": "Jython class file: strings and structure only",
    "ironpython": "IronPython assembly: strings and structure only",
    "brython": "Brython: Python that runs in a browser - read as source",
}


def identify_implementation(data: bytes) -> dict:
    """``{implementation, version, confidence, note}`` for these bytes."""
    info = {"implementation": "unknown", "version": None, "confidence": 0.0,
            "note": ""}
    if not data:
        return info
    magic = int.from_bytes(data[:2], "little") if len(data) >= 2 else -1
    if len(data) >= 4 and data[2:4] == b"\r\n" and magic in MAGIC_VERSIONS:
        info.update(implementation="cpython", version=MAGIC_VERSIONS[magic],
                    confidence=1.0)
        return info
    for name, signatures in IMPLEMENTATIONS.items():
        for signature in signatures:
            if data[:len(signature)] == signature:
                info.update(implementation=name, confidence=0.9)
                info["note"] = APPROXIMATION.get(name, "")
                return info
    if data[:2] == b"MZ" and b"IronPython" in data[:1 << 20]:
        info.update(implementation="ironpython", confidence=0.8,
                    note=APPROXIMATION["ironpython"])
        return info
    if b"__BRYTHON__" in data[:8192]:
        info.update(implementation="brython", confidence=0.7,
                    note=APPROXIMATION["brython"])
    return info
