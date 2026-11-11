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
