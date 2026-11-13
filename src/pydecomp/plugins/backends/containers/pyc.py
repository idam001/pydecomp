"""A .pyc without its header is a marshal stream, and vice versa.

The 16-byte header is four fields: a magic that names the CPython version, two
flags words, and either a timestamp and size or a hash.  Dropping it is the step
between "this file is opaque" and "this file is a code object", and the version
in that magic is the one the rest of the pipeline should read the code with.
"""

from __future__ import annotations

from ..spec import Backend

HEADER = 16
MAGIC_TAIL = (b"\r\n", b"\n\r")

#: a magic word for a version this pipeline knows, then the twelve header bytes
PYTHON_MAGIC = b"3\r\r\n"


def _is_pyc(blob: bytes) -> bool:
    return len(blob) > HEADER and blob[2:4] in MAGIC_TAIL


def _strip_header(blob: bytes) -> bytes | None:
    if not _is_pyc(blob):
        return None
    body = bytes(blob[HEADER:])
    return body or None


def _add_header(blob: bytes) -> bytes | None:
    # the reverse: a bare marshal stream that the pipeline wants as a pyc
    from ...bytecode.magic import MAGIC_VERSIONS_BYTES
    if _is_pyc(blob) or blob[:2] in MAGIC_VERSIONS_BYTES:
        return None
    from ...bytecode.marshal_reader import parse_marshal_blob
    try:
        _version, obj, _layout = parse_marshal_blob(bytes(blob))
    except Exception:                                    # noqa: BLE001
        return None
    if obj is None:
        return None
    return bytes(blob)     # a marshal stream is already a payload candidate


BACKENDS = [
    Backend("pycstrip", "container", 0, _strip_header, None,
            "the marshal stream inside a .pyc header",
            forge=lambda payload: PYTHON_MAGIC + b"\x00" * 12 + bytes(payload)),
    Backend("marshalled", "container", 1, _add_header, None,
            "a bare marshal stream, read as code"),
]
