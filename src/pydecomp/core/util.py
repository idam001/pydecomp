"""pydecomp - util."""
from __future__ import annotations

from typing import Any, Iterable
import ast
import bz2
import gzip
import io
import lzma
import zlib

from ..exceptions import EvalFailed
from ..limits import MAX_DECOMPRESSED

def to_bytes(v: Any) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    if isinstance(v, str):
        return v.encode("utf-8", "surrogateescape")
    raise EvalFailed(f"cannot treat {type(v).__name__} as bytes")

def _cap(data):
    if len(data) > MAX_DECOMPRESSED:
        raise EvalFailed("decompressed output exceeds size cap")
    return data

def _inflate(d: Any, data: bytes) -> bytes:
    """Decompress with a hard output cap where the stdlib allows it.

    NOTE: dispatch is by module *identity*. `isinstance(x, type(zlib))` would be
    true for every module (module is a type), which silently sent bz2/lzma/gzip
    blobs down the zlib path. Keep these as identity checks.
    """
    data = to_bytes(data)
    if d is zlib:
        obj = zlib.decompressobj()
        out = obj.decompress(data, MAX_DECOMPRESSED + 1)
        if len(out) > MAX_DECOMPRESSED or obj.unconsumed_tail:
            raise EvalFailed("zlib output exceeds size cap")
        return _cap(out + obj.flush())
    if d is bz2:
        return _cap(bz2.BZ2Decompressor().decompress(data, MAX_DECOMPRESSED + 1))
    if d is lzma:
        return _cap(lzma.LZMADecompressor().decompress(data, MAX_DECOMPRESSED + 1))
    if d is gzip:
        return _cap(gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_DECOMPRESSED + 1))
    raise EvalFailed("unknown decompressor")

def looks_like_python(data: bytes | str) -> bool:
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
    else:
        text = data
    try:
        ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    printable = sum(1 for ch in text[:4096] if ch.isprintable() or ch in "\r\n\t")
    return printable >= 0.9 * min(len(text), 4096) if text else False

def _strip_pkcs7(data: bytes) -> bytes | None:
    """Drop PKCS#7 padding a cipher left on, when the tail really is padding."""
    if len(data) < 2:
        return None
    pad = data[-1]
    if not 1 <= pad <= 16 or pad >= len(data):
        return None
    if data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return None

def _payload_variants(blob: bytes) -> list[bytes]:
    """The same payload, with and without the padding a cipher may have left."""
    variants = [blob]
    stripped = _strip_pkcs7(blob)
    if stripped and stripped != blob:
        variants.append(stripped)
    zero = blob.rstrip(b"\x00")
    if zero and zero != blob and len(zero) >= 16:
        variants.append(zero)
    return variants

def _as_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text[:4096]:
        return None
    return text
