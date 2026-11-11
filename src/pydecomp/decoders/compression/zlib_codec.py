"""pydecomp - zlib_codec."""
from __future__ import annotations

import zlib


def _zlib_stream(data: bytes) -> bytes:
    """``compressobj`` output - or several concatenated zlib members."""
    out = bytearray()
    for attempt in (15, -15, 31):
        try:
            engine = zlib.decompressobj(attempt)
            out = bytearray(engine.decompress(data))
            if engine.unused_data:
                out.extend(_zlib_stream(engine.unused_data))
            if out:
                return bytes(out)
        except zlib.error:
            continue
    raise ValueError("no zlib stream")
