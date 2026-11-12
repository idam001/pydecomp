"""pydecomp - carve a Python payload out of something that is not Python.

Compiled extensions, one-file executables and licensing runtimes all hide their
Python layer inside a native binary.  The file has no Python syntax to parse, and
running it is out of the question, but the payload is still *in there* - as a
compressed stream, a ``.pyc``, or a long base85 literal - and it can be found by
structure:

* a pyc magic number at any offset,
* a zlib / bz2 / gzip / lzma header that decompresses,
* a long base64 / base85 run that decodes,
* a zip container holding ``.pyc`` entries.

Every candidate is validated before it is reported: it has to parse as Python,
or marshal into a code object, or carry a pyc header.  Carving that only produced
"something" would be worse than carving nothing.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import lzma
import re
import zlib

MAX_INPUT = 64 * 1024 * 1024       # do not scan a 4 GB file byte by byte
MAX_OUTPUT = 32 * 1024 * 1024      # a decompression bomb is not a payload
MAX_CANDIDATES = 24

STREAM_MARKERS = (
    (b"\x78\x9c", zlib.decompress),
    (b"\x78\xda", zlib.decompress),
    (b"\x78\x01", zlib.decompress),
    (b"BZh", bz2.decompress),
    (b"\x1f\x8b\x08", gzip.decompress),
    (b"\xfd7zXZ\x00", lzma.decompress),
)

PYC_MAGIC = re.compile(rb"[\x00-\xff]{2}\r\n")

ENCODED_RUN = re.compile(rb"[A-Za-z0-9+/=]{64,}")
B85_RUN = re.compile(rb"[A-Za-z0-9!#$%&()*+\-;<=>?@^_`{|}~]{64,}")


def _validate(data: bytes) -> bool:
    """Structure only: does this look like a Python payload?"""
    if not data or len(data) < 16:
        return False
    head = data[:4]
    if len(head) == 4 and head[2:4] == b"\r\n" and 0 < head[1] < 0x80:
        return True                                   # a pyc magic
    try:
        import marshal
        marshal.loads(data)
        return True
    except Exception:                                # noqa: BLE001
        pass
    try:
        from ..decoders.emoji import parses_as_python
        return parses_as_python(data.decode("utf-8", "ignore"))
    except Exception:                                # noqa: BLE001
        return False


def _bounded(decompress, chunk: bytes):
    try:
        out = decompress(chunk)
    except Exception:                                # noqa: BLE001
        return None
    if out and len(out) <= MAX_OUTPUT:
        return out
    return None


def find_streams(data: bytes) -> list[tuple[int, str, bytes]]:
    """Compressed streams embedded at any offset."""
    found: list[tuple[int, str, bytes]] = []
    for marker, decompress in STREAM_MARKERS:
        start = 0
        while len(found) < MAX_CANDIDATES:
            offset = data.find(marker, start)
            if offset < 0:
                break
            start = offset + 1
            payload = _bounded(decompress, data[offset:])
            if payload and _validate(payload):
                found.append((offset, f"{marker.hex()} stream", payload))
    return found


def find_pyc(data: bytes) -> list[tuple[int, str, bytes]]:
    """A pyc anywhere in the binary: header, then a marshal body."""
    found: list[tuple[int, str, bytes]] = []
    import marshal
    for match in PYC_MAGIC.finditer(data[:MAX_INPUT]):
        offset = match.start()
        body = data[offset + 16:]
        if not body:
            continue
        try:
            code = marshal.loads(body)
        except Exception:                            # noqa: BLE001
            continue
        if hasattr(code, "co_code") or (hasattr(code, "code") and hasattr(code, "consts")):
            found.append((offset, "embedded .pyc", data[offset:]))
            if len(found) >= MAX_CANDIDATES:
                break
    return found


def _decode_literal(decoder, run: bytes):
    """Yield every plausible decoding of a literal embedded in binary junk.

    A base85 literal usually has random bytes touching both ends, so the regex
    captures a few characters too many, and ``b85decode`` happily returns
    garbage for a misaligned block instead of failing.  Trimming both ends and
    *yielding* every result (rather than returning the first one that does not
    raise) is what makes the difference: validation downstream decides.
    """
    for head in range(0, 9):
        for tail in range(0, 9):
            chunk = run[head: len(run) - tail if tail else len(run)]
            if len(chunk) < 64:
                continue
            try:
                if decoder is base64.b64decode:
                    yield decoder(chunk + b"=" * (-len(chunk) % 4), validate=False)
                else:
                    yield decoder(chunk)             # b85 tolerates a short tail
                    aligned = chunk[: len(chunk) - (len(chunk) % 5)]
                    if len(aligned) != len(chunk):
                        yield decoder(aligned)
            except Exception:                        # noqa: BLE001
                continue


def find_encoded(data: bytes) -> list[tuple[int, str, bytes]]:
    """Long base64 / base85 literals, decoded and then opened if they compress."""
    found: list[tuple[int, str, bytes]] = []
    for pattern, name, decoder in ((ENCODED_RUN, "base64 literal", base64.b64decode),
                                   (B85_RUN, "base85 literal", base64.b85decode)):
        for match in pattern.finditer(data[:MAX_INPUT]):
            if len(found) >= MAX_CANDIDATES:
                break
            for raw in _decode_literal(decoder, match.group(0)):
                payload = raw
                for decompress in (zlib.decompress, bz2.decompress, lzma.decompress,
                                   gzip.decompress):
                    opened = _bounded(decompress, raw)
                    if opened is not None:
                        payload = opened
                        break
                if _validate(payload):
                    found.append((match.start(), name, payload))
                    break
    return found


def carve(data: bytes) -> list[tuple[int, str, bytes]]:
    """Every validated payload candidate, in the order the file stores them."""
    if not data:
        return []
    blob = data[:MAX_INPUT]
    candidates: list[tuple[int, str, bytes]] = []
    for finder in (find_pyc, find_streams, find_encoded):
        try:
            candidates.extend(finder(blob))
        except Exception:                            # noqa: BLE001
            continue
    seen: set[bytes] = set()
    unique: list[tuple[int, str, bytes]] = []
    for offset, how, payload in sorted(candidates, key=lambda item: item[0]):
        digest = payload[:256]
        if digest in seen:
            continue
        seen.add(digest)
        unique.append((offset, how, payload))
        if len(unique) >= MAX_CANDIDATES:
            break
    return unique
