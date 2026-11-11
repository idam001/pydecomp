"""pydecomp - decode."""
from __future__ import annotations

import hashlib

from ..bytecode.magic import MAGIC_VERSIONS_BYTES
from ..decoders.emoji import _emoji_transforms, parses_as_python
from ..decoders.registry import (
    TRANSFORMS, _mostly_text, _printable_count, _transform_allowed,
)
from ..decoders.xor import _score_text, xor_best
from ..limits import MAX_LAYERS
from ..terminal.color import step

_DEEP = {"on": False, "layers": 4, "xor": 2, "keys": 8}

_DECODE_CACHE: dict = {}

_DECODE_CACHE_CAP = 4096

def _deep_mode() -> None:
    """Item 17: spend more time instead of asking the user for a bigger machine."""
    _DEEP["on"] = True
    _DEEP["layers"] = 10
    _DEEP["xor"] = 8
    _DEEP["keys"] = 24
    global MAX_LAYERS
    MAX_LAYERS = max(MAX_LAYERS, 32)

def deep_decode(blob: bytes, depth: int = 4, limit: int = 64 * 1024 * 1024):
    """Breadth-first search over decoder chains for a blob of unknown cooking."""
    key = (hashlib.sha256(blob).digest(), depth, _DEEP["layers"])
    cached = _DECODE_CACHE.get(key)
    if cached is not None:
        return cached
    result = _deep_decode_uncached(blob, depth + (_DEEP["layers"] - 4), limit)
    if len(_DECODE_CACHE) > _DECODE_CACHE_CAP:       # item 29: bounded memo
        _DECODE_CACHE.clear()
    _DECODE_CACHE[key] = result
    return result

def _deep_decode_uncached(blob: bytes, depth: int, limit: int):
    # Nothing shorter than a plausible loader can be a payload; this alone
    # removes thousands of calls on the constant soup inside a big module.
    if len(blob) < 24:
        return None, []
    frontier = [(blob, [])]
    seen = {hashlib.sha256(blob).digest()}
    try:
        as_text = blob.decode("utf-8")
    except UnicodeDecodeError:
        as_text = None
    if as_text is not None:
        emoji = _emoji_transforms(as_text)
        if emoji is not None:
            out, label = emoji
            frontier = [(out, [label])]
            seen.add(hashlib.sha256(out).digest())
    xor_budget = [_DEEP["xor"]]                       # XOR is expensive: spend sparingly
    for _ in range(depth):
        nxt = []
        for data, chain in frontier:
            # a plain XOR layer is invisible to every decoder above: solve it
            xor_key = xor_plain = None
            # only for blobs big enough to be a payload and not already text
            if xor_budget[0] and 512 <= len(data) <= 8192 and _score_text(data) < 2.4:
                xor_budget[0] -= 1
                xor_key, xor_plain = xor_best(data, max_key=_DEEP["keys"])
            if xor_plain is not None and xor_key is not None:
                try:
                    text = xor_plain.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
                if text is not None and "\n" in text and parses_as_python(text):
                    return xor_plain, chain + [f"xor(key={xor_key.hex()})"]
                # not source yet, but still a better base for the next round
                if text is not None and len(xor_plain) >= 32:
                    nxt.append((xor_plain, chain + [f"xor(key={xor_key.hex()})"]))
            is_text = _mostly_text(data, 0.88)
            for name, fn in TRANSFORMS.items():
                if not _transform_allowed(name, data, is_text):
                    continue
                try:
                    out = fn(data)
                except Exception:
                    continue
                if not out or len(out) > limit or len(out) < 16:
                    continue
                digest = hashlib.sha256(out).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                step = chain + [name]
                if out[:2] in MAGIC_VERSIONS_BYTES:
                    return out, step
                try:
                    candidate = out.decode("utf-8")
                except UnicodeDecodeError:
                    candidate = None
                if candidate is not None and "\n" in candidate and parses_as_python(candidate):
                    return out, step
                nxt.append((out, step))
            nxt.sort(key=lambda item: -_printable_count(item[0]))
        frontier = nxt[:24]
    return None, []
