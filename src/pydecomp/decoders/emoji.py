"""pydecomp - emoji."""
from __future__ import annotations

import ast

from ..terminal.color import step

_EMOJI_POOLS = [
    "\U0001F600\U0001F601\U0001F602\U0001F923\U0001F603\U0001F604\U0001F605"
    "\U0001F606\U0001F609\U0001F60A\U0001F60B\U0001F60E\U0001F60D\U0001F618"
    "\U0001F970\U0001F617\U0001F619\U0001F61A\U0001F642\U0001F917",
    "\U0001F1E6\U0001F1E7\U0001F1E8\U0001F1E9\U0001F1EA\U0001F1EB\U0001F1EC"
    "\U0001F1ED\U0001F1EE\U0001F1EF\U0001F1F0\U0001F1F1\U0001F1F2\U0001F1F3"
    "\U0001F1F4\U0001F1F5\U0001F1F6\U0001F1F7\U0001F1F8\U0001F1F9",
    "\U0001F400\U0001F401\U0001F402\U0001F403\U0001F404\U0001F405\U0001F406"
    "\U0001F407\U0001F408\U0001F409\U0001F40A\U0001F40B\U0001F40C\U0001F40D"
    "\U0001F40E\U0001F40F\U0001F410\U0001F411\U0001F412\U0001F413",
    "\U0001F950\U0001F951\U0001F952\U0001F953\U0001F954\U0001F955\U0001F956"
    "\U0001F957\U0001F958\U0001F959\U0001F95A\U0001F95B\U0001F95C\U0001F95D"
    "\U0001F95E\U0001F95F\U0001F960\U0001F961\U0001F962\U0001F963",
]

_EMOJI_SETS = [tuple(pool) for pool in _EMOJI_POOLS]

_EMOJI_BLOCKS = (0x1F300, 0x1F600, 0x1F900, 0x2600, 0x2700, 0x1F1E6)

#: how much of a text the emoji readers look at.  A layer that is 8 MB of
#: something else should not be walked four ways character by character.
WINDOW = 64 << 10
_HIGH = {code: 1 for code in range(0x2001, 0x110000) if chr(code).strip()}


def _window(text: str) -> str:
    return text[:WINDOW] if len(text) > WINDOW else text


def _emoji_density(text: str) -> float:
    text = _window(text)
    if not text:
        return 0.0
    hits = sum(1 for ch in text if ord(ch) > 0x2000 and not ch.isspace())
    return hits / len(text)

def _emoji_byte_chain(text: str) -> bytes | None:
    """Emoji where each symbol stands for one byte (``emojify``-style)."""
    if len(text) > 8 << 20:
        return None                 # a chain that size is not what this reads
    if _emoji_density(text) < 0.9:
        return None
    symbols = [ch for ch in text if not ch.isspace()]
    alphabet = []
    for ch in symbols:
        if ch not in alphabet:
            alphabet.append(ch)
    if not 4 <= len(alphabet) <= 300:
        return None
    index = {ch: i for i, ch in enumerate(alphabet)}
    out = bytearray()
    for ch in symbols:
        value = index[ch]
        if value > 255:
            return None
        out.append(value)
    return bytes(out)

def _emoji_base_chain(text: str, bits: int = 2) -> bytes | None:
    """Emoji quads: four 2-bit symbols per byte (``emoji-array`` style)."""
    known = None
    for pool in _EMOJI_SETS:
        seen = sum(1 for ch in text if ch in pool)
        if seen > len(text) * 0.8:
            known = pool
            break
    if known is None or _emoji_density(text) < 0.8:
        return None
    symbols = [ch for ch in text if not ch.isspace()]
    try:
        values = [known.index(ch) for ch in symbols]
    except ValueError:
        return None
    out = bytearray()
    step = 8 // bits
    for i in range(0, len(values) - step + 1, step):
        byte = 0
        for j in range(step):
            byte = (byte << bits) | values[i + j]
        out.append(byte)
    return bytes(out)

def _looks_emoji(text: str) -> bool:
    return _emoji_density(text) > 0.5

def _chacha_layer(data: bytes) -> bytes:
    raise ValueError("chacha needs a key")

def _emoji_transforms(text: str) -> tuple[bytes, str] | None:
    """Emoji payloads are invisible to every byte-level decoder above."""
    if not _looks_emoji(text):
        return None
    for name, fn in (("emoji-bytes", _emoji_byte_chain),
                     ("emoji-quad", lambda t: _emoji_base_chain(t, 2)),
                     ("emoji-octet", lambda t: _emoji_base_chain(t, 4))):
        try:
            out = fn(text)
        except Exception:                            # noqa: BLE001
            out = None
        if out and len(out) >= 16:
            return out, name
    return None

def parses_as_python(text: str) -> bool:
    """The only honest test for 'we recovered a script'."""
    try:
        ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return "\x00" not in text[:4096]
