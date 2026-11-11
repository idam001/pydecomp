"""pydecomp - escapes."""
from __future__ import annotations

import codecs


def _escaped_bytes(data: bytes) -> bytes:
    """A source literal full of ``\\xNN`` escapes, taken at face value."""
    text = data.decode("latin-1")
    if "\\x" not in text[:200]:
        raise ValueError("no escapes")
    if len(text) > 4 * 1024 * 1024:
        raise ValueError("too big")
    try:
        return codecs.decode(text, "unicode_escape").encode("latin-1")
    except Exception as exc:                          # noqa: BLE001
        raise ValueError("bad escapes") from exc
