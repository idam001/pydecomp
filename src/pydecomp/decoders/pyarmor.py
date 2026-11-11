"""pydecomp - pyarmor.

PyArmor 8+ replaces a script with a four-line bootstrap and a blob:

    # Pyarmor 8.5.11 (pro), 005724, non-profits, 2024-12-13T07:33:37
    from pyarmor_runtime_005724 import __pyarmor__
    __pyarmor__(__name__, __file__, b'PY005724\\x00\\x03\\x0b\\x00...')

The blob is *not* marshal: it carries the tag ``PY005724`` (or ``PYARMOR`` on
older releases) and a per-code-object header, and the code inside is encrypted
with a key baked into the matching ``pyarmor_runtime_*.so/.pyd``.  Without that
runtime nothing on earth decrypts it statically, and pydecomp will not pretend
otherwise - but a great deal *is* recoverable and worth emitting:

* the bootstrap itself, which is real source and names the runtime package;
* the build banner (version, serial, edition, timestamp) from the comment line;
* the blob's tag, header bytes and length;
* every printable string and identifier-shaped token in the blob;
* the payload we would hand to the decryptor if a runtime library is supplied.

That last one matters: supplying the runtime as a second input lets the native
scanner look for the key material, which is the only honest route in.
"""
from __future__ import annotations

import ast
import codecs
import re

_TAG = re.compile(rb"PY[A-Z0-9]{6}\x00|PYARMOR\x00")
_BANNER = re.compile(r"#\s*Pyarmor\s+([0-9][^\s,]*)[^\n]*", re.IGNORECASE)
_CALL = re.compile(r"__pyarmor__\s*\(\s*__name__\s*,\s*__file__\s*,\s*b?['\"]")
_RUNTIME = re.compile(r"pyarmor_runtime_([0-9A-Za-z]+)")
_STRINGY = re.compile(rb"[ -~]{5,}")


def detect(text: str) -> dict | None:
    """Recognise PyArmor output in *source* form."""
    if not isinstance(text, str):
        return None
    if "__pyarmor__" not in text and "pyarmor_runtime" not in text:
        return None
    info: dict = {"banner": None, "serial": None, "runtime": None, "blob": b""}
    banner = _BANNER.search(text)
    if banner:
        info["banner"] = banner.group(0).lstrip("# ").strip()
        parts = [p.strip() for p in info["banner"].split(",")]
        if len(parts) > 1 and parts[1].isdigit():
            info["serial"] = parts[1]
    runtime = _RUNTIME.search(text)
    if runtime:
        info["runtime"] = runtime.group(0)
    blob = _find_blob(text)
    if blob:
        info["blob"] = blob
    return info


def _find_blob(text: str) -> bytes:
    """Reassemble the bytes literal handed to ``__pyarmor__`` from its repr."""
    call = _CALL.search(text)
    if not call:
        return b""
    start = call.end() - 1
    quote = text[start]
    cursor = start + 1
    escaped = False
    out_chars: list[str] = []
    while cursor < len(text):
        char = text[cursor]
        if escaped:
            out_chars.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
            out_chars.append(char)
        elif char == quote:
            break
        else:
            out_chars.append(char)
        cursor += 1
    literal = "".join(out_chars)
    # the literal is *data*: unescape it with literal_eval, which only ever
    # builds constants and never executes anything
    try:
        value = ast.literal_eval("b'" + literal.replace("'", "\\'") + "'")
    except Exception:                                            # noqa: BLE001
        try:
            value = codecs.escape_decode(literal.encode("latin-1", "ignore"))[0]
        except Exception:                                        # noqa: BLE001
            return b""
    return value if isinstance(value, bytes) else b""


def describe(blob: bytes) -> dict:
    """Tag, header fields and carved strings from a PyArmor payload."""
    info: dict = {"tag": "", "length": len(blob), "header": b"", "strings": []}
    if not blob:
        return info
    tag = _TAG.match(blob)
    if tag:
        info["tag"] = tag.group(0).rstrip(b"\x00").decode("ascii", "replace")
        info["header"] = blob[len(tag.group(0)):len(tag.group(0)) + 32]
    seen = []
    for match in _STRINGY.finditer(blob[:1_000_000]):
        text = match.group(0).decode("ascii", "replace").strip()
        if len(text) >= 8 and text not in seen:
            seen.append(text)
        if len(seen) >= 60:
            break
    info["strings"] = seen
    return info


def recovery_note(info: dict) -> str:
    """One line for the report (never for the recovered file itself)."""
    tag = info.get("tag") or "PyArmor"
    return (f"{tag} payload ({info.get('length', 0):,} B) - code objects are "
            "encrypted with a key inside the pyarmor_runtime library; the "
            "bootstrap, build banner and carved strings below are everything "
            "that exists in the file in readable form")
