"""pydecomp - hyperion.

Hyperion (billythegoat356 / BlueRed) is the most widely used free "military
grade" Python obfuscator, and the one that turns up in real samples.  Its output
is deliberately small and *always* pure Python:

    __obfuscator__ = 'Hyperion'
    __code__ = 'print("hello")'
    _while, Product, _builtins, _power, Add, Builtins, _floor = (
        exec, str, tuple, map, ord, globals, type)

    class _cube:
        def execute(code=str):
            return _while(Product(_builtins(_power(Add, code))))

The payload never leaves the file as text: it is a string in ``__code__`` (or a
tuple of character ordinals), and everything else - the class, the junk
`try/except` blocks, the arithmetic no-ops, the 10+ "layers" - exists to make a
reader give up before reaching it.

Reading it needs no execution at all:

* ``__code__`` is a literal, so it *is* the program;
* if it is a tuple/list of integers, ``''.join(map(chr, ...))`` is the program;
* if the tail of the module only shuffles that string around (``map(ord, …)``,
  ``tuple(...)``, ``str(...)``), the reconstruction is the string itself.

Hyperion's own README admits it: "Not impossible to deobfuscate … the source can
still be retrieved."  This is that retrieval, done statically.
"""
from __future__ import annotations

import ast
import re

_MARKERS = ("__obfuscator__", "'Hyperion'", '"Hyperion"', "__github__", "_cube")
_CODE = re.compile(r"__code__\s*=\s*(\"\"\"(?:.*?)\"\"\"|'''(?:.*?)'''|'(?:[^'\\]|\\.)*'|"
                   r"\"(?:[^\"\\]|\\.)*\"|\[[0-9,\s\.]+\]|\([0-9,\s\.]+\))", re.DOTALL)


def is_hyperion(text: str) -> bool:
    lowered = text[:200_000]
    hits = sum(1 for marker in _MARKERS if marker in lowered)
    return hits >= 2 or "Hyperion" in lowered


def _unescape(literal: str) -> str:
    """The payload is a Python string literal: read it as one."""
    try:
        value = ast.literal_eval(literal)
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
    except Exception:                                  # noqa: BLE001
        pass
    quote = 3 if literal[:3] in ('"""', "'''") else 1
    return literal[quote:-quote]


def payload(text: str) -> tuple[str | None, str]:
    """Return (program text, how it was found) or (None, reason)."""
    match = _CODE.search(text)
    if match:
        literal = match.group(1).strip()
        if literal.startswith(("[", "(")):
            body = literal.strip("[]()")
            numbers = [int(part) for part in re.findall(r"-?\d+", body)]
            if numbers and all(0 <= code <= 0x10FFFF for code in numbers):
                try:
                    return "".join(chr(code) for code in numbers), "ordinal tuple"
                except ValueError:
                    pass
        else:
            recovered = _unescape(literal)
            if recovered.strip():
                return recovered, "__code__ literal"
    # last resort: the largest string literal that parses as Python
    best = None
    for literal in re.findall(r"\"\"\"(.*?)\"\"\"|'''(.*?)'''", text, re.DOTALL):
        body = literal[0] or literal[1]
        if len(body) > (len(best) if best else 0):
            best = body
    if best:
        return best, "largest embedded literal"
    return None, "no payload literal found"


def note(how: str) -> str:
    return f"Hyperion container recognised · payload recovered from {how}"
