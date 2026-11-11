"""pydecomp - harvest."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj
from ..bytecode.marshal_reader import iter_code

def harvest_inline_text(code: CodeObj) -> str:
    """Recover a string that the bytecode rebuilds from inline integer loads.

    The classic obfuscator trick is ``exec(''.join(chr(n) for n in (...)))``
    where the integers are pushed one at a time.  Whichever opcode carries
    them dominates the instruction stream, so we look for the most frequent
    opcode whose operand bytes spell out text.
    """
    raw = code.code
    if len(raw) < 64:
        return ""
    counts = {}
    for i in range(0, len(raw) - 1, 2):
        op = raw[i]
        if op:
            counts[op] = counts.get(op, 0) + 1
    for op, count in sorted(counts.items(), key=lambda kv: -kv[1])[:4]:
        if count < 32:
            continue
        chars = [raw[i + 1] for i in range(0, len(raw) - 1, 2) if raw[i] == op]
        text = "".join(chr(c) for c in chars if 0 < c < 0x110000)
        if len(text) < 48:
            continue
        printable = sum(1 for ch in text if 32 <= ord(ch) < 127 or ch in "\n\t")
        if printable / max(len(text), 1) > 0.93:
            return text
    return ""

def harvest_constants(code: CodeObj, minimum: int = 24) -> list:
    """Every big str/bytes constant in the module, innermost code included."""
    found = []
    for node in iter_code(code):
        for const in node.consts:
            if isinstance(const, (bytes, str)) and len(const) >= minimum:
                found.append(const)
    return found
