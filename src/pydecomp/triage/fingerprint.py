"""pydecomp - fingerprint."""
from __future__ import annotations

import re

from ..decoders.emoji import _looks_emoji
from ..polish.demangle import _mangled_name

def _fingerprint(source: str, trace: list) -> str:
    """Which tool most likely produced this file (item 30)."""
    text = source
    joined = " ".join(trace).lower()
    if "__pyarmor__" in text or "pyarmor_runtime" in text or "pyarmor" in joined:
        return "PyArmor 8/9 (encrypted code objects)"
    if "__obfuscator__" in text or "_0x" in text[:4000] and "hyperion" in text.lower():
        return "Hyperion (multi-layer zlib)"
    if "pyobfus" in text.lower():
        return "pyobfus"
    if re.search(r"%=\(\w+\)s.*%=\w+", text[:4000]) and "_ = lambda __" in text:
        return "PyObfuscate / lambda-indirection family"
    if text.count("exec(") > 1 and "b64decode" in text and "zlib" in text:
        return "multi-stage exec loader (BlankOBF / Kramer style)"
    if re.search(r"\bl\w{6,}\b", text[:2000]) and _mangled_name("lIlIlIlI"):
        return "identifier-mangling obfuscator (Mr.X / pyobfus style)"
    if "marshal" in text and ("zlib" in text or "bz2" in text or "lzma" in text):
        return "marshal + compression packer"
    if _looks_emoji(text[:20000]):
        return "emoji / pictograph encoder"
    if "base64" in text and len(text) < 400:
        return "single-stage base64 loader"
    return "unknown / hand-rolled"
