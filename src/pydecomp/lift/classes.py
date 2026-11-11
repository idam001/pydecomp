"""pydecomp - classes."""
from __future__ import annotations

import re


_CLASS_BODY_KEYS = ("__module__", "__qualname__", "__firstlineno__", "__static_attributes__")

def promote_class_bodies(text: str) -> str:
    """Turn a class body that was lifted as ``def Name():`` back into a class.

    A class body is a function whose first statements bind ``__module__`` and
    ``__qualname__``.  When a rebuild loses the ``class`` shape those binds are
    the only evidence left, and they are enough to restore it.
    """
    lines = text.split("\n")
    out = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)def (\w+)\(\):\s*$", line)
        if not match:
            out.append(line)
            index += 1
            continue
        indent, name = match.group(1), match.group(2)
        probe = index + 1
        keys = set()
        while probe < len(lines):
            raw = lines[probe]
            stripped = raw.strip()
            if not stripped:
                probe += 1
                continue
            if not raw.startswith(indent + " ") and not raw.startswith(indent + "\t"):
                break
            key_match = re.match(r"^(\w+) = ", stripped)
            if key_match and key_match.group(1) in _CLASS_BODY_KEYS:
                keys.add(key_match.group(1))
                probe += 1
                continue
            break
        if "__module__" not in keys and "__qualname__" not in keys:
            out.append(line)
            index += 1
            continue
        out.append(indent + "class " + name + ":")
        for pos in range(index + 1, probe):
            stripped = lines[pos].strip()
            key_match = re.match(r"^(\w+) = ", stripped)
            if key_match and key_match.group(1) in _CLASS_BODY_KEYS:
                continue
            if stripped.startswith("__doc__ = "):
                out.append(indent + "    " + stripped[len("__doc__ = "):])
                continue
            out.append(lines[pos])
        index = probe
    return "\n".join(out)
