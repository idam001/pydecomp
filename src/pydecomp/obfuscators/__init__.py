"""pydecomp.obfuscators - named schemes, then the generic peeler.

    >>> from pydecomp.obfuscators import identify, detect
    >>> identify("# Created by pyminifier\\nimport os\\n")
    'pyminifier'

Naming is a claim, so a name is only returned when the scheme's own contract
holds (see :mod:`pydecomp.obfuscators.schemes`).  Everything is peeled by the
generic engine regardless of whether a name was found: the name is intelligence,
not a gate.
"""
from __future__ import annotations

from ..obfuscators.schemes import SCHEMES, SHAPES, Scheme, known  # noqa: F401
from ..obfuscators.schemes import detect, identify


def unwrap(source: str) -> tuple[str | None, str]:
    """``(unwrapped, how)`` for the schemes with a real unwrapper, else (None, "")."""
    if not source:
        return None, ""
    found = detect(source)
    for match in found:
        name = match.get("name")
        if name == "hyperion":
            from ..decoders.hyperion import hyperion_payload, is_hyperion
            if is_hyperion(source):
                program, how = hyperion_payload(source)
                if program:
                    return program, f"hyperion: {how}"
        if name == "pyobfuscate":
            from ..decoders.pyobfuscate_com import is_pyobfuscate, pyobfuscate_decrypt
            if is_pyobfuscate(source):
                plain, facts = pyobfuscate_decrypt(source)
                if plain:
                    return plain, "pyobfuscate: decrypting preamble evaluated"
        if name == "pyminifier":
            lines = [line for line in source.splitlines()
                     if "pyminifier" not in line.lower()]
            return "\n".join(lines) + "\n", "pyminifier: banner removed"
    return None, ""


__all__ = ["SCHEMES", "SHAPES", "Scheme", "detect", "identify", "known", "unwrap"]
