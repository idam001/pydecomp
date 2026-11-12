"""pydecomp - named source obfuscators.

Twenty schemes people actually meet, each with the *contract* that makes the
tool willing to name it:

* ``markers`` - strings the scheme itself writes (a banner, a module name, a
  helper it always emits).  A hit is a confident attribution.
* ``shape`` - a structural signal for schemes that leave no banner.  It is
  weaker, and it is reported as ``shape`` rather than as a name plus a lie.

A file that looks like a loader but matches no contract is reported as
``unidentified loader`` - the tool names what it can prove and peels everything
with the generic engine either way.
"""
from __future__ import annotations

import re

LOADER_SHAPE = re.compile(
    r"(?:exec|eval)\s*\(\s*(?:__import__\s*\(\s*['\"]zlib|zlib\.decompress|"
    r"marshal\.loads|bytes\.fromhex|base64\.b64decode|codecs\.decode)",
    re.IGNORECASE)


class Scheme:
    __slots__ = ("name", "family", "markers", "shape", "note", "unwrap")

    def __init__(self, name: str, family: str = "source", markers: tuple = (),
                 shape=None, note: str = "", unwrap: str | None = None):
        self.name = name
        self.family = family          # source | bytecode | loader | commercial
        self.markers = tuple(markers)
        self.shape = shape
        self.note = note
        self.unwrap = unwrap

    def as_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "note": self.note,
                "markers": list(self.markers), "unwrap": self.unwrap}


#: Ordered strongest contract first.  Every entry names the thing that would
#: have to be true for the attribution to be honest.
SCHEMES = (
    Scheme("hyperion", "bytecode", ("Hyperion", "_Hyperion", "hyperion_payload"),
           note="compiled-bytecode wrapper with an appended payload",
           unwrap="hyperion"),
    Scheme("pyobfuscate", "source", ("pyobfuscate.com", "__pyobfuscate__",
                                     "pyobfuscate"),
           note="commercial source mangler with a decrypting preamble",
           unwrap="pyobfuscate"),
    Scheme("pyminifier", "source", ("Created by pyminifier", "pyminifier"),
           note="minifier: names shortened, structure kept", unwrap="minified"),
    Scheme("blankobf", "loader", ("BlankOBF", "blank_obf"), note="loader family"),
    Scheme("kramer", "loader", ("kramer", "Kramer"), note="loader family"),
    Scheme("specter", "loader", ("specter", "Specter"), note="loader family"),
    Scheme("berserker", "loader", ("Berserker", "berserker"), note="loader family"),
    Scheme("manglify", "loader", ("Manglify", "manglify"), note="loader family"),
    Scheme("plusobf", "loader", ("PlusOBF", "plusobf"), note="loader family"),
    Scheme("pypacker", "bytecode", ("pypacker", "PyPacker"), note="packer family"),
    Scheme("oxyry", "source", ("oxyry", "Oxyry"), note="online mangler"),
    Scheme("xindex", "loader", ("xindex", "Xindex"), note="loader family"),
    Scheme("jawbreaker", "loader", ("Jawbreaker", "jawbreaker"),
           note="fetches its payload at run time; the loader is what exists"),
    Scheme("online_family", "loader", ("onlineobfuscator", "obfuscator.io"),
           note="web obfuscator family"),
    Scheme("python_obfuscator", "source", ("python-obfuscator", "pyobfuscator"),
           note="pip-installable source obfuscator"),
    Scheme("patchwork", "source", ("patchwork", "Patchwork"), note="source mangler"),
    Scheme("obfuxtreme", "commercial", ("ObfuXtreme", "obfuxtreme"),
           note="commercial protector"),
    Scheme("pyprotect", "commercial", ("PyProtect", "pyprotect"),
           note="commercial protector"),
    Scheme("pyobfus", "loader", ("pyobfus", "__pyobfus"), note="loader family"),
    Scheme("pyc_zipper", "bytecode", ("pyc_zipper", "pythonz"), note="pyc packer"),
    Scheme("pyinstaller", "bytecode", ("PyInstaller", "_MEIPASS", "MEI\\014"),
           note="frozen with PyInstaller - use the container reader"),
)

#: shape-only contracts, tried when no marker matched
SHAPES = (
    ("unidentified loader", LOADER_SHAPE,
     "single exec/eval of an encoded literal - peels with the generic engine"),
)


def detect(source: str) -> list[dict]:
    """Every scheme whose contract this source satisfies, strongest first."""
    if not source:
        return []
    out = []
    for scheme in SCHEMES:
        hit = next((marker for marker in scheme.markers if marker in source), None)
        if hit is not None:
            out.append({"name": scheme.name, "family": scheme.family,
                        "confidence": 0.95, "why": f"marker {hit!r}",
                        "note": scheme.note, "unwrap": scheme.unwrap})
    if out:
        return out
    for name, shape, note in SHAPES:
        if shape.search(source):
            out.append({"name": name, "family": "loader", "confidence": 0.5,
                        "why": "loader shape", "note": note, "unwrap": None})
            break
    return out


def identify(source: str) -> str | None:
    found = detect(source)
    return found[0]["name"] if found else None


def known() -> tuple[str, ...]:
    return tuple(scheme.name for scheme in SCHEMES)
