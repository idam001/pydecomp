#!/usr/bin/env python3
"""Regenerate the per-version opcode tables from CPython's own opcode listings.

The tables in ``bytecode/opcodes/tables.py`` are the part of this project most
likely to rot silently: a wrong number does not crash, it renames an opcode and
quietly changes what the decompiler thinks it is reading.  So the numbering is
read from the release it belongs to rather than remembered:

* 3.8-3.12 list their opcodes in ``Lib/opcode.py`` (``def_op('NAME', N)``);
* 3.13 and later keep the numbering in ``Lib/_opcode_metadata.py`` (``'NAME': N``).

Three facts come out of each release, and all three are needed to decode its
bytecode correctly:

* the opcode table itself;
* which jumps are relative and which are absolute - 3.8's ``FOR_ITER`` counts
  from its own instruction while its ``JUMP_IF_FALSE_OR_POP`` names an absolute
  address;
* the comparison table, because before 3.12 ``COMPARE_OP``'s operand is a plain
  index into ``cmp_op``, and in 3.8 that list also holds ``in``, ``is`` and
  ``exception match``.

The generated tables are committed data: nothing in the package fetches anything
at run time, and the single-file build carries them with it.

    python3 tools/fetch_opcode_tables.py --write     # regenerate tables.py
    python3 tools/gen_opcode_tables.py --check       # validate what is committed
"""
from __future__ import annotations

import argparse
import dataclasses
import re
import sys
import urllib.request

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
TABLES = ROOT / "src" / "pydecomp" / "bytecode" / "opcodes" / "tables.py"

SOURCE = "https://raw.githubusercontent.com/python/cpython/{branch}/Lib/{name}"

BRANCHES = {"3.8": "3.8", "3.9": "3.9", "3.10": "3.10", "3.11": "3.11",
            "3.12": "3.12", "3.13": "3.13", "3.14": "3.14", "3.15": "3.15"}

#: a release that keeps only a numbering file still jumps; from 3.11 every jump
#: is relative to its own instruction, so the kinds are recorded rather than
#: guessed per opcode name
RELATIVE_EVERYWHERE = ("3.11", "3.12", "3.13", "3.14", "3.15")

_DEF = re.compile(r"^(def_op|name_op|jrel_op|jabs_op)\('([A-Z][A-Z0-9_]*)',\s*(\d+)\)")
#: 3.13/3.14 write the numbering as `'NAME': N,`, 3.15 as `NAME=N,`
_META_QUOTED = re.compile(r"^\s*'([A-Z][A-Z0-9_]*)':\s*(\d+),?\s*$")
_META_PLAIN = re.compile(r"^\s*([A-Z][A-Z0-9_]*)=(\d+),?\s*$")
_CMP = re.compile(r"^cmp_op\s*=\s*\((.*?)\)", re.S | re.M)


@dataclasses.dataclass
class Release:
    version: str
    table: dict = dataclasses.field(default_factory=dict)
    relative: list = dataclasses.field(default_factory=list)
    absolute: list = dataclasses.field(default_factory=list)
    compare: list = dataclasses.field(default_factory=list)
    source: str = ""


def fetch(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=30) as handle:
            return handle.read().decode("utf-8", "replace")
    except Exception:                                  # noqa: BLE001 - offline is fine
        return None


def read_release(version: str) -> Release | None:
    branch = BRANCHES[version]
    release = Release(version=version)
    text = fetch(SOURCE.format(branch=branch, name="_opcode_metadata.py"))
    if not text and version == "3.15":
        text = fetch(SOURCE.format(branch="main", name="_opcode_metadata.py"))
    if text:
        release.source = "_opcode_metadata.py"
        for name, number in read_opmap_block(text):
            release.table[name] = number
        if release.table:
            if version in RELATIVE_EVERYWHERE:
                release.relative = sorted(
                    name for name in release.table
                    if "JUMP" in name or name in ("FOR_ITER", "SEND"))
            return release
    text = fetch(SOURCE.format(branch=branch, name="opcode.py"))
    if not text and version == "3.15":
        # the development branch is called `main` until the release gets one
        text = fetch(SOURCE.format(branch="main", name="opcode.py"))
        branch = "main"
    if not text:
        return None
    release.source = "opcode.py"
    for line in text.splitlines():
        found = _DEF.match(line)
        if not found:
            continue
        kind, name, number = found.group(1), found.group(2), int(found.group(3))
        release.table[name] = number
        if kind == "jrel_op":
            release.relative.append(name)
        elif kind == "jabs_op":
            release.absolute.append(name)
    found = _CMP.search(text)
    if found:
        release.compare = [item.strip().strip("'\"")
                           for item in found.group(1).replace("\n", " ").split(",")
                           if item.strip()]
    return release


def read_opmap_block(text: str) -> list[tuple[str, int]]:
    """The `opmap` mapping only: the specialized table is a different fact.

    A warmed-up interpreter renumbers specialised instructions, but those never
    appear in a ``.pyc`` - only the base numbering does, and mixing the two would
    put names in the decoder's table that no file can contain.
    """
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(r"^opmap\s*=", line):
            start = index
            break
    if start is None:
        return []
    out: list[tuple[str, int]] = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace() and not line.startswith((")", "}")):
            break
        found = _META_QUOTED.match(line) or _META_PLAIN.match(line)
        if found:
            number = int(found.group(2))
            if number >= 256:
                # 3.13 and later list the compiler's own pseudo-instructions
                # here (JUMP, SETUP_FINALLY, POP_BLOCK ...).  They are expanded
                # before a .pyc is written, so they never appear in a file.
                continue
            out.append((found.group(1), number))
        elif line.startswith((")", "}")):
            break
    return out


def wrap(names: list[str], per_line: int = 9) -> list[str]:
    return [" ".join(names[start:start + per_line])
            for start in range(0, len(names), per_line)]


def render(releases: dict[str, Release]) -> str:
    lines: list[str] = ['"""pydecomp - the opcode table of every interpreter this build reads.',
                        "",
                        "Generated by ``tools/fetch_opcode_tables.py --write`` from each",
                        "release's own ``Lib/opcode.py`` / ``Lib/_opcode_metadata.py``, so the",
                        "numbers here are the ones CPython actually used.  Regenerate rather",
                        "than edit: a hand-typed number silently renames an opcode.",
                        '"""',
                        "from __future__ import annotations",
                        "",
                        "_OPCODE_TEXT = {"]
    for version, release in releases.items():
        names = [f"{name}={number}" for name, number
                 in sorted(release.table.items(), key=lambda item: (item[1], item[0]))]
        lines.append(f'    "{version}": (')
        for chunk in wrap(names):
            lines.append(f'        "{chunk} "')
        # close the trailing space cleanly and the tuple
        lines[-1] = lines[-1].rstrip()
        lines[-1] = lines[-1].rstrip('"') + '"'
        lines.append("    ),")
    lines.append("}")
    lines.append("")
    lines.append("#: per version, which jumps count from their own instruction and which")
    lines.append("#: name an absolute address")
    lines.append("JUMP_KINDS = {")
    for version, release in releases.items():
        if not release.relative and not release.absolute:
            lines.append(f'    "{version}": {{}},')
            continue
        lines.append(f'    "{version}": {{')
        lines.append(f'        "relative": {tuple(release.relative)!r},')
        lines.append(f'        "absolute": {tuple(release.absolute)!r},')
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("#: before 3.12 a COMPARE_OP operand is an index into this list; 3.8 also")
    lines.append("#: reaches `in`, `is` and `exception match` through it")
    lines.append("COMPARE_TABLES = {")
    for version, release in releases.items():
        if release.compare:
            lines.append(f'    "{version}": {tuple(release.compare)!r},')
    lines.append("}")
    lines.append('''
def _opname_tables() -> dict:
    out = {}
    for ver, chunks in _OPCODE_TEXT.items():
        table = {}
        blob = chunks if isinstance(chunks, str) else " ".join(chunks)
        for item in blob.split():
            name, sep, num = item.partition("=")
            if not sep or not num.isdigit():
                continue
            table.setdefault(int(num), name)
        out[tuple(int(part) for part in ver.split("."))] = table
    return out


OPNAMES = _opname_tables()


def _as_tuple(version: tuple) -> tuple:
    return tuple(version[:2])


def table_for(version: tuple) -> dict:
    """The opcode table for *version*, or the nearest one below it.

    A file from a version newer than the newest table decodes with the table
    directly under it, which is right far more often than it is wrong; a file
    from 3.8 must never decode with the 3.13 table, where opcode 100 is a jump
    and 124 is `LOAD_FAST`.
    """
    version = _as_tuple(version)
    if version in OPNAMES:
        return OPNAMES[version]
    lower = [key for key in OPNAMES if key <= version]
    if not lower:
        return OPNAMES[min(OPNAMES)]
    return OPNAMES[max(lower)]


def _version_key(version: tuple) -> str:
    return "%d.%d" % _as_tuple(version)


def jump_kind(version: tuple, opname: str) -> str:
    """``relative``, ``absolute`` or ``""`` for a jump opcode."""
    kinds = JUMP_KINDS.get(_version_key(version), {})
    if opname in kinds.get("relative", ()):
        return "relative"
    if opname in kinds.get("absolute", ()):
        return "absolute"
    return ""


def compare_table(version: tuple) -> tuple:
    """The comparison names a COMPARE_OP operand indexes, where the version
    indexes a list at all (3.12 and later pack flags instead)."""
    return COMPARE_TABLES.get(_version_key(version), ())


#: the six comparison names 3.12 and later index, with flags carried in the low
#: bits of the operand rather than in the table
COMPARE_SYMS = ["<", "<=", "==", "!=", ">", ">="]


#: BINARY_OP operand -> source operator.  0-25 are the binary and in-place
#: families every version from 3.11 shares; 26 is the subscript read the
#: compiler folds into BINARY_OP when it inlines a store.
BINARY_SYMS = {0: "+", 1: "&", 2: "//", 3: "<<", 4: "@", 5: "*", 6: "%", 7: "|",
               8: "**", 9: ">>", 10: "-", 11: "/", 12: "^", 13: "+=", 14: "&=",
               15: "//=", 16: "<<=", 17: "@=", 18: "*=", 19: "%=", 20: "|=",
               21: "**=", 22: ">>=", 23: "-=", 24: "/=", 25: "^=", 26: "[]"}
''')
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite tables.py")
    parser.add_argument("--show", action="store_true", help="report what was read")
    args = parser.parse_args()

    releases: dict[str, Release] = {}
    missing = []
    for version in BRANCHES:
        release = read_release(version)
        if release is None or not release.table:
            missing.append(version)
            continue
        releases[version] = release
    for version, release in releases.items():
        print(f"  {version}: {len(release.table):3d} opcodes from {release.source}"
              f"  ({len(release.relative)} relative, {len(release.absolute)} absolute"
              f" jumps, {len(release.compare)} comparisons)")
    for version in missing:
        print(f"  {version}: not read from upstream - keeping the committed table")
    if missing and args.write:
        print("\nrefusing to write a table set with gaps", file=sys.stderr)
        return 1
    if args.write:
        text = render(releases)
        TABLES.write_text(text, encoding="utf-8")
        print(f"\nwrote {TABLES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
