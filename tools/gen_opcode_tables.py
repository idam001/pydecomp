#!/usr/bin/env python3
"""Validate (and optionally refresh) the per-version opcode tables.

``src/pydecomp/bytecode/opcodes/tables.py`` carries one ``NAME=value`` line per
supported CPython version so pydecomp can disassemble a 3.9 ``marshal`` image on
a 3.13 interpreter.  Those numbers are the part of the project most likely to
rot silently, so this tool checks them three ways:

1. **Coherence** — every table parses, has no duplicate opcode numbers, no name
   bound to two numbers and no negative values.
2. **Cross-version drift** — an opcode that exists in two versions should not
   silently change number between them unless it is in the known-renumbered set.
3. **Ground truth** — for the *running* interpreter, every opcode pydecomp claims
   for that version must match ``dis.opmap`` exactly.

    python3 tools/gen_opcode_tables.py --check     # exit 1 on any drift
    python3 tools/gen_opcode_tables.py --write     # refresh the running version
    python3 tools/gen_opcode_tables.py --show 3.13
"""
from __future__ import annotations

import argparse
import ast
import dis
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLES = ROOT / "src" / "pydecomp" / "bytecode" / "opcodes" / "tables.py"

# Opcodes that legitimately moved between releases (pseudo-instruction churn).
KNOWN_RENUMBERED = {
    "RETURN_VALUE", "RETURN_CONST", "YIELD_VALUE", "CALL", "RESUME", "PRECALL",
    "PUSH_NULL", "BEFORE_WITH", "END_FOR", "END_SEND", "CLEANUP_THROW", "GET_ITER",
    "SEND", "JUMP_BACKWARD", "BEFORE_ASYNC_WITH", "ASYNC_GEN_WRAP", "BINARY_SUBSCR",
    "LOAD_ATTR", "STORE_ATTR", "COMPARE_OP", "IS_OP", "CONTAINS_OP", "COPY",
    "SWAP", "LIST_APPEND", "SET_ADD", "MAP_ADD", "BUILD_STRING", "FORMAT_VALUE",
}

# 3.13 rearranged the whole opcode space (specialised families were folded into
# the base table), so numbers across that boundary are not comparable at all.
RENUMBERED_BOUNDARIES = {("3.12", "3.13"), ("3.13", "3.14")}

LIMIT = 2 ** 8          # opcodes are a byte, even with EXTENDED_ARG folding


def load_tables() -> dict[str, dict[str, int]]:
    """Parse ``_OPCODE_TEXT`` without importing the package."""
    tree = ast.parse(TABLES.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(target, "id", "") == "_OPCODE_TEXT" for target in node.targets):
            raw = ast.literal_eval(node.value)
            break
    else:
        raise SystemExit("_OPCODE_TEXT not found in tables.py")

    tables: dict[str, dict[str, int]] = {}
    for version, text in raw.items():
        table: dict[str, int] = {}
        blob = text if isinstance(text, str) else " ".join(text)
        for token in blob.split():
            name, _, value = token.partition("=")
            if not name or not value:
                continue
            table[name] = int(value, 0)
        tables[version] = table
    return tables


def check_coherence(tables: dict[str, dict[str, int]]) -> list[str]:
    problems: list[str] = []
    for version, table in sorted(tables.items()):
        if not table:
            problems.append(f"{version}: empty table")
            continue
        seen: dict[int, str] = {}
        for name, value in table.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                problems.append(f"{version}: odd opcode name {name!r}")
            if not 0 <= value < LIMIT:
                problems.append(f"{version}: {name}={value} outside 0..{LIMIT - 1}")
            if value in seen and seen[value] != name:
                problems.append(f"{version}: {name} and {seen[value]} both = {value}")
            seen[value] = name
            if "=" in name:
                problems.append(f"{version}: unparsed token {name!r}")
    return problems


def check_drift(tables: dict[str, dict[str, int]]) -> list[str]:
    problems: list[str] = []
    versions = sorted(tables)
    for older, newer in zip(versions, versions[1:]):
        if (older, newer) in RENUMBERED_BOUNDARIES:
            continue                      # wholesale reshuffle, nothing to compare
        left, right = tables[older], tables[newer]
        for name in sorted(set(left) & set(right)):
            if left[name] != right[name] and name not in KNOWN_RENUMBERED:
                problems.append(
                    f"{name}: {left[name]} in {older} but {right[name]} in {newer} "
                    f"(add to KNOWN_RENUMBERED if the move is real)")
    return problems


def running_version() -> str:
    major, minor = sys.version_info[:2]
    return f"{major}.{minor}"


def check_ground_truth(tables: dict[str, dict[str, int]]) -> list[str]:
    version = running_version()
    table = tables.get(version)
    if table is None:
        print(f"  (no table for the running interpreter, {version}: skipped)")
        return []
    problems: list[str] = []
    # INSTRUMENTED_* only exists when sys.monitoring is active; a normal .pyc
    # never contains one, so the table deliberately omits them.
    def wanted(name: str, value: int = 0) -> bool:
        # INSTRUMENTED_* needs sys.monitoring; values above 255 are compiler
        # pseudo-instructions.  Neither can appear in a real .pyc.
        return not name.startswith("INSTRUMENTED_") and value < LIMIT

    for name, value in sorted(dis.opmap.items()):
        if not wanted(name, value):
            continue
        claimed = table.get(name)
        if claimed is None:
            problems.append(f"{version}: {name}={value} is missing from the table")
        elif claimed != value:
            problems.append(f"{version}: {name}={claimed} but dis says {value}")
    # specialised opcodes are real names but never appear in a .pyc
    known = {**getattr(dis, "_all_opmap", {}), **dis.opmap,
             **getattr(dis, "_specialized_opmap", {})}
    for name in sorted(set(table) - set(known)):
        if not wanted(name, table[name]):
            continue
        problems.append(f"{version}: table claims {name}={table[name]} (not in this build)")
    return problems


def write_table(tables: dict[str, dict[str, int]]) -> None:
    version = running_version()
    tokens = " ".join(f"{name}={value}" for name, value in sorted(
        dis.opmap.items(), key=lambda item: item[1]))
    text = TABLES.read_text(encoding="utf-8")
    if version in tables:
        pattern = re.compile(rf'("{re.escape(version)}": \(\n)(?:.*?\n)(    \),)', re.S)
        replacement = (tokens[i:i + 96] for i in range(0, 0, 96))   # placeholder
        del replacement
        wrapped = "\n".join(f'        "{tokens[i:i + 96]} "' for i in range(0, len(tokens), 96))
        new, count = pattern.subn(lambda match: match.group(1) + wrapped + "\n" + match.group(2),
                                  text, count=1)
        if count != 1:
            raise SystemExit(f"could not rewrite the {version} entry")
        TABLES.write_text(new, encoding="utf-8")
        print(f"  rewrote the {version} table ({len(dis.opmap)} opcodes)")
    else:
        print(f"  no {version} entry in tables.py; add one by hand with:\n")
        print(f'    "{version}": (\n' + "\n".join(
            f'        "{tokens[i:i + 96]} "' for i in range(0, len(tokens), 96)) + "\n    ),")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate and exit non-zero on drift")
    parser.add_argument("--write", action="store_true", help="refresh the running version")
    parser.add_argument("--show", metavar="VERSION", help="print one table")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    tables = load_tables()
    if args.show:
        table = tables.get(args.show)
        if table is None:
            print(f"no table for {args.show}; have {', '.join(sorted(tables))}")
            return 1
        for name, value in sorted(table.items(), key=lambda item: item[1]):
            print(f"  {value:>4}  {name}")
        return 0

    if args.write:
        write_table(tables)
        tables = load_tables()

    problems = check_coherence(tables) + check_drift(tables)
    if args.check:
        problems += check_ground_truth(tables)

    if not args.quiet:
        total = sum(len(table) for table in tables.values())
        print(f"versions: {', '.join(sorted(tables))}   opcodes: {total}")
    if problems:
        print(f"{len(problems)} problem(s):")
        for problem in problems[:40]:
            print("  " + problem)
        if len(problems) > 40:
            print(f"  … and {len(problems) - 40} more")
        return 1
    if not args.quiet:
        print("opcode tables: coherent, no drift, ground truth matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
