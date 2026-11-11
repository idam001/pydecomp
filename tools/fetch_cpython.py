#!/usr/bin/env python3
"""Fetch the CPython sources pydecomp's tables are derived from.

Development helper, never part of the installed package: it downloads
``Lib/opcode.py`` (or ``Lib/dis.py``) and ``Python/marshal.c`` for a release so
the opcode numbers and the marshal format can be compared against the real
thing instead of memory.

    python3 tools/fetch_cpython.py --list
    python3 tools/fetch_cpython.py 3.9 3.10 3.13        # into .cache/cpython
    python3 tools/fetch_cpython.py 3.13 --file Python/marshal.c --print

Everything lands in ``.cache/cpython/<version>/`` which is git-ignored; nothing
is imported and nothing is executed.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "cpython"
BASE = "https://raw.githubusercontent.com/python/cpython/{tag}/{path}"

SUPPORTED = ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]

DEFAULT_FILES = ["Lib/opcode.py", "Python/marshal.c", "Include/opcode_ids.h"]

# pydecomp parses marshal without an interpreter, so the C source is the
# authority on the type tags; these are the ones it implements.
MARSHAL_TAGS = {
    "TYPE_NULL": "0", "TYPE_NONE": "N", "TYPE_FALSE": "F", "TYPE_TRUE": "T",
    "TYPE_STOPITER": "S", "TYPE_ELLIPSIS": ".", "TYPE_INT": "i", "TYPE_INT64": "I",
    "TYPE_FLOAT": "f", "TYPE_BINARY_FLOAT": "g", "TYPE_COMPLEX": "x",
    "TYPE_BINARY_COMPLEX": "y", "TYPE_LONG": "l", "TYPE_STRING": "s",
    "TYPE_INTERNED": "t", "TYPE_REF": "r", "TYPE_TUPLE": "(", "TYPE_LIST": "[",
    "TYPE_DICT": "{", "TYPE_CODE": "c", "TYPE_UNICODE": "u", "TYPE_UNKNOWN": "?",
    "TYPE_SET": "<", "TYPE_FROZENSET": ">", "TYPE_ASCII": "a", "TYPE_ASCII_INTERNED": "A",
    "TYPE_SMALL_TUPLE": ")", "TYPE_SHORT_ASCII": "z", "TYPE_SHORT_ASCII_INTERNED": "Z",
    "FLAG_REF": "0x80",
}


def tag_for(version: str) -> str:
    return f"v{version}.0" if version.count(".") == 1 else version


def fetch(version: str, path: str) -> pathlib.Path:
    url = BASE.format(tag=tag_for(version), path=path)
    target = CACHE / version / pathlib.PurePosixPath(path).name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        print(f"  cached  {version}/{target.name}")
        return target
    print(f"  get     {url}")
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read()
    target.write_bytes(body)
    print(f"          {len(body):,} B -> {target.relative_to(ROOT)}")
    return target


def show_tags(path: pathlib.Path) -> None:
    text = path.read_text(errors="replace")
    print(f"\n  marshal type tags referenced in {path.name}:")
    for name, tag in MARSHAL_TAGS.items():
        present = f"Py_{name}" in text or f"case '{tag}'" in text or f"'{tag}'" in text
        print(f"    {'ok ' if present else '-- '} {name:<24} {tag}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("versions", nargs="*", help="versions to fetch (default: running)")
    parser.add_argument("--file", action="append", dest="files",
                        help="path inside the CPython tree (repeatable)")
    parser.add_argument("--print", action="store_true", help="print the fetched file")
    parser.add_argument("--list", action="store_true", help="list supported versions")
    parser.add_argument("--tags", action="store_true", help="compare marshal type tags")
    args = parser.parse_args()

    if args.list:
        print("supported:", " ".join(SUPPORTED))
        print("default files:", " ".join(DEFAULT_FILES))
        return 0

    versions = args.versions or [f"{sys.version_info[0]}.{sys.version_info[1]}"]
    files = args.files or DEFAULT_FILES
    for version in versions:
        if version not in SUPPORTED:
            print(f"unsupported version {version}; have {', '.join(SUPPORTED)}")
            return 2
        print(f"\n{version}:")
        for path in files:
            try:
                target = fetch(version, path)
            except Exception as exc:                       # noqa: BLE001 - network
                print(f"  ! {path}: {exc}")
                continue
            if args.print:
                print(target.read_text(errors="replace"))
            if args.tags and target.name == "marshal.c":
                show_tags(target)
    print(f"\ncache: {CACHE.relative_to(ROOT)} (git-ignored)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
