#!/usr/bin/env python3
"""Regenerate the text fixtures used by the integration gates.

Every fixture is *generated*: a small generator under ``tests/fixtures/`` writes
the obfuscated sample together with the plain source it wraps, so a fixture
never contains unexplained bytes and can always be rebuilt byte for byte.

    python3 tools/make_fixtures.py            # rebuild everything
    python3 tools/make_fixtures.py --check    # fail if anything is stale
    python3 tools/make_fixtures.py --list     # what would be built

The compiled native fixtures are separate: see
``tests/fixtures/native/make_native_fixtures.py`` (needs cython + gcc).
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

GENERATORS = [
    ("obf_cases", FIXTURES / "make_fixtures.py"),
    ("obf_bench", FIXTURES / "obf_cases.py"),
]


def fingerprint(folder: pathlib.Path) -> str:
    """A stable hash of every file a fixture directory contains."""
    digest = hashlib.sha256()
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(folder).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="rebuild in a scratch copy and compare hashes")
    parser.add_argument("--list", action="store_true", help="show the generators")
    args = parser.parse_args()

    missing = [str(path) for _name, path in GENERATORS if not path.exists()]
    if args.list:
        for name, path in GENERATORS:
            state = "present" if path.exists() else "MISSING"
            print(f"  {name:<12} {path.relative_to(ROOT)}  ({state})")
        return 1 if missing else 0
    if missing:
        print("missing generator(s):", *missing, sep="\n  ")
        return 1

    before = {name: fingerprint(FIXTURES / name)
              for name, _ in GENERATORS if (FIXTURES / name).is_dir()}
    for name, path in GENERATORS:
        print(f"  building {name} from {path.relative_to(ROOT)}")
        done = subprocess.run([sys.executable, str(path)], capture_output=True, text=True,
                              timeout=600)
        if done.returncode != 0:
            print(done.stdout[-1500:], done.stderr[-1500:], sep="\n")
            return 1
    after = {name: fingerprint(FIXTURES / name)
             for name, _ in GENERATORS if (FIXTURES / name).is_dir()}

    changed = [name for name in after if before.get(name) != after[name]]
    if args.check and changed:
        print(f"stale fixtures: {', '.join(changed)} — regenerate and commit")
        return 1
    print(f"fixtures: {len(after)} set(s) rebuilt"
          + (f", {len(changed)} changed" if changed else ", no changes"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
