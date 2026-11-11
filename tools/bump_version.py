#!/usr/bin/env python3
"""Bump the version everywhere it is written down.

The version lives in exactly one place in the code (``src/pydecomp/limits.py``;
``pyproject.toml`` reads it through hatch), plus the citation file and the
changelog.  This tool updates all of them and refuses to leave the tree
inconsistent.

    python3 tools/bump_version.py 8.2.0
    python3 tools/bump_version.py 8.2.0 --date 2026-11-15 --dry-run
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIMITS = ROOT / "src" / "pydecomp" / "limits.py"
CITATION = ROOT / "CITATION.cff"
CHANGELOG = ROOT / "CHANGELOG.md"

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def current() -> str:
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', LIMITS.read_text(), re.M)
    if not match:
        raise SystemExit("no __version__ in limits.py")
    return match.group(1)


def bump_limits(version: str) -> bool:
    text = LIMITS.read_text()
    new, count = re.subn(r'^__version__\s*=\s*"[^"]+"',
                         f'__version__ = "{version}"', text, count=1, flags=re.M)
    if count != 1:
        raise SystemExit("could not rewrite limits.py")
    LIMITS.write_text(new)
    return True


def bump_citation(version: str, date: str) -> bool:
    text = CITATION.read_text()
    text = re.sub(r"^version: .*$", f"version: {version}", text, count=1, flags=re.M)
    text = re.sub(r"^date-released: .*$", f'date-released: "{date}"', text,
                  count=1, flags=re.M)
    text = re.sub(r"^  version: .*$", f"  version: {version}", text, count=1, flags=re.M)
    CITATION.write_text(text)
    return True


def bump_changelog(version: str, date: str) -> bool:
    text = CHANGELOG.read_text()
    if f"## [{version}]" in text:
        print(f"  changelog already has {version}; leaving it alone")
        return False
    anchor = "## [Unreleased]"
    if anchor not in text:
        raise SystemExit("no [Unreleased] section in CHANGELOG.md")
    body = text.split(anchor, 1)[1]
    body = body.split("\n## ", 1)[0]
    # move the Unreleased bullets into the new release
    bullets = "\n".join(line for line in body.splitlines() if line.strip())
    entry = f"## [{version}] — {date}\n\n{bullets or '### Changed\n- (describe the release)'}\n\n"
    text = text.replace(anchor, f"{anchor}\n\n" + entry.rstrip() + "\n", 1)
    CHANGELOG.write_text(text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="new version, e.g. 8.2.0")
    parser.add_argument("--date", default=dt.date.today().isoformat())
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not SEMVER.match(args.version):
        print(f"not a semantic version: {args.version}")
        return 2

    old = current()
    print(f"  {old} -> {args.version}  ({args.date})")
    if args.dry_run:
        print("  dry run: nothing written")
        return 0

    bump_limits(args.version)
    bump_citation(args.version, args.date)
    bump_changelog(args.version, args.date)

    # a version bump invalidates the single-file build
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_single.py")], check=False)
    print("  next: update CHANGELOG prose, run tools/run_gates.py, commit, tag")
    return 0


if __name__ == "__main__":
    sys.exit(main())
