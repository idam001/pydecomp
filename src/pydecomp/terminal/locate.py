"""pydecomp — locate.

"file not found" is not an answer.  Analysts work from a phone as often as a
desk, and a path typed on a phone (``KAMRUL~4.py``) is rarely where the shell
happens to be.  This module resolves what the operator meant and prints the
command that would have worked.
"""
from __future__ import annotations

import difflib
import os
import sys

# Where a phone or a lab box actually keeps downloads.
SEARCH_DIRS = (
    ".",
    "~",
    "~/storage/downloads",
    "~/storage/shared",
    "~/Downloads",
    "~/Download",
    "~/Downloads/Telegram",
    "/sdcard/Download",
    "/sdcard/Downloads",
    "/sdcard",
    "/tmp",
)

MAX_SUGGESTIONS = 3


def expand(path: str) -> str:
    """Strip what a copy/paste adds, then let the shell's shorthand through."""
    cleaned = str(path).strip().strip("'\"").strip()
    cleaned = os.path.expandvars(os.path.expanduser(cleaned))
    return cleaned


def _listing(directory: str) -> list[str]:
    try:
        return sorted(os.listdir(directory))
    except OSError:
        return []


def _dirs() -> list[str]:
    seen, out = set(), []
    here = os.getcwd()
    for raw in (here, *SEARCH_DIRS):
        directory = os.path.abspath(os.path.expanduser(raw))
        if directory in seen or not os.path.isdir(directory):
            continue
        seen.add(directory)
        out.append(directory)
    return out


def suggestions(path: str, limit: int = MAX_SUGGESTIONS) -> list[str]:
    """Existing files that are plausibly the one that was meant."""
    wanted = os.path.basename(expand(path))
    if not wanted:
        return []
    found: list[str] = []
    for directory in _dirs():
        names = _listing(directory)
        for name in names:
            full = os.path.join(directory, name)
            if os.path.isfile(full) and name == wanted and full not in found:
                found.append(full)
    if found:
        return found[:limit]
    for directory in _dirs():                       # then case-blind
        names = _listing(directory)
        for name in names:
            full = os.path.join(directory, name)
            if os.path.isfile(full) and name.lower() == wanted.lower() and full not in found:
                found.append(full)
    if found:
        return found[:limit]
    pool: list[str] = []
    for directory in _dirs():                       # then close names
        pool.extend(os.path.join(directory, name) for name in _listing(directory))
    close = difflib.get_close_matches(os.path.join(os.getcwd(), wanted), pool, limit, 0.75)
    return [item for item in close if os.path.isfile(item)][:limit]


def sample_command(found: str, out_dir: str | None = None) -> str:
    """A command the operator can paste, using the name they actually invoked."""
    program = os.path.basename(sys.argv[0] or "pydecomp")
    if program.endswith(".py"):
        head = f"python {program}"
    else:
        head = program
    out = f" -o {out_dir}" if out_dir else ""
    shown = found
    home = os.path.expanduser("~")
    if shown.startswith(home + os.sep):
        shown = "~" + shown[len(home):]
    return f"{head} '{shown}'{out}"


def missing(path: str, out_dir: str | None = None) -> list[str]:
    """Lines explaining what was looked for and what to type instead."""
    given = str(path).strip().strip("'\"")
    resolved = os.path.abspath(expand(path))
    lines = [f"file not found: {given}",
             f"looked in: {os.getcwd()}"]
    if resolved != given:
        lines.append(f"resolved to: {resolved}")
    if os.path.isdir(resolved):
        contents = [name for name in _listing(resolved)][:6]
        lines.append("that is a folder, not a file"
                     + (f" — it holds: {', '.join(contents)}" if contents else ""))
        return lines
    exact = exact_matches(path)
    if len(exact) > 1:
        lines.append(f"{len(exact)} files share that name — pick one:")
        for option in exact[:4]:
            lines.append("  " + option)
        lines.append("paste: " + sample_command(exact[0], out_dir))
        return lines
    found = suggestions(path)
    if found:
        lines.append("did you mean: " + found[0])
        for extra in found[1:]:
            lines.append("          or: " + extra)
        lines.append("paste: " + sample_command(found[0], out_dir))
    else:
        lines.append("give the full path — on a phone: ~/storage/downloads/<name>")
        lines.append("to see what is there: ls ~/storage/downloads")
    return lines


def exact_matches(path: str) -> list[str]:
    """Files with exactly this name in the places we search."""
    wanted = os.path.basename(expand(path))
    if not wanted:
        return []
    out: list[str] = []
    for directory in _dirs():
        full = os.path.join(directory, wanted)
        if os.path.isfile(full) and full not in out:
            out.append(full)
    return out


def resolve(path: str) -> str | None:
    """The file the operator meant — but only when the answer is unambiguous."""
    resolved = os.path.abspath(expand(path))
    if os.path.isfile(resolved):
        return resolved
    matches = exact_matches(path)
    return matches[0] if len(matches) == 1 else None
