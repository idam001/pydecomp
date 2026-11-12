"""pydecomp - locate.

``file not found`` is not an answer, and neither is *"paste this command"*.  If
the tool can see the file, it uses it.  A phone that types ``KAMRUL~4.py`` from
a downloads folder should never have to copy a path back into the shell - the
tool searches, ranks what it finds and carries on.

Ranking, in order, and the reason is printed with the choice:

1. the path exactly as given;
2. the name in the current folder;
3. an exact name match elsewhere on the device (newest wins);
4. a case-insensitive match;
5. the closest name (a typo the operator can see);
6. a bounded recursive scan of home and the usual download folders.

When several files qualify, the newest one is used and the others are listed, so
the choice is visible instead of hidden.  ``--pick N`` overrides it.
"""
from __future__ import annotations

import difflib
import os
import sys
from typing import NamedTuple

# Where a phone or a lab box actually keeps downloads.
SEARCH_DIRS = (
    ".",
    "~",
    "~/storage/downloads",
    "~/storage/shared/Download",
    "~/storage/shared",
    "~/Download",
    "~/Downloads",
    "~/Downloads/Telegram",
    "~/Documents",
    "~/tools",
    "~/samples",
    "/sdcard/Download",
    "/sdcard/Downloads",
    "/sdcard",
    "/storage/emulated/0/Download",
    "/storage/emulated/0",
    "/tmp",
)

MAX_SUGGESTIONS = 3
SCAN_DEPTH = 4                 # how deep the last-resort scan goes
SCAN_BUDGET = 60_000           # how many directory entries it may look at
SCAN_ROOTS = ("~", "/sdcard", "/storage/emulated/0", "/tmp")


class Choice(NamedTuple):
    """The file that was picked, why, and what else qualified."""

    path: str
    reason: str
    alternatives: tuple[str, ...] = ()
    how: str = "exact"

    @property
    def direct(self) -> bool:
        return self.how == "given"


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


def _search_dirs() -> tuple[str, ...]:
    """``PYDECOMP_PATHS`` pins the search space (handy in CI and sandboxes)."""
    override = os.environ.get("PYDECOMP_PATHS", "").strip()
    if override:
        return tuple(part for part in override.split(os.pathsep) if part)
    return SEARCH_DIRS


def _dirs() -> list[str]:
    seen, out = set(), []
    here = os.getcwd()
    for raw in (here, *_search_dirs()):
        directory = os.path.abspath(os.path.expanduser(raw))
        if directory in seen or not os.path.isdir(directory):
            continue
        seen.add(directory)
        out.append(directory)
    return out


def _files(shallow: bool = True) -> list[str]:
    """Every file in the search folders - and one level below them.

    One level down matters more than it looks: a phone keeps the same sample in
    ``~/storage/downloads`` *and* ``~/Download/Telegram``, and a lab keeps
    per-case subfolders.  Walking one level keeps the search instant while
    covering those.
    """
    out: list[str] = []
    seen: set[str] = set()
    for directory in _dirs():
        queue = [directory]
        if shallow:
            queue.extend(os.path.join(directory, entry)
                         for entry in _listing(directory)
                         if not entry.startswith("."))
        for folder in queue:
            if not os.path.isdir(folder):
                continue
            for name in _listing(folder):
                full = os.path.join(folder, name)
                if full in seen or not os.path.isfile(full):
                    continue
                seen.add(full)
                out.append(full)
    return out


def _scan_roots(name: str) -> list[str]:
    """Last resort: walk home and the phone's shared storage for this name.

    Bounded in both depth and entries - a locate must never turn into a full
    disk crawl - and only exact or case-insensitive names are collected.
    """
    wanted = name.lower()
    found: list[str] = []
    budget = SCAN_BUDGET
    skip = {"node_modules", ".git", "__pycache__", ".cache", ".venv", "site-packages"}
    for raw in SCAN_ROOTS:
        root = os.path.abspath(os.path.expanduser(raw))
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for directory, subdirs, files in os.walk(root):
            subdirs[:] = [entry for entry in subdirs if entry not in skip]
            if directory.count(os.sep) - base_depth >= SCAN_DEPTH:
                subdirs[:] = []
            budget -= len(files) + len(subdirs)
            if budget <= 0:
                return found
            for entry in files:
                if entry.lower() == wanted:
                    full = os.path.join(directory, entry)
                    if full not in found:
                        found.append(full)
            if len(found) >= 20:
                return found
    return found


def _under_home(path: str) -> bool:
    home = os.path.expanduser("~")
    return bool(home) and path.startswith(home.rstrip(os.sep) + os.sep)


def _newest(paths: list[str]) -> list[str]:
    """Rank matches: the operator's own folders first, then newest, then largest.

    The home preference matters on a shared box: a stale copy in ``/tmp`` must
    never outrank the download the operator is actually looking at.
    """
    def key(path: str) -> tuple[int, float, int]:
        try:
            info = os.stat(path)
        except OSError:
            return (0, 0.0, 0)
        return (1 if _under_home(path) else 0, info.st_mtime, info.st_size)
    return sorted(paths, key=key, reverse=True)


def _pick(paths: list[str], reason: str, how: str, pick: int | None = None) -> Choice:
    ranked = _newest(paths)
    index = 0
    if pick is not None:
        index = max(0, min(len(ranked) - 1, pick - 1))
        reason = f"{reason} (chosen with --pick {pick})"
    elif len(ranked) > 1:
        reason = f"{reason} — newest of {len(ranked)}"
    others = tuple(path for position, path in enumerate(ranked) if position != index)
    return Choice(ranked[index], reason, others[:MAX_SUGGESTIONS], how)


def exact_matches(path: str) -> list[str]:
    """Files with exactly this name in the places we search."""
    wanted = os.path.basename(expand(path))
    if not wanted:
        return []
    return [full for full in _files() if os.path.basename(full) == wanted]


def search(path: str, pick: int | None = None) -> Choice | None:
    """Find the file the operator meant and say why that one was chosen."""
    given = expand(path)
    if os.path.isfile(given):
        return Choice(os.path.abspath(given), "path as given", (), "given")
    if os.path.isdir(given):
        return None                                  # a folder: the tree mode handles it
    wanted = os.path.basename(given)
    if not wanted:
        return None
    here = os.path.abspath(wanted)
    if os.path.isfile(here):
        return Choice(here, "in the current folder", (), "cwd")
    exact = [item for item in exact_matches(path) if item != here]
    if exact:
        return _pick(exact, "found by name", "exact", pick)
    folded = wanted.lower()
    blind = [full for full in _files() if os.path.basename(full).lower() == folded]
    if blind:
        return _pick(blind, "found by name, ignoring case", "case", pick)
    pool = _files()
    close = difflib.get_close_matches(wanted, [os.path.basename(item) for item in pool],
                                      MAX_SUGGESTIONS, 0.75)
    fuzzy = [item for item in pool if os.path.basename(item) in close]
    if fuzzy:
        return _pick(fuzzy, "closest name to what was typed", "fuzzy", pick)
    scanned = _scan_roots(wanted)
    if scanned:
        return _pick(scanned, f"found by scanning home and shared storage", "scan", pick)
    stem = os.path.splitext(wanted)[0].lower()
    if stem and stem != wanted:
        loose = [full for full in pool if stem in os.path.basename(full).lower()]
        if loose:
            return _pick(loose, "name contains what was typed", "partial", pick)
    return None


def resolve(path: str, pick: int | None = None) -> str | None:
    """The file the operator meant, or None when nothing matches at all."""
    choice = search(path, pick=pick)
    return choice.path if choice is not None else None


def sample_command(found: str, out_dir: str | None = None) -> str:
    """How to invoke the tool on this file - used only in documentation."""
    program = os.path.basename(sys.argv[0] or "pydecomp")
    head = f"python {program}" if program.endswith(".py") else program
    out = f" -o {out_dir}" if out_dir else ""
    shown = found
    home = os.path.expanduser("~")
    if shown.startswith(home + os.sep):
        shown = "~" + shown[len(home):]
    return f"{head} '{shown}'{out}"


def visible_samples(limit: int = 5) -> list[str]:
    """Python-ish files the search can already see, newest first."""
    wanted = (".py", ".pyc", ".pyz", ".so", ".pyd", ".zip", ".whl")
    pool = [full for full in _files() if full.lower().endswith(wanted)]
    return _newest(pool)[:limit]


def missing(path: str, out_dir: str | None = None) -> list[str]:
    """Lines for the case where nothing matches - never a command to paste.

    The operator asked the tool to do the work.  Telling them to retype a
    command is not help, so this reports what was searched and what *is* there,
    and stops.
    """
    given = str(path).strip().strip("'\"")
    resolved = os.path.abspath(expand(path))
    lines = [f"nothing named {given} anywhere I searched"]
    if resolved != given:
        lines.append(f"the name resolves to: {resolved}")
    if os.path.isdir(resolved):
        contents = [name for name in _listing(resolved)][:6]
        lines.append("that is a folder, not a file"
                     + (f" — it holds: {', '.join(contents)}" if contents else ""))
        return lines
    directories = [directory for directory in _dirs()][:4]
    lines.append("searched: " + ", ".join(directories))
    samples = visible_samples()
    if samples:
        home = os.path.expanduser("~")
        shown = []
        for item in samples:
            pretty = "~" + item[len(home):] if item.startswith(home + os.sep) else item
            try:
                shown.append(f"{os.path.basename(pretty)}  ({os.path.getsize(item):,} B)")
            except OSError:
                shown.append(os.path.basename(pretty))
        lines.append("what I can see right now: " + " · ".join(shown))
    else:
        lines.append("no python samples are visible in those folders either")
    return lines


