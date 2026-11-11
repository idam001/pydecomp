"""pydecomp - color."""
from __future__ import annotations

import os
import re
import sys


USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

RESET, BOLD, DIM = "\x1b[0m", "\x1b[1m", "\x1b[2m"

RED, GREEN, YELLOW, CYAN, MAGENTA, WHITE, GREY = (
    "\x1b[38;5;203m", "\x1b[38;5;46m", "\x1b[38;5;220m",
    "\x1b[38;5;51m", "\x1b[38;5;177m", "\x1b[97m", "\x1b[38;5;245m")

BLUE = "\x1b[38;5;39m"

# Backgrounds, for the welcome band on the banner.
RED_BG, GREEN_BG, YELLOW_BG = ("\x1b[48;5;160m", "\x1b[48;5;34m",
                               "\x1b[48;5;220m")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

def paint(text: str, *codes: str) -> str:
    if not USE_COLOR or not codes:
        return text
    return "".join(codes) + text + RESET

def ellipsis(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"

def clip(text: str, room: int) -> str:
    """Cut painted text to ``room`` visible columns without breaking escape codes."""
    if room <= 0:
        return ""
    if vlen(text) <= room:
        return text
    out, visible, index, coloured = [], 0, 0, False
    while index < len(text):
        match = ANSI_RE.match(text, index)
        if match:
            out.append(match.group(0))
            coloured = True
            index = match.end()
            continue
        if visible >= room - 1:
            break
        out.append(text[index])
        visible += 1
        index += 1
    out.append("…")
    if coloured:
        out.append(RESET)
    return "".join(out)


def shorten_path(path: str, room: int) -> str:
    """Keep the part of a path that identifies the file when space is short."""
    path = str(path)
    if len(path) <= room:
        return path
    pieces = [piece for piece in path.split(os.sep) if piece]
    keep: list[str] = []
    for piece in reversed(pieces):
        trial = os.sep.join([piece, *keep])
        if keep and len(trial) + 2 > room:
            break
        keep.insert(0, piece)
    candidate = "…" + os.sep + os.sep.join(keep) if keep else path
    return candidate if len(candidate) <= room else ellipsis(path, room)


def vlen(text: str) -> int:
    """Visible length of a string that may contain ANSI colour codes."""
    return len(ANSI_RE.sub("", text))

def emit(painted: str, indent: int = 3) -> None:
    """Print one line that fits the terminal — a phone must never wrap it."""
    from ..terminal.animate import width
    print(" " * indent + clip(painted, max(12, width() - indent)))


def step(msg: str) -> None:
    emit(paint("▸", CYAN) + " " + msg)

def ok(msg: str) -> None:
    emit(paint("✔", GREEN) + " " + msg)

def warn(msg: str) -> None:
    emit(paint("!", YELLOW) + " " + msg)

def die(msg: str, code: int = 1) -> None:
    emit(paint("✘", RED) + " " + msg)
    raise SystemExit(code)

def ask(prompt: str, default: str = "") -> str:
    tail = paint(f" [{default}]", GREY) if default else ""
    try:
        value = input(f"   {paint('?', MAGENTA)} {prompt}{tail}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)
    return value or default

INTERACTIVE = bool(getattr(sys.stdout, "isatty", lambda: False)()) \
    and not os.environ.get("PYDECOMP_NO_ANIM")
