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

def vlen(text: str) -> int:
    """Visible length of a string that may contain ANSI colour codes."""
    return len(ANSI_RE.sub("", text))

def step(msg: str) -> None:
    print("   " + paint("▸", CYAN) + " " + msg)

def ok(msg: str) -> None:
    print("   " + paint("✔", GREEN) + " " + msg)

def warn(msg: str) -> None:
    print("   " + paint("!", YELLOW) + " " + msg)

def die(msg: str, code: int = 1) -> None:
    print("   " + paint("✘", RED) + " " + msg)
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
