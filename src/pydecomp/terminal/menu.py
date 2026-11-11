"""pydecomp - menu."""
from __future__ import annotations

import time

from ..engine.run import deobfuscate
from ..native import deobfuscate_native
from ..terminal.animate import clear, width
from ..terminal.banner import header
from ..terminal.color import (
    BOLD, GREEN, GREY, MAGENTA, RED, WHITE,
    YELLOW, clip, ellipsis, paint, vlen,
)

def menu() -> None:
    box_w = width() - 3
    inner = max(4, box_w - 3)
    top = "╭─ MAIN MENU "
    print("   " + paint(top + "─" * max(0, box_w - len(top) - 1) + "╮", MAGENTA, BOLD))
    # One line per option when there is room; on a phone the description drops to
    # its own line instead of being chopped in the middle of a word.
    stacked = inner < 62
    name_w = max(10, inner - 6) if stacked else (24 if box_w >= 72 else 16)
    rows = [
        ("1", "Deobfuscate a script", "peel every layer  ·  save one file",
         "peel layers, save one file", True),
        ("2", "Cython module (.so)", "rebuild the source from a compiled module",
         "source from a .so", True),
        ("3", "ELF binary", "find python payloads inside a binary",
         "payloads inside a binary", True),
        ("0", "Exit", "", "", False),
    ]

    def row(body: str) -> None:
        body = clip(body, inner)
        pad = " " * max(0, inner - vlen(body))
        print("   " + paint("│ ", MAGENTA) + body + pad + paint("│", MAGENTA))

    for key, name, desc, short, hot in rows:
        body = (paint(f"[{key}]", GREEN if hot else GREY, BOLD) + "  "
                + paint(f"{ellipsis(name, name_w):<{name_w}}", WHITE, BOLD if hot else ""))
        if stacked:
            row(body.rstrip())
            if desc:
                row(paint("     " + ellipsis(short or desc, inner - 5), GREY))
            continue
        room = inner - vlen(body) - 1
        if desc and room >= 8:
            body += " " + paint(ellipsis(desc, room), GREY)
        row(body)
    print("   " + paint("╰" + "─" * (box_w - 2) + "╯", MAGENTA, BOLD))


def ask_file(hint: str = "", label: str = "script") -> str | None:
    print("   " + paint(f"paste the path of the {label}, then Enter", GREY))
    if hint:
        print("   " + paint(f"(last used: {hint})", GREY))
    try:
        value = input(f"   {paint('❯', MAGENTA, BOLD)} ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not value:
        return hint or None
    return value.strip().strip("'\"")

def interactive_loop(out_dir: str | None) -> int:
    target: str | None = None
    while True:
        header()
        menu()
        print()
        try:
            choice = input(f"   {paint('❯', MAGENTA, BOLD)} option ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("0", "q", "quit", "exit"):
            clear()
            print("\n   " + paint("bye ⚡", GREY) + "\n")
            return 0
        if choice not in ("1", "01", "2", "02", "3", "03"):
            print("   " + paint("!", YELLOW) + " pick 1, 2, 3 or 0")
            time.sleep(1.0)
            continue

        mode = "auto"
        label = "script"
        if choice in ("2", "02"):
            mode, label = "cython", "Cython module (.so)"
        elif choice in ("3", "03"):
            mode, label = "elf", "ELF binary"

        print()
        path = ask_file(target or "", label)
        if not path:
            print("   " + paint("✘", RED) + " no path given\n")
            time.sleep(1.0)
            continue
        target = path
        print()
        if mode == "auto":
            deobfuscate(path, out_dir)
        else:
            deobfuscate_native(path, out_dir, mode)
        print()
        try:
            input("   " + paint("press Enter for the menu", GREY) + " ")
        except (EOFError, KeyboardInterrupt):
            return 0
