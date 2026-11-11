"""pydecomp - menu."""
from __future__ import annotations

import time

from ..engine.run import deobfuscate
from ..native import deobfuscate_native
from ..terminal.animate import clear, width
from ..terminal.banner import header
from ..terminal.color import (
    BOLD, GREEN, GREY, MAGENTA, RED, WHITE,
    YELLOW, ellipsis, paint, vlen,
)

def menu() -> None:
    box_w = width() - 3
    top = "╭─ MAIN MENU "
    print("   " + paint(top + "─" * max(0, box_w - len(top) - 1) + "╮", MAGENTA, BOLD))
    name_w = 24 if box_w >= 72 else 16
    rows = [
        ("1", "Deobfuscate a script", "peel every layer  ·  save one file", True),
        ("2", "Cython module (.so)", "rebuild the source from a compiled module", True),
        ("3", "ELF binary", "find python payloads inside a binary", True),
        ("0", "Exit", "", False),
    ]
    for key, name, desc, hot in rows:
        room = box_w - 3 - (3 + 2 + name_w + 1)     # leave one space before the desc
        shown_desc = ellipsis(desc, room) if room >= 8 else ""
        body = (paint(f"[{key}]", GREEN if hot else GREY, BOLD) + "  "
                + paint(f"{ellipsis(name, name_w):<{name_w}}", WHITE, BOLD if hot else "")
                + (" " + paint(shown_desc, GREY) if shown_desc else ""))
        pad = " " * max(0, box_w - 3 - vlen(body))
        print("   " + paint("│ ", MAGENTA) + body + pad + paint("│", MAGENTA))
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
