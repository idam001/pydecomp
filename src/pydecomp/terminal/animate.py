"""pydecomp - animate."""
from __future__ import annotations

import os
import sys
import time

from ..terminal.color import BOLD, CYAN, GREEN, GREY, INTERACTIVE, WHITE, paint

SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

BAR_FULL, BAR_EMPTY = "█", "░"

def clear() -> None:
    """Wipe the screen (no shell call, pure ANSI)."""
    if INTERACTIVE:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

def width(default: int = 78) -> int:
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = default
    return max(52, min(cols, 96))

def rule(ch: str = "─", tint: str = GREY) -> None:
    print("   " + paint(ch * (width() - 6), tint))

def animate_text(text: str, seconds: float = 0.55, tint: str = CYAN) -> None:
    """Type the text out, then a run of dots — the 'it is working' moment."""
    if not INTERACTIVE:
        print("   " + paint("▸", tint) + " " + text)
        return
    sys.stdout.write("   " + paint("▸", tint) + " ")
    sys.stdout.flush()
    for ch in text:
        sys.stdout.write(paint(ch, WHITE, BOLD))
        sys.stdout.flush()
        time.sleep(min(0.02, seconds / max(len(text), 1)))
    for _ in range(10):
        sys.stdout.write(paint("·", GREY))
        sys.stdout.flush()
        time.sleep(0.03)
    sys.stdout.write("\r   " + paint("▸", tint) + " " + paint(text, WHITE)
                     + "\033[K\n")
    sys.stdout.flush()

def animate_bar(label: str, seconds: float = 0.7, tint: str = GREEN,
                detail: str = "") -> None:
    """Fill a progress bar over `seconds`. Decorative but honest: it runs only
    after the work it is announcing has actually finished."""
    bar_w = max(18, min(34, width() - 40))
    if not INTERACTIVE:
        print("   " + paint("▸", CYAN) + " " + label
              + (paint(f"   {detail}", GREY) if detail else ""))
        return
    steps = max(8, int(seconds / 0.02))
    for i in range(steps + 1):
        pct = int(100 * i / steps)
        filled = int(bar_w * i / steps)
        bar = paint(BAR_FULL * filled, tint) + paint(BAR_EMPTY * (bar_w - filled), GREY)
        line = (f"\r   {paint(SPIN[i % len(SPIN)], CYAN)} {label:<22}"
                f"[{bar}] {pct:3d}%")
        if detail:
            line += paint(f"  {detail}", GREY)
        sys.stdout.write(line + "\033[K")
        sys.stdout.flush()
        time.sleep(0.02)
    sys.stdout.write("\r   " + paint("✔", GREEN) + f" {label:<22}"
                     + paint(detail, GREY) + "\033[K")
    sys.stdout.write("\n")
    sys.stdout.flush()

def spinner(label: str, seconds: float = 0.8) -> None:
    if not INTERACTIVE:
        return
    frames = max(6, int(seconds / 0.05))
    for i in range(frames):
        sys.stdout.write(f"\r   {paint(SPIN[i % len(SPIN)], CYAN)} {label}"
                         f"{'.' * (1 + i % 4):<4}\033[K")
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write(f"\r   {paint('✔', GREEN)} {label}\033[K\n")
    sys.stdout.flush()
