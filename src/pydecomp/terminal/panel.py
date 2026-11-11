"""pydecomp - panel."""
from __future__ import annotations

from ..terminal.animate import width
from ..terminal.color import BOLD, GREEN, GREY, ellipsis, paint, vlen

def panel(title: str, rows: list[tuple[str, str, str]], tint: str = GREEN) -> None:
    """A box that stays aligned no matter how wide the terminal or the value is."""
    box_w = width() - 3
    top = f"╭─ {title} "
    print("   " + paint(top + "─" * max(0, box_w - len(top) - 1) + "╮", tint, BOLD))
    for label, value, value_tint in rows:
        room = max(8, box_w - 3 - 10)                # 9 for the label, 1 for the gap
        body = paint(f"{label:<9}", GREY) + " " + paint(ellipsis(str(value), room),
                                                        value_tint)
        pad = " " * max(0, box_w - 3 - vlen(body))
        print("   " + paint("│ ", tint) + body + pad + paint("│", tint))
    print("   " + paint("╰" + "─" * (box_w - 2) + "╯", tint, BOLD))
