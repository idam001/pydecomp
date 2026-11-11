"""pydecomp - banner.

The face of the tool: a block-letter logo, the author's welcome band, the
host's network and country, and a small identity card.  Everything here is
printed through :func:`paint`, so ``--no-color`` (or a pipe) turns it into
plain text with no escape codes.

Layout is capped to the terminal width and never wraps: the logo is 47 columns,
which leaves room for the ornament rules on an 80-column Termux window.
"""
from __future__ import annotations

from ..limits import __version__
from ..terminal import identity
from ..terminal.animate import clear, width
from ..terminal.color import (BOLD, CYAN, GREEN, GREY, MAGENTA, RED, RED_BG, WHITE,
                              YELLOW, paint, vlen)

# 5 rows x 5 columns per glyph, joined with one space: 47 columns for PYDECOMP.
GLYPHS = {
    "P": ("████ ", "█   █", "████ ", "█    ", "█    "),
    "Y": ("█   █", "█   █", " ███ ", "  █  ", "  █  "),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "C": (" ████", "█    ", "█    ", "█    ", " ████"),
    "O": (" ███ ", "█   █", "█   █", "█   █", " ███ "),
    "M": ("█   █", "██ ██", "█ █ █", "█   █", "█   █"),
}

WORD = "PYDECOMP"

# Cyan / magenta / cyan, like the KHOSO-style boards this banner is modelled on.
LOGO_TINT = (CYAN, CYAN, MAGENTA, MAGENTA, CYAN)

ORNAMENT = "꧁✿❀✿꧂"


def logo() -> list[str]:
    """The word PYDECOMP in block letters, one string per row."""
    return [" ".join(GLYPHS[letter][row] for letter in WORD) for row in range(5)]


LOGO = logo()


def _rule(fill: str = "─") -> str:
    """An ornament rule that fits the terminal."""
    room = max(20, min(width() - 3, 78))
    inner = max(4, room - 2 * vlen(ORNAMENT) - 4)
    return ORNAMENT + fill * inner + ORNAMENT


def _centre(text: str, room: int) -> str:
    """Centre a band inside ``room`` columns, never wider than the rule."""
    visible = vlen(text)
    if visible >= room:
        return text[:room]
    left = (room - visible) // 2
    return " " * left + text + " " * (room - visible - left)


def _identity_lines() -> list[str]:
    network = identity.network()
    country = identity.country_label()
    return [
        paint("[ NETWORK ]", GREEN, BOLD) + paint(" : ", GREY)
        + paint(network, WHITE, BOLD),
        paint("[ COUNTRY ]", GREEN, BOLD) + paint(" : ", GREY)
        + paint(country, WHITE, BOLD),
    ]


def _card_lines() -> list[str]:
    rows = identity.card()
    widths = max(len(label) for label, _ in rows)
    return [paint("[•] ", GREEN, BOLD)
            + paint(label.ljust(widths), CYAN)
            + paint(" : ", GREY)
            + paint(f"[{value}]", WHITE, BOLD)
            for label, value in rows]


def _print_common(tagline: str) -> None:
    print("   " + paint(_rule(), GREEN))
    print()
    for line, tint in zip(LOGO, LOGO_TINT):
        print("   " + paint(line, tint, BOLD))
    print()
    print("   " + paint(_rule(), GREEN))
    room = max(24, min(width() - 3, 78)) - 2 * vlen(ORNAMENT)
    band = _centre("  " + identity.WELCOME + "  ", room)
    print("   " + paint(band, WHITE, BOLD, RED_BG))
    print()
    for line in _identity_lines():
        print("   " + line)
    print("   " + paint("═" * room, GREEN))
    for line in _card_lines():
        print("   " + line)
    print("   " + paint("═" * room, GREEN))
    print("   " + paint(f" v{__version__}", GREY)
          + paint("  ·  ", GREY)
          + paint(tagline, YELLOW)
          + paint("  ·  by ", GREY)
          + paint(identity.author(), CYAN, BOLD))
    print()


def banner() -> None:
    """The full board, used when the CLI starts interactively."""
    print()
    _print_common("static python deobfuscator — one file in, one file out")


def header(do_clear: bool = True) -> None:
    """The board printed before an interactive run."""
    if do_clear:
        clear()
    print()
    _print_common("samples are analysed, never executed")
    print("   " + paint("send a sample the engine cannot peel → ", GREY)
          + paint("issues", CYAN, BOLD))
    print()


def stamp() -> str:
    """The one-line signature written above every recovered file."""
    return identity.signature()


def short_banner() -> str:
    """A single line for non-interactive runs and the report header."""
    return (f"PYDECOMP v{__version__} · by {identity.author()} · "
            f"{identity.network()} · {identity.country()}")


__all__ = ["banner", "header", "logo", "LOGO", "stamp", "short_banner",
           "ORNAMENT", "RED"]
