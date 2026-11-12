#!/usr/bin/env python3
"""Render the GitHub social preview card (1280x640) from a real run.

The card is a picture of the tool working, not a drawing of one: the monospaced
block is the captured stdout of ``dist/pydecomp.py`` on the PyArmor case, and the
footer carries the commit it came from.

    python3 tools/make_social_card.py
    # then: repository Settings -> Social preview -> upload the PNG
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(ROOT, "dist", "pydecomp.py")
TARGET = os.path.join(ROOT, "docs", "assets", "social-preview.png")
FONTS = "/usr/share/fonts/truetype/dejavu"

W, H = 1280, 640
BG = (13, 17, 23)
PANEL = (22, 27, 34)
FG = (230, 237, 243)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
LINE = (48, 54, 61)


def capture() -> list[str]:
    sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import pyarmor_case

    folder = tempfile.mkdtemp(prefix="card-")
    case = pyarmor_case.build(folder)
    done = subprocess.run(
        [sys.executable, BUNDLE, case["loader"], "-o", os.path.join(folder, "out"),
         "--no-color", "--no-anim"],
        capture_output=True, text=True, timeout=900,
        env={**os.environ, "COLUMNS": "96", "NO_COLOR": "1"})
    lines = []
    for line in (done.stdout or "").splitlines():
        line = line.replace(folder + "/", "~/").replace(folder, "~").rstrip()
        if not line.strip() or line.strip().startswith("cat '"):
            continue
        # the result panel's borders do not survive truncation: keep the content
        line = line.strip()
        while line[:1] in ("│", "╭", "╰") or line[:1] == " ":
            line = line[1:].lstrip() if line[:1] == "│" else line[1:]
        line = line.rstrip("─╮╯│ ").rstrip()
        if line:
            lines.append("  " + line)
    return lines[-15:]


def commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip() or "dev"
    except OSError:
        return "dev"


def main() -> int:
    from PIL import Image, ImageDraw, ImageFont

    lines = capture()
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)
    title = ImageFont.truetype(os.path.join(FONTS, "DejaVuSans-Bold.ttf"), 62)
    tagline = ImageFont.truetype(os.path.join(FONTS, "DejaVuSans.ttf"), 25)
    claim = ImageFont.truetype(os.path.join(FONTS, "DejaVuSans-Bold.ttf"), 27)
    mono = ImageFont.truetype(os.path.join(FONTS, "DejaVuSansMono.ttf"), 14)
    small = ImageFont.truetype(os.path.join(FONTS, "DejaVuSansMono.ttf"), 12)

    draw.text((56, 30), "pydecomp", font=title, fill=FG)
    draw.text((60, 102), "static python deobfuscator and decompiler", font=tagline, fill=DIM)
    draw.text((56, 142), "Deobfuscate anything. Prove what you recovered.",
              font=claim, fill=GREEN)
    draw.text((56, 182),
              "PyArmor 8/9 · PyInstaller · Nuitka · .pyc 1.0-3.15 · marshal · base64/zlib/XOR",
              font=tagline, fill=BLUE)

    draw.rounded_rectangle([(44, 228), (W - 44, H - 52)], radius=12, fill=PANEL,
                           outline=LINE)
    draw.text((66, 244), "python pydecomp.py worker.py", font=mono, fill=DIM)
    y = 272
    for line in lines:
        colour = FG
        if "proof" in line or line.strip().startswith(("+", "saved to")):
            colour = GREEN
        elif line.strip().startswith("▸") or line.strip().startswith("stage"):
            colour = DIM
        draw.text((66, y), line[:112], font=mono, fill=colour)
        y += 20
    draw.text((56, H - 40),
              f"no execution · no telemetry · every output carries a proof · commit {commit()}",
              font=small, fill=DIM)
    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    image.save(TARGET, "PNG", optimize=True)
    print(f"wrote {TARGET}  ({os.path.getsize(TARGET):,} B, {len(lines)} captured lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
