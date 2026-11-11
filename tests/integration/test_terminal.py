"""Gate: the interface fits the terminal it is drawn in — phones included.

The layout used to assume 52 columns minimum, which is wider than a Termux
window; every panel then wrapped and the borders looked broken.  This gate
renders the real banner, menu and result panel at phone, tablet and desktop
widths and refuses ragged boxes.
"""
import io
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.terminal import banner, color, menu, panel  # noqa: E402

FAILED = []
WIDTHS = (34, 40, 47, 52, 60, 72, 80, 96, 130)


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def render(cols, *calls):
    os.environ["COLUMNS"] = str(cols)
    color.USE_COLOR = True                     # worst case: escape codes present
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        for call in calls:
            call()
    return buffer.getvalue().split("\n")


def boxes(lines):
    found, current = [], []
    for line in lines:
        text = line.rstrip()
        if "╭" in text:
            current = [text]
        elif current:
            current.append(text)
            if "╰" in text:
                found.append(current)
                current = []
    return found


def result_panel():
    panel.panel("DONE", [
        ("source", "KAMRUL~4.py   9,151 bytes", color.WHITE),
        ("result", "python source   1 stage", color.WHITE),
        ("saved to", "/data/data/com.termux/files/home/out/KAMRUL~4_deob.py", color.WHITE),
        ("elapsed", "0.39s", color.WHITE),
    ])


def main():
    # 1. nothing may ever be drawn wider than the terminal
    for cols in WIDTHS:
        lines = render(cols, lambda c=cols: banner._print_common("x"), menu.menu, result_panel)
        over = [(color.vlen(line), color.ANSI_RE.sub("", line))
                for line in lines if color.vlen(line) > cols]
        ok(not over, f"{cols} columns: {len(over)} line(s) overflow"
                     + (f" — e.g. {over[0][1][:40]!r}" if over else ""))

    # 2. every box must have a straight right edge
    for cols in WIDTHS:
        for index, box in enumerate(boxes(render(cols, menu.menu, result_panel))):
            widths = {color.vlen(line) for line in box}
            ok(len(widths) == 1, f"{cols} columns: box {index} is ragged ({sorted(widths)})")
            def edge(line: str) -> str:
                return color.ANSI_RE.sub("", line).rstrip()

            ok(all(edge(line).endswith(("│", "╮", "╯")) for line in box),
               f"{cols} columns: box {index} has a broken edge")

    # 3. the menu still says what it offers at every width
    for cols in WIDTHS:
        text = "\n".join(render(cols, menu.menu))
        for token in ("MAIN MENU", "[1]", "[2]", "[3]", "[0]", "Exit"):
            ok(token in text, f"{cols} columns: menu is missing {token}")

    # 4. a phone-width run end to end, with a name that has a tilde in it
    work = tempfile.mkdtemp()
    sample = os.path.join(work, "KAMRUL~4.py")
    with open(sample, "w") as handle:
        handle.write("import base64\nprint(base64.b64decode('aGk=').decode())\n")
    bundle = os.path.join(ROOT, "dist", "pydecomp.py")
    out = os.path.join(work, "out")
    run = subprocess.run([sys.executable, bundle, sample, "-o", out, "--no-color",
                          "--no-anim"], capture_output=True, text=True,
                         env={**os.environ, "COLUMNS": "47", "NO_COLOR": "1"})
    ok(run.returncode == 0, "a 47-column run succeeds")
    wide = [line for line in run.stdout.split("\n") if color.vlen(line) > 47]
    ok(not wide, f"47-column run: {len(wide)} line(s) wider than the terminal")
    ok(os.path.isdir(out) and any(n.endswith("_deob.py") for n in os.listdir(out)),
       "47-column run still writes the recovered file")

    # 5. a missing file is explained, not just refused
    ghost = subprocess.run([sys.executable, bundle, "NOTHERE.py", "--no-color",
                            "--no-anim"], capture_output=True, text=True, cwd=work,
                           env={**os.environ, "COLUMNS": "47", "NO_COLOR": "1"})
    ok("file not found" in ghost.stdout, "a missing file is named")
    ok("looked in" in ghost.stdout, "the current directory is named")
    ok("ls " in ghost.stdout or "did you mean" in ghost.stdout,
       "the operator is told what to do next")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print(f"\nall {len(WIDTHS)} widths clean — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
