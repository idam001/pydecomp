#!/usr/bin/env python3
"""Capture real runs and render them as SVG, for the README and the docs.

This is not a mock-up: each image is the stdout of `dist/pydecomp.py` on a case
built by `tests/fixtures`, with the temporary path rewritten to `~`.  The
caption records the commit and the command, so a reader can reproduce it.

    python3 tools/make_evidence.py              # write docs/assets/*.svg
    python3 tools/make_evidence.py --check      # fail if a claim no longer holds
"""
from __future__ import annotations

import argparse
import html
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(ROOT, "dist", "pydecomp.py")
ASSETS = os.path.join(ROOT, "docs", "assets")
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))
sys.path.insert(0, os.path.join(ROOT, "src"))

FONT = "ui-monospace,SFMono-Regular,Menlo,Consolas,'DejaVu Sans Mono',monospace"
LINE_H = 17
PAD = 18
BAR = 30


def commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip() or "working tree"
    except OSError:
        return "working tree"


def run(args: list[str], cwd: str, columns: int = 100) -> tuple[str, int]:
    done = subprocess.run([sys.executable, BUNDLE, *args], cwd=cwd,
                          capture_output=True, text=True, timeout=900,
                          env={**os.environ, "COLUMNS": str(columns), "NO_COLOR": "1"})
    text = done.stdout or done.stderr
    return text, done.returncode


def tidy(text: str, folder: str) -> str:
    """Absolute temp paths become ``~`` so the image is readable."""
    out = text.replace(folder.rstrip("/") + "/", "~/")
    out = out.replace(folder.rstrip("/"), "~")
    lines = []
    for line in out.splitlines():
        if line.rstrip().endswith("cat") or line.startswith("   cat '"):
            continue
        lines.append(line.rstrip())
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(_square(lines))


def _square(lines: list[str]) -> list[str]:
    """Re-align panel borders after paths were shortened, so the box is not ragged."""
    out = list(lines)
    index = 0
    while index < len(out):
        if "│" not in out[index]:
            index += 1
            continue
        start = index
        while index < len(out) and "│" in out[index]:
            index += 1
        block = out[start:index]
        target = max(len(line) for line in block)
        for offset, line in enumerate(block):
            if not line.endswith("│"):
                continue
            head = line[:-1]
            block[offset] = head + " " * max(0, target - len(line)) + "│"
        out[start:index] = block
    return out


def svg(lines: list[str], caption: str, subtitle: str) -> str:
    width = max(560, min(1600, max((len(line) for line in lines), default=80) * 8 + 2 * PAD))
    height = BAR + PAD + LINE_H * len(lines) + PAD + 34
    body = []
    for index, line in enumerate(lines):
        y = BAR + PAD + LINE_H * index + 12
        escaped = html.escape(line).replace(" ", "\u00a0")
        colour = "#c9d1d9"
        if "✘" in line or "FAIL" in line or "DRIFT" in line:
            colour = "#f85149"
        elif "proof      " in line or "ok   " in line:
            colour = "#3fb950"
        elif line.strip().startswith(("▸", "│", "╭", "╰", "+")):
            colour = "#8b949e"
        body.append(f'<text x="{PAD}" y="{y}" fill="{colour}">{escaped}</text>')
    title = html.escape(caption)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"
viewBox="0 0 {width} {height}" role="img" aria-label="{title}">
<rect width="{width}" height="{height}" rx="10" fill="#0d1117" stroke="#30363d"/>
<rect width="{width}" height="{BAR}" rx="10" fill="#161b22"/>
<rect y="{BAR - 10}" width="{width}" height="10" fill="#161b22"/>
<circle cx="18" cy="15" r="5" fill="#f85149"/><circle cx="36" cy="15" r="5" fill="#d29922"/>
<circle cx="54" cy="15" r="5" fill="#3fb950"/>
<text x="{width - PAD}" y="19" text-anchor="end" fill="#8b949e"
font-family="{FONT}" font-size="11">{html.escape(subtitle)}</text>
<g font-family="{FONT}" font-size="12.5" xml:space="preserve">
{chr(10).join(body)}
</g>
<text x="{PAD}" y="{height - 12}" fill="#6e7681" font-family="{FONT}" font-size="10.5">
captured from dist/pydecomp.py · commit {commit()} · {title}</text>
</svg>
"""


def cases(folder: str) -> list[dict]:
    import freezer_cases
    import pyarmor_case
    built = []
    case = pyarmor_case.build(os.path.join(folder, "pyarmor"))
    built.append({
        "name": "proof-pyarmor",
        "caption": "pydecomp: synthetic PyArmor-shaped fixture, static recovery + proof",
        "args": [os.path.join(folder, "pyarmor", "worker.py"), "-o",
                 os.path.join(folder, "pyarmor-out"), "--no-color", "--no-anim"],
        "claims": ["static unpack", "proof", "pyarmor_runtime"],
        "folder": folder,
        "note": case["marker"],
    })
    freezer = os.path.join(folder, "frozen.bin")
    with open(freezer, "wb") as handle:
        handle.write(freezer_cases.pyinstaller())
    built.append({
        "name": "pyinstaller",
        "caption": "pydecomp: PyInstaller CArchive → PYZ → source",
        "args": [freezer, "-o", os.path.join(folder, "frozen-out"), "--no-color",
                 "--no-anim"],
        "claims": ["pyinstaller container", "member(s) inside", "proof"],
        "folder": folder,
    })
    weak = os.path.join(folder, "opaque.bin")
    with open(weak, "wb") as handle:
        handle.write(bytes(range(256)) * 6)
    built.append({
        "name": "strict-refusal",
        "caption": "pydecomp --strict: refuses to write what it cannot prove",
        "args": [weak, "-o", os.path.join(folder, "weak-out"), "--strict",
                 "--no-color", "--no-anim"],
        "claims": ["strict:", "nothing written"],
        "folder": folder,
        "exit": 3,
    })
    return built


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="re-run and confirm the claims the images make")
    args = parser.parse_args()
    os.makedirs(ASSETS, exist_ok=True)
    folder = tempfile.mkdtemp(prefix="evidence-")
    failures = 0
    try:
        for case in cases(folder):
            text, code = run(case["args"], cwd=folder)
            body = tidy(text, folder)
            for claim in case["claims"]:
                if claim.lower() not in body.lower():
                    failures += 1
                    print(f"FAIL  {case['name']}: run does not show {claim!r}")
            if "exit" in case and code != case["exit"]:
                failures += 1
                print(f"FAIL  {case['name']}: exit {code}, expected {case['exit']}")
            if "\x1b[" in body:
                failures += 1
                print(f"FAIL  {case['name']}: ANSI escapes in a caption")
            path = os.path.join(ASSETS, case["name"] + ".svg")
            document = svg(body.splitlines(), case["caption"],
                           "python dist/pydecomp.py " + os.path.basename(
                               case["args"][0]) + " …")
            if args.check:
                if not os.path.exists(path):
                    failures += 1
                    print(f"FAIL  {case['name']}: {path} is missing")
                else:
                    # the SVG keeps spacing with non-breaking spaces
                    previous = open(path, encoding="utf-8").read().replace("\u00a0", " ")
                    if html.escape(case["caption"]) not in previous:
                        failures += 1
                        print(f"FAIL  {case['name']}: image caption is stale")
                    for claim in case["claims"]:
                        if claim.lower() not in previous.lower():
                            failures += 1
                            print(f"FAIL  {case['name']}: image does not show {claim!r}")
                continue
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(document)
            print(f"wrote {path}  ({len(document):,} B, {len(body.splitlines())} lines)")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    print()
    print("all good" if not failures else f"{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
