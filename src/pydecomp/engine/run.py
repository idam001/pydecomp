"""pydecomp - run."""
from __future__ import annotations

import hashlib
import os
import time

from ..engine.dig import dig
from ..output.save import save
from ..polish.apply import polish_source
from ..polish.neutralize import neutralize_source
from ..terminal.animate import animate_bar, animate_text, spinner, width
from ..terminal.color import (
    BOLD, CYAN, GREEN, GREY, RED, WHITE,
    YELLOW, ellipsis, paint,
)
from ..terminal.panel import panel
from ..triage.report import analyse_recovered, render_report, write_reports
from ..triage.verify import _exec_dry_run

STAMP_PREFIX = "#[ Deobfuscated by"

def _strip_pydecomp_preamble(text: str) -> str:
    """Drop the header this tool wrote last time, keep the sample's own."""
    if text.startswith(STAMP_PREFIX):
        newline = text.find("\n")
        return text[newline + 1:].lstrip("\n")
    marker = "# pydecomp "
    if text.startswith(marker) or text.startswith("# rebuilt by pydecomp"):
        split = text.find("\n\n")
        if 0 < split < 8000:
            return text[split + 2:]
    return text

def deobfuscate(src_path: str, out_dir: str | None = None,
                clean: bool = True, keep_artifacts: bool = False,
                reports: bool = True, verify: bool = False,
                dry_run: bool = False, neutralize: bool = False) -> str | None:
    """Unpack whatever this file is, save one file, print the result panel."""
    started = time.time()
    src_path = os.path.abspath(os.path.expanduser(str(src_path).strip().strip("'\"")))
    if not os.path.isfile(src_path):
        print("   " + paint("✘", RED) + " " + paint(f"file not found: {src_path}", RED))
        return None

    name = os.path.basename(src_path)
    raw_size = os.path.getsize(src_path)
    with open(src_path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()

    animate_text(f"Decompiling {name}", 0.45)
    spinner(f"identifying {raw_size:,} bytes", 0.5)

    artifact = dig(raw, name)
    trace = list(artifact.trace)

    shown = 0
    for line in trace:
        if shown >= 7:
            break
        animate_bar(f"stage {shown + 1}", 0.42, CYAN, ellipsis(line, max(width() - 34, 20)))
        shown += 1

    body = _strip_pydecomp_preamble(artifact.text)
    clean_notes: list[str] = []
    if artifact.kind in ("source", "pseudo"):
        body, clean_notes = polish_source(body, clean)
    if neutralize:
        body, guard_notes = neutralize_source(body)
        clean_notes = list(clean_notes) + guard_notes

    report = analyse_recovered(body, trace)
    head = render_report(report, trace, name, raw_size, digest)
    text = "\n".join(head) + "\n\n" + body

    path = save(text, src_path, out_dir)
    nbytes = len(text.encode("utf-8", "surrogateescape"))
    animate_bar("writing output", 0.4, GREEN, os.path.basename(path))
    animate_bar("verifying", 0.35, GREEN,
                f"sha256 {hashlib.sha256(text.encode('utf-8', 'surrogateescape')).hexdigest()[:16]}…")

    elapsed = time.time() - started
    side = {}
    if reports:
        side = write_reports(path, report, trace, name, raw_size, digest, elapsed,
                             notes=clean_notes)
    if keep_artifacts:
        folder = os.path.dirname(os.path.abspath(path))
        stem = os.path.splitext(os.path.basename(path))[0]
        try:
            blob = raw
            with open(os.path.join(folder, stem + ".raw.bin"), "wb") as fh:
                fh.write(blob)
            side["raw"] = os.path.join(folder, stem + ".raw.bin")
        except Exception:                            # noqa: BLE001
            pass

    verdict = None
    if verify or dry_run:
        ok_run, why = _exec_dry_run(path)
        verdict = ("runs" if ok_run else "does not run", why)

    kind_label = {"source": "python source", "pseudo": "lifted from bytecode",
                  "strings": "string dump"}.get(artifact.kind, artifact.kind)
    elapsed = time.time() - started
    print()
    rows = [
        ("source", f"{name}   {raw_size:,} bytes", WHITE),
        ("result", f"{kind_label}   {len(trace)} "
                   f"stage{'' if len(trace) == 1 else 's'}", WHITE),
        ("fingerprint", report["fingerprint"], CYAN),
        ("output", f"{os.path.basename(path)}   {nbytes:,} bytes", WHITE),
    ]
    if report["iocs"]:
        counts = ", ".join(f"{label} {len(values)}"
                           for label, values in report["iocs"].items())
        rows.append(("indicators", counts, YELLOW))
    if report["risks"]:
        rows.append(("behaviour", ", ".join(report["risks"]), RED))
    if clean_notes:
        rows.append(("cleaned", "; ".join(clean_notes), GREY))
    if verdict:
        rows.append(("verify", verdict[1], GREEN if verdict[0] == "runs" else YELLOW))
    rows.append(("saved to", path, GREEN + BOLD))
    rows.append(("elapsed", f"{elapsed:.2f}s", GREY))
    panel("DONE", rows, tint=GREEN)
    if side:
        print("   " + paint("+ " + ", ".join(os.path.basename(v) for v in side.values()),
                            GREY))
    print()
    print("   " + paint(f"cat '{path}'", GREY))
    return path

def deobfuscate_tree(target: str, out_dir: str | None = None, **kwargs) -> list[str]:
    """Item 25: a folder, .zip, .whl, .tar.gz or .pyz full of samples."""
    target = os.path.abspath(os.path.expanduser(str(target).strip().strip("'\"")))
    todo: list[str] = []
    if os.path.isdir(target):
        for root, _dirs, files in os.walk(target):
            for entry in files:
                if entry.endswith((".py", ".pyc", ".pyz", ".whl", ".egg", ".zip",
                                   ".tar", ".gz", ".bz2", ".xz")):
                    todo.append(os.path.join(root, entry))
    else:
        todo = [target]
    if not todo:
        print("   " + paint("✘ no python files in that folder", RED))
        return []
    print("   " + paint(f"{len(todo)} file(s) queued", CYAN))
    written = []
    for entry in todo[:400]:
        result = deobfuscate(entry, out_dir, **kwargs)
        if result:
            written.append(result)
    print()
    print("   " + paint(f"{len(written)} of {len(todo)} recovered", GREEN + BOLD))
    return written
