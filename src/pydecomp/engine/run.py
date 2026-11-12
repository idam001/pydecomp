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
    emit,
    BOLD, CYAN, GREEN, GREY, RED, WHITE,
    YELLOW, ellipsis, paint,
)
from ..terminal.locate import missing, search
from ..terminal.panel import panel
from ..triage.payload import summary as summary_intel
from ..triage.report import analyse_recovered, render_report, write_reports
from ..triage.verify import _exec_dry_run

STAMP_PREFIX = "#[ Deobfuscated by"

#: set when a run refuses to write under --strict, so the CLI can exit 3
EXIT_CODE = 0

def _payload_intel(artifact) -> dict | None:
    """Fingerprints a sealed payload still shows: names, files, literals.

    Never an attempt at recovery - the ciphertext stays ciphertext - but the
    author's own name tables survive packaging and are worth a file.
    """
    code = getattr(artifact, "payload_code", None)
    if code is None:
        return None
    try:
        from ..triage.payload import harvest
        return harvest(code) or None
    except Exception:                                # noqa: BLE001 - never fail a run
        return None

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
                reports: bool = True, verify: bool = False, yara: bool = False,
                diff: bool = False,
                dry_run: bool = False, neutralize: bool = False,
                fast: bool = False, pick: int | None = None,
                strict: bool = False, proof: bool = True,
                annotate: bool = False, pyarmor_runtime: str | None = None,
                pyarmor_key: str | None = None,
                fetch_iocs: bool = False, html_report: bool = False) -> str | None:
    """Unpack whatever this file is, save one file, print the result panel."""
    global EXIT_CODE
    EXIT_CODE = 0
    started = time.time()
    requested = str(src_path)
    # The tool does the looking.  If a file is visible anywhere the search
    # reaches, it is used - the operator is told which one and why, never told
    # to retype a command.
    choice = search(requested, pick=pick)
    if choice is None:
        lines = missing(requested, out_dir)
        emit(paint("✘", RED) + " " + paint(lines[0], RED))
        for line in lines[1:]:
            tint = CYAN if line.startswith(("give me", "searched")) else GREY
            emit(paint("  " + line, tint))
        return None
    found = choice.path
    if not choice.direct:
        emit(paint("i", CYAN, BOLD) + " " + paint("using ", GREY)
             + paint(found, CYAN) + paint("  — " + choice.reason, GREY))
        for other in choice.alternatives:
            emit(paint("    also matched: " + other, GREY))
    src_path = found
    if not os.path.isfile(src_path):
        print("   " + paint("✘", RED) + " " + paint(f"file not found: {src_path}", RED))
        return None

    name = os.path.basename(src_path)
    raw_size = os.path.getsize(src_path)
    with open(src_path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()

    # Protector context: if a pyarmor_runtime library sits beside the sample,
    # the engine uses it - the operator is never asked to go and find it.
    from ..protectors import pyarmor as _armor
    key_bytes = None
    if pyarmor_key:
        try:
            key_bytes = bytes.fromhex(pyarmor_key.strip().lower().removeprefix("0x"))
        except ValueError:
            key_bytes = pyarmor_key.encode("utf-8")[:32] or None
    _armor.set_context(src_path, pyarmor_runtime, key_bytes)
    runtime_path = _armor.context().get("runtime_path")
    if runtime_path and (pyarmor_runtime or b"pyarmor" in raw[:1 << 16].lower()):
        emit(paint("runtime   " + runtime_path + "  (used for the runtime key)", CYAN))

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

    intel = None
    body = _strip_pydecomp_preamble(artifact.text)
    original_text = body
    clean_notes: list[str] = []
    if artifact.kind in ("source", "pseudo"):
        body, clean_notes = polish_source(body, clean, fast=fast)
    # "Nothing unpacked" is only a *copy* if the polishing pass left it alone too;
    # a plain file that we did clean is a legitimately cleaned file.
    left_alone = artifact.unchanged and body.strip() == original_text.strip()
    fidelity = None
    if artifact.kind in ("source", "pseudo"):
        from ..polish.fidelity import summary as fidelity_summary, verify as verify_fidelity
        fidelity = verify_fidelity(_strip_pydecomp_preamble(artifact.text), body,
                                   notes=clean_notes)
        if artifact.stalled:
            fidelity = dict(fidelity, kept="unverified",
                            reason="payload still encrypted — the output is the loader")
        elif left_alone:
            fidelity = dict(fidelity, kept="unverified",
                            reason="nothing was unpacked — the output is the input")
        if fidelity["kept"] == "unpacked":
            body = fidelity["text"]
            clean_notes = list(clean_notes) + [fidelity["reason"]]
        # A cleaning pass is only kept when the result is still the recovered
        # program *as code*, not merely as a diff.  Proven, not assumed.
        from ..proof import tiers as _tiers
        before_tier = _tiers.grade(_strip_pydecomp_preamble(artifact.text))
        after_tier = _tiers.grade(body)
        if _tiers.TIER_RANK[after_tier] > _tiers.TIER_RANK[before_tier]:
            body = original_text
            clean_notes = [note for note in clean_notes if "rename" not in note]
            clean_notes.append(f"cleaning rolled back: {before_tier} -> {after_tier}")
        verdict_tint = {"cleaned": GREEN, "unverified": RED}.get(fidelity["kept"], YELLOW)
        emit(paint("fidelity   " + fidelity_summary(fidelity), verdict_tint))
    if neutralize:
        body, guard_notes = neutralize_source(body)
        clean_notes = list(clean_notes) + guard_notes

    if fetch_iocs:
        # Opt-in, and only when the loader left its payload on a URL.  Fetching
        # is not executing: the bytes come back and are unpacked statically.
        from .. import fetch as fetch_mod
        from ..engine.dig import dig as _dig
        results = fetch_mod.run(body)
        emit(paint("fetch      " + fetch_mod.summary(results), CYAN))
        for item in results:
            trace.append("fetched " + item.line())
            if not item.ok:
                continue
            deeper = _dig(item.body, "fetched-from-url")
            if deeper.kind in ("source", "pseudo") and not deeper.stalled:
                emit(paint("           " + item.url + " opened into "
                           + f"{len(deeper.text):,} chars of source", GREEN))
                body = deeper.text
                trace.extend("fetched: " + line for line in deeper.trace[:4])
                break

    report = analyse_recovered(body, trace, raw=raw)
    if artifact.stalled:
        report["recovered"] = {
            "complete": False,
            "reason": ("the payload is sealed: this is the packer's loader, "
                       "not the program it would run"),
            "encrypted_blobs": artifact.encrypted_blobs,
            "encrypted_bytes": artifact.encrypted_bytes,
        }
        emit(paint("payload      still encrypted  " + str(artifact.encrypted_blobs)
                   + f" blob(s), {artifact.encrypted_bytes:,} B — "
                   + "lifted the loader, not the script", RED, BOLD))
        intel = _payload_intel(artifact)
        if intel:
            report["intel"] = summary_intel(intel)
            if intel.get("sealed"):
                report["sealed"] = [entry["kind"] for entry in intel["sealed"]]
            emit(paint("intel        " + summary_intel(intel)
                       + "  (structure the packer left behind)", CYAN))
    if fidelity is not None:
        report["fidelity"] = {key: fidelity[key] for key in ("kept", "reason")} | {
            "before": fidelity["before"], "after": fidelity["after"]}
    rule_text = None
    if yara:
        try:
            import datetime as _dt
            from ..triage.yara import build_rule
            from ..triage.yara_check import summary as yara_summary, validate
            rule_text = build_rule(name, report, digest=digest,
                                   date=_dt.date.today().isoformat()) or None
            if rule_text:
                verdict = validate(rule_text, body.encode("utf-8", "surrogateescape"))
                report["yara"] = True
                report["yara_check"] = {key: value for key, value in verdict.items()}
                emit(paint("rule       " + yara_summary(verdict),
                           GREEN if verdict["ok"] else YELLOW))
            else:
                emit(paint("rule       not written: no shippable indicator", GREY))
        except Exception:                                # noqa: BLE001
            rule_text = None
    coverage = None
    if diff:
        from ..triage.coverage import compare, render_markdown as render_cov, summary as cov_summary
        coverage = compare(_strip_pydecomp_preamble(artifact.text), body)
        report["coverage"] = {key: value for key, value in coverage.items()
                              if key != "definitions"}
        emit(paint("coverage   " + cov_summary(coverage), CYAN))
        for line in render_cov(name, coverage).splitlines()[2:12]:
            if line.strip():
                emit(paint(line, GREY))
    # ---- proof of what was recovered -------------------------------------
    from ..lift.module import _last_module_version
    from ..proof import build as build_proof, prefix_for, write as write_proof
    from ..proof import failure as proof_failure
    proof_obj = build_proof(
        body, name=name, digest=digest, size=raw_size, kind=artifact.kind,
        trace=trace, reports=report, notes=clean_notes,
        version=_last_module_version, identity=left_alone)
    proof_obj.input_path = os.path.abspath(src_path)
    if annotate:
        mark = prefix_for(proof_obj)
        if mark and not body.startswith(mark):
            body = mark + body
    if strict:
        why = proof_failure(proof_obj)
        if why:
            counts = proof_obj.counts
            emit(paint("✘ " + why, RED, BOLD))
            emit(paint("  " + f"{counts['semantic']} proven · "
                             f"{counts['structural']} structural · "
                             f"{counts['syntactic']} syntactic · "
                             f"{counts['unverified']} unverified", GREY))
            emit(paint("  this run did not prove the output, so no file was written",
                       GREY))
            EXIT_CODE = 3
            return None
    tier_tint = {"semantic": GREEN, "structural": CYAN}.get(proof_obj.worst, YELLOW)
    emit(paint("proof      " + proof_obj.summary(), tier_tint))

    head = render_report(report, trace, name, raw_size, digest)
    text = "\n".join(head) + "\n\n" + body

    suffix = "loader" if artifact.stalled else ("copy" if left_alone else "deob")
    path = save(text, src_path, out_dir, suffix=suffix)
    intel_path = None
    if intel:
        try:
            from ..triage.payload import render as render_intel
            intel_path = os.path.join(os.path.dirname(os.path.abspath(path)),
                                      os.path.splitext(os.path.basename(path))[0]
                                      + "_intel.txt")
            with open(intel_path, "w", encoding="utf-8") as handle:
                handle.write(render_intel(name, intel))
        except OSError:
            intel_path = None
    if coverage is not None:
        from ..triage.coverage import render_markdown as render_cov
        try:
            cov_path = os.path.join(os.path.dirname(os.path.abspath(path)),
                                    os.path.splitext(os.path.basename(path))[0]
                                    + ".coverage.md")
            with open(cov_path, "w", encoding="utf-8") as handle:
                handle.write(render_cov(name, coverage))
            if reports:
                report["coverage_path"] = cov_path
        except OSError:
            pass
    nbytes = len(text.encode("utf-8", "surrogateescape"))
    animate_bar("writing output", 0.4, GREEN, os.path.basename(path))
    animate_bar("verifying", 0.35, GREEN,
                f"sha256 {hashlib.sha256(text.encode('utf-8', 'surrogateescape')).hexdigest()[:16]}…")

    elapsed = time.time() - started
    side = {}
    if reports:
        side = write_reports(path, report, trace, name, raw_size, digest, elapsed,
                             notes=clean_notes)
    if proof:
        proof_obj.output = {
            "name": os.path.basename(path),
            "bytes": len(text.encode("utf-8", "surrogateescape")),
            "sha256": hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()}
        side = dict(side, **write_proof(proof_obj, path))
        if html_report:
            try:
                from ..output.html import write as write_html
                side["html"] = write_html(path, name, body, proof_obj.as_dict(), report)
            except OSError:
                pass
    if intel_path:
        side = dict(side, intel=intel_path) if side else {"intel": intel_path}
    if coverage is not None:
        cov_file = os.path.join(os.path.dirname(os.path.abspath(path)),
                                os.path.splitext(os.path.basename(path))[0]
                                + ".coverage.md")
        if os.path.exists(cov_file):
            side["coverage"] = cov_file
    if rule_text and report.get("yara"):
        try:
            yara_path = os.path.join(os.path.dirname(os.path.abspath(path)),
                                     os.path.splitext(os.path.basename(path))[0] + ".yar")
            with open(yara_path, "w", encoding="utf-8") as handle:
                handle.write(rule_text)
            side["yara"] = yara_path
        except OSError:
            pass
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
    if artifact.stalled:
        kind_label = "loader only — payload encrypted"
    elif left_alone:
        kind_label = "copy — nothing unpacked"
    elif artifact.unchanged:
        kind_label = "python source, cleaned in place"
    elapsed = time.time() - started
    print()
    rows = [
        ("source", f"{name}   {raw_size:,} bytes", WHITE),
        ("result", f"{kind_label}   {len(trace)} "
                   f"stage{'' if len(trace) == 1 else 's'}", WHITE),
        ("fingerprint", report["fingerprint"], CYAN),
        ("output", f"{os.path.basename(path)}   {nbytes:,} bytes", WHITE),
    ]
    if artifact.stalled:
        sealed_line = (f"sealed   {artifact.encrypted_blobs} blob(s)   "
                       f"{artifact.encrypted_bytes:,} bytes")
        if intel and intel.get("sealed"):
            from ..triage.sealed import summary as sealed_summary
            sealed_line += "   " + sealed_summary(intel["sealed"]).split(" — ")[-1]
        rows.append(("payload", sealed_line, RED))
    if intel:
        rows.append(("intel", summary_intel(intel), CYAN))
    rows.append(("proof", proof_obj.summary(), GREEN if proof_obj.worst == "semantic"
                 else CYAN))
    if report["iocs"]:
        rows.append(("indicators", report.get("ioc_summary", "none found"), YELLOW))
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
        names = [os.path.basename(v) for v in side.values()]
        from ..terminal.animate import width as _width
        room = max(12, _width() - 5)
        joined = ", ".join(names)
        if len(joined) > room:
            shown = names[0]
            extra = len(names) - 1
            joined = shown if not extra else f"{shown} +{extra} more"
        emit(paint("+ " + joined, GREY))
    print()
    from ..terminal.animate import width as _w
    from ..terminal.color import shorten_path
    shown_path = shorten_path(path, max(12, _w() - 11))
    emit(paint(f"cat '{shown_path}'", GREY))
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
    sheets = []
    for entry in todo[:400]:
        result = deobfuscate(entry, out_dir, **kwargs)
        if result:
            written.append(result)
            folder = os.path.dirname(os.path.abspath(result))
            stem = os.path.splitext(os.path.basename(result))[0]
            if kwargs.get("reports", True):
                sheet_path = os.path.join(folder, stem + ".iocs.md")
                if os.path.exists(sheet_path):
                    sheets.append((result, sheet_path))
    print()
    print("   " + paint(f"{len(written)} of {len(todo)} recovered", GREEN + BOLD))
    combined = _combine_sheets(written, sheets)
    if combined:
        print("   " + paint(f"+ {os.path.basename(combined)}", GREY))
    return written


def _combine_sheets(written: list, sheets: list) -> str | None:
    """One indicator sheet for a whole folder, merged per type."""
    import json
    merged: dict[str, set] = {}
    per_file: list[tuple[str, dict]] = []
    for result, _path in sheets:
        folder = os.path.dirname(os.path.abspath(result))
        stem = os.path.splitext(os.path.basename(result))[0]
        report_path = os.path.join(folder, stem + ".report.json")
        try:
            with open(report_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        iocs = data.get("iocs") or {}
        if not iocs:
            continue
        per_file.append((data.get("input", stem), iocs))
        for label, values in iocs.items():
            merged.setdefault(label, set()).update(values)
    if not merged or not written:
        return None
    from ..triage.iocs import render_batch_sheet
    folder = os.path.dirname(os.path.abspath(written[0]))
    path = os.path.join(folder, "iocs-all.md")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_batch_sheet(per_file, merged))
    except OSError:
        return None
    return path
