"""pydecomp - report."""
from __future__ import annotations

import json
import os

from ..limits import __version__
from ..polish.demangle import _ast
from ..terminal.color import ellipsis
from ..triage.behavior import _RISKY
from ..triage.fingerprint import _fingerprint
from ..triage.iocs import extract, render_markdown, summary
from ..triage.pyarmor import pyarmor_note

def analyse_recovered(source: str, trace: list | None = None,
                      raw: bytes | None = None) -> dict:
    """Everything a human wants to know before reading the code (items 22-24)."""
    trace = trace or []
    report = {"fingerprint": _fingerprint(source, trace), "imports": [],
              "pyarmor": pyarmor_note(source),
              "execs": [], "sys_modules": [], "iocs": {}, "risks": {},
              "ioc_counts": {}, "ioc_where": {}, "ioc_summary": "none found",
              "defines": 0, "statements": 0}
    sheet = extract(source, raw)
    report["iocs"] = sheet["iocs"]
    report["ioc_counts"] = sheet["counts"]
    report["ioc_where"] = sheet["where"]
    report["ioc_defanged"] = sheet["defanged"]
    report["ioc_summary"] = summary(sheet["iocs"])
    for label, pattern in _RISKY.items():
        hits = sorted({m.group(0) for m in pattern.finditer(source)})[:12]
        if hits:
            report["risks"][label] = hits
    try:
        tree = _ast.parse(source)
    except (SyntaxError, ValueError):
        tree = None
    if tree is not None:
        imports = set()
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, _ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                   _ast.ClassDef)):
                report["defines"] += 1
            elif isinstance(node, _ast.stmt):
                report["statements"] += 1
            elif isinstance(node, _ast.Call):
                name = ""
                try:
                    name = _ast.unparse(node.func)
                except Exception:                    # noqa: BLE001
                    continue
                if name in ("exec", "eval", "__import__('builtins').exec"):
                    snippet = ""
                    if node.args:
                        try:
                            snippet = ellipsis(_ast.unparse(node.args[0]), 90)
                        except Exception:            # noqa: BLE001
                            snippet = "?"
                    report["execs"].append(f"{name}({snippet}…)")
                if "sys.modules" in name:
                    report["sys_modules"].append(ellipsis(name, 120))
        report["imports"] = sorted(imports)
    return report

def render_report(report: dict, trace: list, name: str, size: int,
                  digest: str) -> list[str]:
    """The line that goes above a recovered file — and nothing else.

    Everything this header used to carry (hash, fingerprint, peeled layers,
    imports, behaviour, indicators) is still collected: it now goes to the
    ``--reports`` JSON/Markdown and to the console panel, so the recovered file
    reads like source instead of a lab report.
    """
    from ..terminal.banner import stamp
    return [stamp()]

def write_reports(path: str, report: dict, trace: list, name: str, size: int,
                  digest: str, elapsed: float, notes: list | None = None) -> dict:
    """Side files: JSON, markdown, IOCs, raw artifacts (items 26, 27)."""
    folder = os.path.dirname(os.path.abspath(path))
    stem = os.path.splitext(os.path.basename(path))[0]
    written = {}
    payload = {
        "tool": f"pydecomp {__version__}",
        "input": name,
        "input_bytes": size,
        "sha256": digest,
        "output": os.path.basename(path),
        "elapsed_s": round(elapsed, 3),
        "fingerprint": report.get("fingerprint"),
        "trace": trace,
        "imports": report.get("imports", []),
        "execs": report.get("execs", []),
        "sys_modules": report.get("sys_modules", []),
        "iocs": report.get("iocs", {}),
        "ioc_counts": report.get("ioc_counts", {}),
        "ioc_where": report.get("ioc_where", {}),
        "behavior": report.get("risks", {}),
        "statements": report.get("statements", 0),
        "readme": list(notes or []),
    }
    try:
        json_path = os.path.join(folder, stem + ".report.json")
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        written["json"] = json_path
    except Exception:                                # noqa: BLE001
        pass
    try:
        sheet = {"iocs": report.get("iocs", {}), "counts": report.get("ioc_counts", {})}
        ioc_path = os.path.join(folder, stem + ".iocs.md")
        with open(ioc_path, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(name, sheet, digest))
        written["iocs"] = ioc_path
    except Exception:                                # noqa: BLE001
        pass
    try:
        md = [f"# pydecomp report — `{name}`", "",
              f"- **input**: {name} ({size:,} bytes)",
              f"- **sha256**: `{digest}`",
              f"- **fingerprint**: {report.get('fingerprint')}",
              f"- **unpacked in** {payload['elapsed_s']}s", "",
              "## Layers", ""]
        md += [f"{i}. {line}" for i, line in enumerate(trace, 1)] or ["- none recorded"]
        md += ["", "## Indicators", ""]
        if report.get("iocs"):
            for label, values in report["iocs"].items():
                md.append(f"**{label}**")
                md += [f"- `{value}`" for value in values[:40]]
                md.append("")
        else:
            md.append("- none found\n")
        md += ["## Behaviour", ""]
        if report.get("risks"):
            for label, hits in report["risks"].items():
                md.append(f"- **{label}**: {', '.join(hits[:8])}")
        else:
            md.append("- nothing flagged\n")
        md += ["", "## Imports", "", ", ".join(report.get("imports", [])) or "none", ""]
        md_path = os.path.join(folder, stem + ".report.md")
        with open(md_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(md))
        written["md"] = md_path
    except Exception:                                # noqa: BLE001
        pass
    return written
