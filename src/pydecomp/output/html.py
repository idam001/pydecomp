"""pydecomp - html.

One self-contained file per recovery: the source, the proof table, the
indicators, and the guarantee.  No CDN, no fonts, no scripts, no network - it
opens on a phone with no signal and looks the same.

    pydecomp sample.py -o out --html
"""
from __future__ import annotations

import html
import os

STYLE = """
:root{--bg:#0d1117;--fg:#e6edf3;--dim:#8b949e;--line:#30363d;--ok:#3fb950;
--warn:#d29922;--bad:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:28px 24px 12px;border-bottom:1px solid var(--line)}
h1{margin:0 0 6px;font-size:21px;letter-spacing:-.2px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
margin:26px 0 10px}
.wrap{max-width:1100px;margin:0 auto;padding:0 24px 60px}
.stamp{color:var(--dim);font-size:13px}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;
border:1px solid var(--line);margin-right:6px}
.ok{color:var(--ok);border-color:var(--ok)}.warn{color:var(--warn);border-color:var(--warn)}
.bad{color:var(--bad);border-color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.06em}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:#161b22;border:1px solid var(--line);border-radius:8px;padding:16px;
overflow:auto;font-size:13px;line-height:1.5}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:#161b22}
.card b{display:block;color:var(--dim);font-size:11.5px;text-transform:uppercase;
letter-spacing:.07em;margin-bottom:4px;font-weight:600}
footer{color:var(--dim);font-size:12.5px;border-top:1px solid var(--line);
padding-top:14px;margin-top:34px}
"""


def _tier_class(tier: str) -> str:
    return {"semantic": "ok", "structural": "warn", "syntactic": "warn",
            "unverified": "bad"}.get(tier, "")


def _rows(items: list) -> str:
    return "".join(
        f"<tr><td><code>{html.escape(str(item.get('depth')))}</code></td>"
        f"<td>{html.escape(str(item.get('transform')))}</td>"
        f"<td><code>{html.escape(str(item.get('backend') or '-'))}</code></td>"
        f"<td>{html.escape(str(item.get('target') or ''))}</td>"
        f"<td>{'✓' if item.get('verified') else '·'}</td></tr>" for item in items)


def render(name: str, source: str, proof: dict, report: dict | None = None,
           captured: str = "") -> str:
    """The whole report as one HTML document."""
    tiers = proof.get("tiers") or {}
    counts = {key: len(value) for key, value in tiers.items()}
    total = sum(counts.values()) or 1
    proven = counts.get("semantic", 0)
    worst = next((key for key in ("unverified", "syntactic", "structural", "semantic")
                  if counts.get(key)), "unverified")
    input_info = proof.get("input") or {}
    iocs = (report or {}).get("iocs") or {}
    ioc_rows = "".join(
        f"<tr><td>{html.escape(kind)}</td><td><code>{html.escape(str(value))}</code></td></tr>"
        for kind, values in iocs.items() for value in list(values)[:12])
    layers = _rows(proof.get("layers") or [])
    inferred = "".join(
        f"<li>{html.escape(str(item.get('region')))} - {html.escape(str(item.get('reason')))}"
        f" <span class='stamp'>(confidence {item.get('confidence')})</span></li>"
        for item in (proof.get("inferred") or [])[:20])
    lost = "".join(f"<li>{html.escape(str(item))}</li>"
                   for item in (proof.get("lost") or []))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pydecomp · {html.escape(name)}</title><style>{STYLE}</style></head>
<body>
<header><h1>pydecomp · {html.escape(name)}</h1>
<div class="stamp">{html.escape(str(proof.get('tool', '')))} ·
sha256 <code>{html.escape(str(input_info.get('sha256', ''))[:32])}…</code> ·
{input_info.get('bytes', 0):,} B in · {len(source):,} chars out</div></header>
<div class="wrap">
<h2>verdict</h2>
<div class="grid">
 <div class="card"><b>tier</b><span class="pill {_tier_class(worst)}">{worst}</span></div>
 <div class="card"><b>proven</b>{proven}/{total} units ({100 * proven // total}%)</div>
 <div class="card"><b>layers</b>{len(proof.get('layers') or [])} transformations</div>
 <div class="card"><b>guarantee</b>{html.escape(str(proof.get('guarantee', '')))}</div>
</div>
<h2>layers</h2>
<table><thead><tr><th>#</th><th>transformation</th><th>backend</th><th>target</th>
<th>verified</th></tr></thead><tbody>{layers}</tbody></table>
<h2>units</h2>
<table><thead><tr><th>tier</th><th>count</th><th>names</th></tr></thead><tbody>
{''.join(f"<tr><td>{key}</td><td>{counts.get(key, 0)}</td><td><code>"
         + html.escape(', '.join(tiers.get(key, [])[:22])) + "</code></td></tr>"
         for key in ('semantic', 'structural', 'syntactic', 'unverified'))}
</tbody></table>
<h2>recovered source</h2>
<pre>{html.escape(source[:400000])}</pre>
{f"<h2>indicators</h2><table><thead><tr><th>kind</th><th>value</th></tr></thead>"
 f"<tbody>{ioc_rows}</tbody></table>" if ioc_rows else ""}
{f"<h2>inferred</h2><ul>{inferred}</ul>" if inferred else ""}
{f"<h2>lost</h2><ul>{lost}</ul>" if lost else ""}
{f"<h2>captured run</h2><pre>{html.escape(captured[:20000])}</pre>" if captured else ""}
<footer>Generated by pydecomp. Nothing in this report was produced by executing
the sample; open it offline, it needs no network.<br>
{html.escape(str(proof.get('guarantee', '')))}</footer>
</div></body></html>
"""


def write(path: str, *args, **kwargs) -> str:
    """Write the report next to *path* and return the file it wrote."""
    folder = os.path.dirname(os.path.abspath(path))
    stem = os.path.splitext(os.path.basename(path))[0]
    target = os.path.join(folder, stem + ".report.html")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(render(*args, **kwargs))
    return target
