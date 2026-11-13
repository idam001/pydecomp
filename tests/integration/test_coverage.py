"""Gate: `--diff` proves what the cleaning kept, end to end through the CLI."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


SAMPLE = '''import base64
import os

TOKEN = "not-a-real-token"
LIMIT = 4

def _d(value):
    return base64.b64decode(value).decode()

def collect(items):
    total = 0
    for item in items:
        total += item * 2
    return total

def beacon():
    return _d("aHR0cDovL2V4YW1wbGUuaW52YWxpZA==")

class Box:
    def size(self):
        return LIMIT

if __name__ == "__main__":
    print(beacon(), collect([1, 2, 3]))
'''


def main():
    work = tempfile.mkdtemp()
    sample = os.path.join(work, "diffme.py")
    with open(sample, "w") as handle:
        handle.write(SAMPLE)
    out = os.path.join(work, "out")
    from pydecomp.engine.run import deobfuscate
    saved = deobfuscate(sample, out_dir=out, reports=True, diff=True,
                        verify=False, dry_run=False)
    ok(saved is not None, "run completed")
    if not saved:
        print("\n1 failed")
        return 1
    folder = os.path.dirname(saved)
    stem = os.path.splitext(os.path.basename(saved))[0]

    coverage_path = os.path.join(folder, stem + ".coverage.md")
    ok(os.path.exists(coverage_path), "--diff writes a coverage report")
    if os.path.exists(coverage_path):
        text = open(coverage_path, encoding="utf-8").read()
        ok(text.startswith("# Coverage — `diffme.py`"), "coverage report is titled")
        ok("verdict" in text, "verdict present")
        for name in ("collect", "beacon", "Box", "_d"):
            ok(f"`{name}`" in text, f"{name} listed in the coverage table")
        ok("kept" in text, "definitions are marked kept")

    report_path = os.path.join(folder, stem + ".report.json")
    ok(os.path.exists(report_path), "report written alongside")
    if os.path.exists(report_path):
        data = json.load(open(report_path, encoding="utf-8"))
        coverage = data.get("coverage") or {}
        ok(coverage.get("verdict") in ("complete", "mostly complete"),
           f"verdict recorded in the JSON: {coverage.get('verdict')}")
        ok(coverage.get("lost") == 0, "nothing was lost")
        ok(coverage.get("strings_kept", 0) >= 2, "string literals accounted for")
        ok(coverage.get("strings_folded", 0) >= 1,
           "the folded literal is counted, not silently dropped")

    # the recovered file still holds every definition the original had
    recovered = open(saved, encoding="utf-8", errors="surrogateescape").read()
    for name in ("collect", "beacon", "Box"):
        ok(f"def {name}" in recovered or f"class {name}" in recovered,
           f"{name} survived into the recovered source")

    # a sample that loses a definition is reported as incomplete
    from pydecomp.triage.coverage import compare
    reduced = SAMPLE.replace('''def beacon():
    return _d("aHR0cDovL2V4YW1wbGUuaW52YWxpZA==")
''', "")
    verdict = compare(SAMPLE, reduced)
    ok(verdict["verdict"] != "complete", "a lost definition downgrades the verdict")
    ok(verdict["definitions"]["beacon"]["status"] == "missing", "the lost def is named")

    # ------------------------------------------------------------------
    # suspicion: a definition that survived but does not look like itself
    # ------------------------------------------------------------------
    from pydecomp.triage.coverage import render_markdown, summary

    intact = compare(SAMPLE, SAMPLE)
    ok(intact["verdict"] == "complete", "an unchanged file is complete")
    ok(intact["suspicions"] == 0, "an unchanged file raises no suspicion")

    # the historical bug in docs/UPGRADES.md: a mutable literal propagated into
    # the return, so the function keeps its shape and stops returning its work
    original = ("def report(items):\n"
                "    results = []\n"
                "    for item in items:\n"
                "        results.append(item * 2)\n"
                "    return results\n")
    broken = ("def report(items):\n"
              "    for item in items:\n"
              "        [].append(item * 2)\n"
              "    return []\n")
    caught = compare(original, broken)
    ok(caught["verdict"] == "suspicious",
       f"a body that stopped returning its own names is suspicious: {caught['verdict']}")
    ok(caught["lost"] == 0 and caught["emptied"] == 0,
       "it is reported as suspicious, not as lost - the definition is still there")
    kinds = [item["kind"] for item in caught["suspicious"]]
    ok("mutates a literal" in kinds, f"the reason is named: {kinds}")
    report_md = render_markdown("broken.py", caught)
    ok("Suspicious" in report_md and "mutates a literal" in report_md,
       "the markdown report says why")
    ok("suspicious" in summary(caught), "the one-line summary carries the suspicion")

    # a decoder folded into a literal is legitimate and must stay quiet
    folded = ("def beacon():\n"
              "    return _d('aHR0cDovL2V4YW1wbGUuaW52YWxpZA==')\n")
    inlined = ("def beacon():\n"
               "    return 'http://example.invalid'\n")
    ok(compare(folded, inlined)["verdict"] == "complete",
       "folding a call into its literal is not suspicious")

    # a body that lost more than half its statements is reported the same way
    halved = ("def walk(items):\n"
              "    total = 0\n"
              "    for item in items:\n"
              "        total += item\n"
              "        total += 0\n"
              "        total *= 1\n"
              "    return total\n")
    slimmed = ("def walk(items):\n"
               "    return sum(items)\n")
    shrunk = compare(halved, slimmed)
    ok(shrunk["verdict"] == "suspicious", "a body more than halved is suspicious")
    ok(any(item["kind"] == "body more than halved"
           for item in shrunk["suspicious"]), "the halving is named")

    # and the signal has to stay quiet on healthy output, or it is noise
    import pathlib as _pathlib
    root = _pathlib.Path(__file__).resolve().parents[2]
    payloads = sorted((root / "corpus").glob("*/*/payload.py"))
    ok(len(payloads) >= 200 and len(payloads) % 4 == 0,
       f"the corpus is on disk ({len(payloads)} payloads, four per family)")
    from pydecomp.polish.apply import polish_source
    verdicts, fired = {}, 0
    for payload in payloads:
        text = payload.read_text(encoding="utf-8", errors="surrogateescape")
        cleaned_text = polish_source(text)[0]
        result = compare(text, cleaned_text)
        verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1
        fired += result["suspicions"]
    ok(set(verdicts) == {"complete"},
       f"cleaning {len(payloads)} real payloads raises no suspicion: {verdicts}")
    ok(fired == 0, f"suspicion count across the corpus: {fired}")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print("\n33 checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
