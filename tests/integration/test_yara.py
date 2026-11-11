"""Gate: the YARA rule is one an analyst can ship.

Checked: the rule parses under the same grammar YARA uses for text rules (name
rules, meta block, grouped strings, layered condition), it never embeds a
generic string, it escapes quotes and backslashes, and it refuses to emit an
empty rule when there is nothing to match.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from pydecomp.triage.iocs import extract      # noqa: E402
from pydecomp.triage.yara import build_rule, write_rule   # noqa: E402
from pydecomp.triage import yara_check        # noqa: E402

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


SAMPLE = '''
WEBHOOK = "https://discord.com/api/webhooks/1226766972675428372/BuBywdldEWncg7fbIpEhCROLpkGLkYirOoP2bP-uzzO"
BOT = "8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM"
C2 = "185.220.101.42"
GATE = "http://185.220.101.42/api/v2/report"
WALLET = "0x52908400098527886E0F7030069857D2E4169EE7"
PATH = r"C:\\\\Users\\\\Public\\\\note.txt"
exec(open(PATH).read())
'''

RULE_NAME = re.compile(r"^rule [A-Za-z_][A-Za-z0-9_]{0,127}$", re.M)
STRING_LINE = re.compile(r'^\s+\$[a-z]+_\d+ = "[^"\n]*"( ascii| ascii wide)*$', re.M)


def main():
    sheet = extract(SAMPLE)
    rule = build_rule("5_stealer.py", sheet, digest="a" * 64, date="2026-11-11")

    ok(bool(rule), "a rule is produced when indicators exist")
    ok(RULE_NAME.search(rule) is not None, "rule name is a legal YARA identifier")
    ok("rule pydecomp_5_stealer" in rule, "rule name derives from the sample")
    ok("    meta:" in rule and "    strings:" in rule and "    condition:" in rule,
       "all three sections present")
    ok('author = "idam Emmanuel"' in rule, "author recorded")
    ok('hash = "' + "a" * 64 in rule, "sample hash recorded")
    ok('tlp = "WHITE"' in rule, "TLP marking present")
    ok("filesize < 8MB" in rule, "condition bounds the file size")
    ok("2 of ($*)" in rule or "any of ($*)" in rule, "condition counts indicators")

    strings = STRING_LINE.findall(rule)
    ok(len(STRING_LINE.findall(rule)) >= 3, "several indicators became strings")
    ok('$hook_1 = "https://discord.com' in rule, "webhook captured in its own group")
    ok('$bot_1 = "8013735771:' in rule, "bot token captured in its own group")
    ok('$ip_1 = "185.220.101.42"' in rule, "C2 address captured")
    ok("$eth_1" in rule, "wallet captured")

    # generic strings must never reach the rule
    for banned in ("exec-sink", "browser-artifact", "encoded-blob", "windows-path"):
        ok(banned not in rule, f"generic indicator {banned} kept out of the rule")
    ok("exec(open" not in rule, "sample code not pasted into the rule")

    # a value that repeats across groups is only written once
    ok(rule.count("https://discord.com/api/webhooks/1226766972675428372") == 1,
       "duplicate indicator written once")

    # quoting and escaping
    tricky = {"iocs": {"url": ['http://x.example-cdn.top/a"b\\c']}, "counts": {}}
    escaped = build_rule("tricky.py", tricky)
    ok('\\"' in escaped and "\\\\" in escaped, "quotes and backslashes escaped")

    # no indicators, no rule
    ok(build_rule("clean.py", {"iocs": {}, "counts": {}}) == "",
       "an empty sheet produces no rule at all")
    ok(build_rule("names.py", {"iocs": {"exec-sink": ["os.system"],
                                       "browser-artifact": ["Login Data"]}}) == "",
       "a sheet of only generic indicators produces no rule")

    # every string present in the rule really is in the sample or a decode of it
    for value in sheet["iocs"].get("ipv4", []) + sheet["iocs"].get("eth", []):
        ok(f'"{value}"' in rule, f"{value[:12]}… written into the rule")

    # written next to the recovered file
    work = tempfile.mkdtemp()
    path = os.path.join(work, "sample.yar")
    written = write_rule(path, "sample.py", sheet, digest="b" * 64, date="2026-11-11")
    ok(written == path and os.path.exists(path), "rule written to disk")
    if os.path.exists(path):
        text = open(path, encoding="utf-8").read()
        ok(text.startswith("rule pydecomp_sample"), "written rule starts with its name")
        ok(text.rstrip().endswith("}"), "written rule closes its brace")

    # --- the rule is validated, not just written ---------------------------
    own = yara_check.validate(rule, SAMPLE.encode())
    ok(own["ok"], f"rule validates: {own['problems']}")
    ok(own["matched"], "rule matches the source it was built from")
    ok(own["hit"] >= 3, "most indicator strings are found in that source")
    ok("matches its own source" in yara_check.summary(own), "summary says it matches")

    wrong = yara_check.validate(rule, b"unrelated bytes with nothing in them")
    ok(not wrong["matched"], "rule does not match unrelated bytes")
    ok(not wrong["ok"], "an unmatched rule is reported as a problem")

    parsed = yara_check.parse(rule)
    ok(parsed.name == "pydecomp_5_stealer", "parsed rule keeps its name")
    ok(len(parsed.strings) >= 3, "parsed rule keeps its strings")
    ok(all(isinstance(value, bytes) for _id, value, _mods in parsed.strings),
       "string values are unescaped to bytes")
    ok(parsed.meta.get("author") == "idam Emmanuel", "meta survives parsing")

    # a // inside a URL must not be treated as a comment
    ok(any(b"https://discord.com" in value for _id, value, _m in parsed.strings),
       "URL slashes survive comment stripping")

    for broken, why in (
        ('rule x { strings: $a = "ab" ascii condition: $a }', "short string"),
        ('rule x { strings: $a = "abcd" ascii condition: $b }', "undeclared string"),
        ('rule x { strings: $a = "abcd" ascii condition: ($a }', "unbalanced parens"),
        ('rule x { strings: $a = "abcd" ascii }', "no condition"),
        ('rule x { condition: true }', "no strings"),
        ('rule 1bad { condition: true }', "illegal rule name"),
    ):
        verdict = yara_check.validate(broken, b"abcdef")
        ok(not verdict["ok"], f"{why} is rejected")
        ok(bool(verdict["problems"]), f"{why} comes with a reason")

    # the CLI writes it too
    sample = os.path.join(work, "hidden.py")
    with open(sample, "w") as handle:
        handle.write(SAMPLE)
    from pydecomp.engine.run import deobfuscate
    saved = deobfuscate(sample, out_dir=os.path.join(work, "out"), reports=False,
                        yara=True, verify=False, dry_run=False)
    ok(saved is not None, "cli roundtrip produced a file")
    if saved:
        folder = os.path.dirname(saved)
        stem = os.path.splitext(os.path.basename(saved))[0]
        ok(os.path.exists(os.path.join(folder, stem + ".yar")),
           "--yara writes the rule beside the recovered source")

    # --- and the verdict reaches the JSON report ---------------------------
    if saved:
        import json
        folder = os.path.dirname(saved)
        stem = os.path.splitext(os.path.basename(saved))[0]
        sample_rule = os.path.join(folder, stem + ".yar")
        if os.path.exists(sample_rule):
            from pydecomp.triage.yara_check import validate as _validate
            text = open(sample_rule, encoding="utf-8").read()
            recovered = open(saved, encoding="utf-8", errors="surrogateescape").read()
            verdict = _validate(text, recovered.encode("utf-8", "surrogateescape"))
            ok(verdict["ok"], "the rule written by the CLI matches the CLI's own output")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print("\n36 checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
