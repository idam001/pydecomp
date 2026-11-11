"""Turn an indicator sheet into a YARA rule you can actually ship.

Rule-writing advice from the practitioners is consistent: put the strings in
named groups, keep a meta block for governance, and never let a single weak
string decide the match — layer the condition and bound the file size.  That is
what this module does with the indicators pydecomp recovered.

    rule pydecomp_sample
    {
        meta:
            author = "…"
            description = "…"
            hash = "…"
        strings:
            $hook_1 = "https://discord.com/api/webhooks/…" ascii
            $ip_1   = "185.220.101.42" ascii
            $bot_1  = "8013735771:AAF…" ascii
        condition:
            filesize < 8MB and
            2 of ($*)
    }

Indicators that are structurally generic (`exec-sink`, `windows-path`,
`encoded-blob`, `browser-artifact`) are deliberately left out: as bare strings
they match goodware by the thousand and would poison the rule.
"""
from __future__ import annotations

from ..limits import __version__

AUTHOR = "idam Emmanuel"

# label -> YARA string group prefix.  Order is the order they are written.
_GROUPS = [
    ("telegram-bot", "bot"),
    ("discord-webhook", "hook"),
    ("slack-webhook", "hook"),
    ("telegram-api", "tgapi"),
    ("url", "url"),
    ("domain", "domain"),
    ("ipv4", "ip"),
    ("email", "mail"),
    ("onion", "onion"),
    ("aws-key", "aws"),
    ("github-token", "gh"),
    ("gitlab-token", "gl"),
    ("slack-token", "slack"),
    ("stripe-key", "stripe"),
    ("google-key", "gcp"),
    ("openai-key", "oa"),
    ("jwt", "jwt"),
    ("private-key", "privkey"),
    ("btc", "btc"),
    ("eth", "eth"),
    ("xmr", "xmr"),
]

_SKIPPED = {"exec-sink", "browser-artifact", "windows-path", "encoded-blob",
            "secret-literal", "telegram-chat", "ipv6", "ftp", "db-uri"}

_MAX_STRINGS = 40


def _rule_name(name: str) -> str:
    stem = name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    cleaned = "".join(char if char.isalnum() else "_" for char in stem)
    cleaned = cleaned.strip("_") or "sample"
    # the tool prefix already guarantees a valid first character
    return "pydecomp_" + cleaned


def _escape(value: str) -> str:
    out = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 32 or ord(char) > 126:
            out.append("".join(f"\\x{byte:02x}" for byte in char.encode("utf-8")))
        else:
            out.append(char)
    return "".join(out)


def build_rule(name: str, sheet: dict, digest: str = "", date: str = "") -> str:
    """A YARA rule over the indicators we recovered, or '' when there are none."""
    iocs = sheet.get("iocs") or {}
    lines: list[str] = []
    strings: list[str] = []
    used = 0
    groups_used: set[str] = set()
    seen: set[str] = set()
    for label, prefix in _GROUPS:
        if label in _SKIPPED:
            continue
        values = iocs.get(label) or []
        position = 0
        for value in values:
            if used >= _MAX_STRINGS:
                break
            if len(value) < 6 or value in seen:
                continue
            position += 1
            modifiers = " ascii wide" if label in ("domain", "url") else " ascii"
            strings.append(f'        ${prefix}_{position} = "{_escape(value)}"{modifiers}')
            groups_used.add(prefix)
            seen.add(value)
            used += 1
    if not strings:
        return ""

    # two independent indicators when there are enough of them, otherwise any
    strict = used >= 4
    condition = "        filesize < 8MB and\n"
    if strict:
        condition += "        2 of ($*)"
    else:
        condition += "        any of ($*)"

    lines.append(f"rule {_rule_name(name)}")
    lines.append("{")
    lines.append("    meta:")
    author = AUTHOR
    lines.append(f'        author = "{_escape(author)}"')
    lines.append(f'        description = "Indicators recovered by pydecomp {__version__} — '
                 f'source reconstructed and defanged in the report"')
    lines.append(f'        tool_version = "{__version__}"')
    if digest:
        lines.append(f'        hash = "{digest}"')
    if date:
        lines.append(f'        date = "{date}"')
    lines.append('        tlp = "WHITE"')
    lines.append("")
    lines.append("    strings:")
    lines.extend(strings)
    lines.append("")
    lines.append("    condition:")
    lines.append(condition)
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_rule(path: str, name: str, sheet: dict, digest: str = "",
               date: str = "") -> str | None:
    """Write `<path>.yar` beside a recovered file.  Returns the path written."""
    text = build_rule(name, sheet, digest=digest, date=date)
    if not text:
        return None
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        return None
    return path
