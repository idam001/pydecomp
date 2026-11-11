"""Validate a generated YARA rule instead of hoping it is right.

A rule is only worth shipping if it can match the thing it was written from, and
if it parses under the grammar YARA itself uses.  Rather than shell out to
`yara` (which may not be installed and may not be wanted in a static pipeline),
this module carries a small, strict parser for the subset of YARA that
`triage/yara.py` emits, plus a matcher, and reports what is wrong:

* syntax — unknown sections, malformed string lines, unbalanced condition;
* meaning — no strings, a string shorter than YARA's 4-byte minimum, a rule name
  that is not a valid identifier, a condition that references an undeclared
  string;
* reality — does the rule actually match the recovered source it was built from?

The last check is the one that catches real bugs: a rule whose strings never
appear in its own sample is either a bad indicator or a bad escaper, and either
way it is not a detection.
"""
from __future__ import annotations

import re

_RULE = re.compile(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.M)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_STRING_LINE = re.compile(
    r'^\s*(\$[a-z]+_\d+)\s*=\s*=?"((?:[^"\\]|\\.)*)"\s*((?:(?:ascii|wide|nocase|fullword)\s*)*)$')
_META_LINE = re.compile(r'^\s*([a-z_]+)\s*=\s*"((?:[^"\\]|\\.)*)"$')
_FILE_SIZE = re.compile(r"filesize\s*(<|<=|>|>=)\s*(\d+)\s*(KB|MB|GB)?", re.I)
_OF_COUNT = re.compile(r"(\d+|any|all)\s+of\s+\(\s*\$\*?\s*\)|(\d+)\s+of\s+them", re.I)


class YaraSyntaxError(ValueError):
    """The rule text is not something YARA would accept."""


def _strip_comment(line: str) -> str:
    """Drop a trailing `//` comment without touching `http://` inside a string."""
    quoted = False
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "/" and line[index:index + 2] == "//":
            return line[:index]
        index += 1
    return line


class Rule:
    def __init__(self, name: str, meta: dict, strings: list, condition: str) -> None:
        self.name = name
        self.meta = meta
        self.strings = strings          # [(identifier, value_bytes, modifiers)]
        self.condition = condition

    def __repr__(self) -> str:          # pragma: no cover - debugging aid
        return f"<Rule {self.name} {len(self.strings)} strings>"


def _unescape(text: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            out.extend(char.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(text):
            raise YaraSyntaxError("string ends in a backslash")
        escape = text[index]
        mapping = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\",
                   '"': b'"', "0": b"\x00"}
        if escape in mapping:
            out.extend(mapping[escape])
            index += 1
        elif escape == "x" and index + 2 < len(text):
            try:
                out.append(int(text[index + 1:index + 3], 16))
            except ValueError as exc:
                raise YaraSyntaxError(f"bad hex escape at {index}") from exc
            index += 3
        else:
            raise YaraSyntaxError(f"unknown escape \\{escape}")
    return bytes(out)


def parse(text: str) -> Rule:
    """Parse the YARA subset this tool writes.  Raises YaraSyntaxError."""
    match = _RULE.search(text)
    if not match:
        raise YaraSyntaxError("no `rule <name> {` found")
    name = match.group(1)
    if not _IDENT.match(name):
        raise YaraSyntaxError(f"invalid rule name {name!r}")
    body = text[match.end():]
    if "}" not in body:
        raise YaraSyntaxError("rule brace is never closed")
    body = body[:body.rfind("}")]

    meta: dict[str, str] = {}
    strings: list = []
    condition_lines: list[str] = []
    section = None
    for number, raw in enumerate(body.splitlines(), start=2):
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        lowered = line.strip().lower()
        if lowered in ("meta:", "strings:", "condition:"):
            section = lowered[:-1]
            continue
        if section is None:
            raise YaraSyntaxError(f"line {number}: text before any section")
        if section == "meta":
            found = _META_LINE.match(line)
            if not found:
                raise YaraSyntaxError(f"line {number}: malformed meta entry")
            meta[found.group(1)] = found.group(2)
        elif section == "strings":
            found = _STRING_LINE.match(line)
            if not found:
                raise YaraSyntaxError(f"line {number}: malformed string definition")
            modifiers = found.group(3).split()
            if "nocase" in modifiers and "xor" in modifiers:
                raise YaraSyntaxError(f"line {number}: conflicting modifiers")
            strings.append((found.group(1), _unescape(found.group(2)), modifiers))
        else:
            condition_lines.append(line.strip())
    if not condition_lines:
        raise YaraSyntaxError("rule has no condition")
    condition = " ".join(condition_lines)

    declared = {identifier for identifier, _value, _mods in strings}
    for identifier in re.findall(r"\$[a-z]+_\d+", condition):
        if identifier not in declared:
            raise YaraSyntaxError(f"condition references undeclared {identifier}")
    if condition.count("(") != condition.count(")"):
        raise YaraSyntaxError("unbalanced parentheses in condition")
    if strings and not re.search(r"\$(?:\w+_\d+|\*)", condition):
        raise YaraSyntaxError("condition never references a string")
    for identifier, value, _mods in strings:
        if len(value) < 4:
            raise YaraSyntaxError(
                f"{identifier} is {len(value)} byte(s); YARA needs at least 4")
    return Rule(name, meta, strings, condition)


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------
def _size_limit(condition: str) -> tuple[str, int] | None:
    found = _FILE_SIZE.search(condition)
    if not found:
        return None
    scale = {"kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3}.get(
        (found.group(3) or "").lower(), 1)
    return found.group(1), int(found.group(2)) * scale


def _hits(rule: Rule, data: bytes) -> dict[str, int]:
    counts: dict[str, int] = {}
    lowered = data.lower()
    for identifier, value, modifiers in rule.strings:
        haystacks = [data.lower()] if "nocase" in modifiers else [data]
        if "wide" in modifiers and "ascii" in modifiers:
            haystacks.append(data.decode("utf-8", "ignore").encode("utf-16-le"))
        total = 0
        for haystack in haystacks:
            total += haystack.count(value if "nocase" not in modifiers else value.lower())
        counts[identifier] = total
    return counts


def match(rule: Rule, data: bytes) -> tuple[bool, int, int]:
    """Does the rule match `data`?  Returns (matched, strings_hit, strings_total)."""
    counts = _hits(rule, data)
    hit = sum(1 for value in counts.values() if value)
    total = max(len(counts), 1)
    condition = rule.condition

    size = _size_limit(condition)
    if size is not None:
        operator, limit = size
        comparisons = {
            "<": len(data) < limit, "<=": len(data) <= limit,
            ">": len(data) > limit, ">=": len(data) >= limit,
        }
        if not comparisons.get(operator, True):
            return False, hit, total

    required = 1
    counted = _OF_COUNT.search(condition)
    if counted:
        token = (counted.group(1) or counted.group(2) or "").lower()
        if token == "any":
            required = 1
        elif token == "all":
            required = len(rule.strings)
        elif token.isdigit():
            required = int(token)
    matched = hit >= required
    if " and " in condition.lower():
        # every `and` clause we emit is a size bound plus the string count
        matched = matched and size is not None
    return matched, hit, total


def validate(text: str, sample: bytes) -> dict:
    """Parse, match, and say what is wrong in a form a caller can print."""
    problems: list[str] = []
    try:
        rule = parse(text)
    except YaraSyntaxError as exc:
        return {"ok": False, "problems": [f"parse: {exc}"], "matched": False,
                "hit": 0, "total": 0, "name": ""}
    if not rule.strings:
        problems.append("rule defines no strings")
    if not rule.meta:
        problems.append("rule has no meta block")
    matched, hit, total = match(rule, sample)
    if rule.strings and hit == 0:
        problems.append("no indicator string is present in the sample the rule was built from")
    if rule.strings and 0 < hit < total:
        problems.append(f"{total - hit} indicator string(s) are not in the recovered "
                        "source (carved from the packed bytes only)")
    if rule.strings and not matched:
        problems.append("rule does not match its own sample")
    return {"ok": not problems, "problems": problems, "matched": matched,
            "hit": hit, "total": total, "name": rule.name}


def summary(result: dict) -> str:
    if not result["name"]:
        return "rule invalid"
    verdict = "matches its own source" if result["matched"] else "does not match"
    text = f"{result['name']}: {verdict} ({result['hit']}/{result['total']} strings)"
    if result["problems"]:
        text += " · " + "; ".join(result["problems"][:2])
    return text
