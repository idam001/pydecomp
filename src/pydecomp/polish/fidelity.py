"""The last thing before a file is written: is still the recovered program?

Cleaning passes exist to make recovered code readable.  None of them is allowed
to make it *wrong*, and none of them is allowed to trade a program for junk.  So
the cleaned text is compared against the program as it came out of the
container, and the cleaned text is only kept when it is genuinely better:

* if cleaning produced something that does not parse, the unpacked original is
  written instead;
* if cleaning removed most of the definitions, the original is written instead;
* if the cleaned text is a wall of literals (a string dump, a base64 blob) and
  the original was real source, the original is written instead.

Every rollback is reported, with the reason, in the console line and in the
report - a silent rollback would be its own kind of lie.
"""
from __future__ import annotations

import re

from ..polish.demangle import _ast
from ..triage.coverage import compare

_LONG_LITERAL = re.compile(r"""^\s*(?:[rbuf]{0,2})?('|")[A-Za-z0-9+/=_:;.,\-]{120,}\1\s*$""")
_JUNK_CHARS = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")


def _parse(text: str):
    try:
        return _ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def profile(text: str) -> dict:
    """How much of this text is actually a program?"""
    tree = _parse(text)
    lines = [line for line in text.splitlines() if line.strip()]
    literal_lines = sum(1 for line in lines if _LONG_LITERAL.match(line))
    statements = sum(1 for node in _ast.walk(tree) if isinstance(node, _ast.stmt)) \
        if tree is not None else 0
    definitions = sum(1 for node in _ast.walk(tree)
                      if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                           _ast.ClassDef))) if tree is not None else 0
    literal_share = literal_lines / len(lines) if lines else 0.0
    longest = max((len(line) for line in lines), default=0)
    blob = longest >= 200 and statements <= 2
    return {
        "parses": tree is not None,
        "lines": len(lines),
        "statements": statements,
        "definitions": definitions,
        "literal_share": round(literal_share, 3),
        "junk_chars": len(_JUNK_CHARS.findall(text)),
        "longest_line": longest,
        "rubbish": tree is None or blob or (literal_share >= 0.5 and statements <= 2),
    }


def verify(unpacked: str, cleaned: str) -> dict:
    """Decide which text gets written.  Returns {"text", "kept", "reason", ...}."""
    before = profile(unpacked)
    after = profile(cleaned)
    verdict = {"kept": "cleaned", "reason": "", "before": before, "after": after,
               "text": cleaned}

    rollback = None
    if after["parses"] and not before["parses"]:
        rollback = None              # cleaning *gained* structure: keep it
    elif before["parses"] and not after["parses"]:
        rollback = "cleaned output does not parse as Python"
    elif after["rubbish"] and not before["rubbish"]:
        rollback = "cleaned output is a literal dump, not source"
    elif before["parses"] and after["parses"]:
        comparison = compare(unpacked, cleaned)
        kept, lost = comparison["kept"], comparison["lost"]
        total = max(kept + lost, 1)
        if lost / total > 0.2:
            rollback = (f"cleaning lost {lost} of {total} definition(s)")
        elif kept == 0 and before["definitions"] > 0:
            rollback = "cleaning removed every definition"

    if rollback:
        verdict.update({"kept": "unpacked", "reason": rollback, "text": unpacked})
    return verdict


def summary(verdict: dict) -> str:
    if verdict["kept"] == "cleaned":
        return "output verified: still the recovered program"
    return f"rolled back to the unpacked program — {verdict['reason']}"
