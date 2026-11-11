"""pydecomp - normalize."""
from __future__ import annotations

import ast
import re


def normalize(source: str, fmt: str, strip_ansi: bool) -> str:
    text = source.replace("\r\n", "\n").replace("\r", "\n")
    if fmt == "ast":
        try:
            text = ast.unparse(ast.parse(text)) + "\n"
        except SyntaxError:
            pass
    if strip_ansi:
        text = re.sub(r"\\x1b\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\\033\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\\u001b\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    return text

UNKNOWN_PREAMBLE = '''class _PydecompUnknown:
    """Operand the analysis could not resolve; safe to call, read and iterate."""

    __slots__ = ("why",)

    def __init__(self, why="operand"):
        self.why = why

    def __getattr__(self, item):
        return _PydecompUnknown(self.why + "." + item)

    def __call__(self, *args, **kwargs):
        return _PydecompUnknown(self.why + "()")

    def __getitem__(self, item):
        return _PydecompUnknown(self.why + "[...]")

    def __setitem__(self, item, value):
        return None

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __str__(self):
        return "<unknown>"

    __repr__ = __str__


'''

def with_unknown_preamble(text: str) -> str:
    """Give a reconstruction its sentinel definition, once, if it needs one."""
    if "_PydecompUnknown" not in text or "class _PydecompUnknown" in text:
        return text
    return UNKNOWN_PREAMBLE + text
