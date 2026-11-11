"""pydecomp - artifact."""
from __future__ import annotations


class Artifact:
    """What came out of one input file."""

    def __init__(self, text: str, kind: str, trace: list, score: int = 0):
        self.text = text
        self.kind = kind          # source | pseudo | strings
        self.trace = trace
        self.score = score

    @property
    def is_source(self) -> bool:
        return self.kind == "source"

def _score(text: str, kind: str) -> int:
    base = {"source": 3, "pseudo": 2, "strings": 1}.get(kind, 0)
    return base * 1_000_000 + len(text)
