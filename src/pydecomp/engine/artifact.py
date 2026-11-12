"""pydecomp - artifact."""
from __future__ import annotations


class Artifact:
    """What came out of one input file."""

    def __init__(self, text: str, kind: str, trace: list, score: int = 0):
        self.text = text
        self.kind = kind          # source | pseudo | strings
        self.trace = trace
        self.score = score
        # A packer that encrypts its payload leaves this artifact holding the
        # *loader*, not the program the loader would run.  Saying so is the
        # difference between a tool and a liar.
        self.unchanged = False
        self.stalled = False
        self.encrypted_bytes = 0
        self.encrypted_blobs = 0
        # The sealed code object itself: readable structure even when its
        # constants are ciphertext.  Intelligence, not recovery.
        self.payload_code = None

    @property
    def is_source(self) -> bool:
        return self.kind == "source"

def _score(text: str, kind: str) -> int:
    base = {"source": 3, "pseudo": 2, "strings": 1}.get(kind, 0)
    return base * 1_000_000 + len(text)
