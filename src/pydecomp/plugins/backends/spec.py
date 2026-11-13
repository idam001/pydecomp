"""What a backend is, and the four things it promises.

A backend takes bytes and either opens them or returns ``None``.  It never runs
what it finds, never touches the filesystem or the network, never keeps state
between calls, and returns within a size cap.  ``sniff`` is a cheap opinion
about whether a blob is worth trying at all - the explorer uses it to order
work, never to decide an answer.

A backend that cannot open a blob says nothing.  A backend that would have to
guess says nothing too: guessing belongs in the explorer, where every candidate
has to survive a structural check before anyone sees it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

#: no backend is handed a blob, or returns one, larger than this
MAX_BLOB = 64 << 20


class Refusal(Exception):
    """Raised when an exploration spends its budget.  Never caught silently."""


@dataclass(frozen=True)
class Backend:
    """One technique.  It either opens a blob once, or offers candidates.

    ``each`` exists for the backends whose "search" is really an enumeration -
    single-byte XOR, constant shifts.  Returning only the first structured
    candidate throws away the right key whenever a wrong key also produces
    readable bytes, which happens far more often than it sounds.  Those
    backends yield, and the explorer checks every candidate.
    """

    name: str
    kind: str
    cost: int
    opens: Callable[[bytes], bytes | None] | None = None
    sniff: Callable[[bytes], float] | None = None
    note: str = ""
    each: Callable[[bytes], Iterable[bytes]] | None = None

    def worth_trying(self, blob: bytes) -> float:
        if self.sniff is None:
            # "no opinion" is not evidence: a backend that recognises the blob
            # by its charset is a better first move than one that simply tries
            return 0.5
        try:
            return float(self.sniff(blob))
        except Exception:                                 # noqa: BLE001
            return 0.0

    def candidates(self, blob: bytes) -> list[bytes]:
        if not blob or len(blob) > MAX_BLOB:
            return []
        raw: list[bytes] = []
        try:
            if self.each is not None:
                raw = [bytes(item) for item in self.each(blob) if item]
            elif self.opens is not None:
                single = self.opens(blob)
                raw = [bytes(single)] if single else []
        except Exception:                                 # noqa: BLE001
            return []
        out = []
        for item in raw:
            if not item or len(item) > MAX_BLOB or item == blob:
                continue
            if item not in out:
                out.append(item)
        return out


@dataclass
class Budget:
    """Work an exploration may spend.  Running out is reported, not hidden.

    Two limits, because they fail differently: ``opens`` bounds a search on a
    slow phone where each open is cheap but there are thousands of them, and
    ``seconds`` bounds a search on a fast machine where one open (RC4 over a
    megabyte, a repeating-key solve) is not.  Whichever runs out first ends the
    search, and the caller is told that it ended.
    """

    opens: int = 1024
    seconds: float = 30.0
    started: float = field(default_factory=time.monotonic)

    def spend(self, weight: int = 1) -> None:
        """Charge for one attempt.  ``weight`` is the backend's cost plus one, so
        a 255-key search costs what it costs and the cheap paths run first."""
        self.opens -= max(1, weight)
        if self.opens < 0:
            raise Refusal("exploration budget spent")
        if self.seconds and time.monotonic() - self.started > self.seconds:
            raise Refusal(f"exploration took longer than {self.seconds:g}s")


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for byte in data if 9 <= byte <= 13 or 32 <= byte <= 126)
    return good / len(data)
