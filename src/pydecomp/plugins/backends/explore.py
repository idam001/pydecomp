"""Chain search over the backends.

The peeler reads a loader.  This reads a *blob*: when the loader is too dynamic
to follow - a key from the environment, a file it read at run time, a scheme it
invented - the data is still there, and the techniques that open it are a small
finite set.  Trying them in a chain, cheapest first, and keeping only what
survives a structural check, is how an analyst reads that kind of file.

What this is not: a password cracker.  Every candidate is a backend the tree
declares, every chain is a named sequence, and nothing is accepted because it
"looks close" - the caller supplies the check, and a candidate that fails it is
dropped rather than reported.
"""
from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass

from ._share import promise
from .registry import backends
from .spec import Budget, Refusal


@dataclass(frozen=True)
class Hit:
    chain: tuple[str, ...]
    data: bytes


@dataclass(frozen=True)
class Result:
    hits: tuple[Hit, ...]
    exhausted: bool
    tried: int

    @property
    def recipes(self) -> list[list[str]]:
        return [list(hit.chain) for hit in self.hits]


def explore(blob: bytes, accept, depth: int = 4, budget: Budget | None = None,
            width: int = 12) -> Result:
    """Chains from ``blob``, expanding the most promising node next.

    A chain is only as interesting as the step that follows it: a candidate whose
    bytes open into a known layer is worth more than a candidate that merely
    reads like text, and the wrong XOR key reads like text too.  So the search
    orders its work by that signal and expands the best node first, which both
    finds short chains sooner and stops dead branches before they eat the
    budget.  ``accept(data, chain)`` ends a branch; ``width`` caps how many
    children of one node are worth queueing.
    """
    budget = budget or Budget()
    known = sorted(backends(), key=lambda backend: (backend.cost, backend.name))
    hits: list[Hit] = []
    seen = {hashlib.sha256(blob).digest()}
    queue: list[tuple[float, int, int, tuple[str, ...], bytes]] = [
        (-promise(blob), 0, 0, (), blob)]
    order = 0
    tried = 0
    while queue:
        _weight, level, _order, chain, data = heapq.heappop(queue)
        if level >= max(0, depth):
            continue
        children: list[tuple[float, tuple[str, ...], bytes]] = []
        ranked = sorted(known, key=lambda backend: (-backend.worth_trying(data),
                                                    backend.cost, backend.name))
        for backend in ranked:
            weight = backend.worth_trying(data)
            if weight <= 0.0:
                continue
            # a 255-key scan in the middle of a chain is a rare shape: past the
            # first step, search the expensive backends only when the blob says
            # what it is
            if level and backend.cost >= 3 and weight < 0.8:
                continue
            try:
                budget.spend((backend.cost + 1) * _size_cost(data))
            except Refusal:
                return Result(_shortest(hits), True, tried)
            tried += 1
            for out in backend.candidates(data):
                digest = hashlib.sha256(out).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                step = chain + (backend.name,)
                if accept(out, step):
                    hits.append(Hit(step, out))
                    continue          # a payload is a leaf
                weight = promise(out)
                if weight <= 0.0:
                    continue          # noise does not get another step
                children.append((weight, step, out))
        children.sort(key=lambda item: -item[0])
        for weight, step, out in children[:width]:
            order += 1
            heapq.heappush(queue, (-weight, level + 1, order, step, out))
    return Result(_shortest(hits), False, tried)


def _size_cost(blob: bytes) -> int:
    """A step over a bigger blob costs more, because it is more work.

    Without this a 300 KB literal and a 200 byte payload cost the same, and the
    search spends its whole allowance on the file that was never a loader.
    """
    return 1 + len(blob) // (64 << 10)


def _shortest(hits: list[Hit]) -> tuple[Hit, ...]:
    """The chain a person would name is the shortest one that works."""
    return tuple(sorted(hits, key=lambda hit: (len(hit.chain), hit.chain)))
