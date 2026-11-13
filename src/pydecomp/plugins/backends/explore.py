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
from dataclasses import dataclass

from ._share import evidence
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
    """Breadth-first chains from ``blob``; ``accept(data, chain)`` ends a chain.

    Breadth first is deliberate: the shortest chain that survives the check is
    the one a person would name, and a longer chain through the same bytes is
    only interesting if the short one failed.
    """
    budget = budget or Budget()
    hits: list[Hit] = []
    seen = {hashlib.sha256(blob).digest()}
    frontier: list[tuple[tuple[str, ...], bytes]] = [((), blob)]
    tried = 0
    for _level in range(max(0, depth)):
        if not frontier:
            break
        produced: list[tuple[float, tuple[str, ...], bytes]] = []
        for chain, data in frontier:
            ranked = sorted(backends(),
                            key=lambda backend: (-backend.worth_trying(data),
                                                 backend.cost, backend.name))
            for backend in ranked:
                weight = backend.worth_trying(data)
                if weight <= 0.0:
                    continue
                # a 255-key scan in the middle of a chain is a rare shape: after
                # the first step, only search the expensive backends when the
                # blob itself says what it is
                if _level and backend.cost >= 3 and weight < 0.8:
                    continue
                try:
                    budget.spend(backend.cost + 1)
                except Refusal:
                    return Result(tuple(hits), True, tried)
                tried += 1
                for out in backend.candidates(data):
                    digest = hashlib.sha256(out).digest()
                    if digest in seen:
                        continue
                    seen.add(digest)
                    step = chain + (backend.name,)
                    if accept(out, step):
                        hits.append(Hit(step, out))
                        continue      # a payload is a leaf: nothing decodes it further
                    weight = evidence(out)
                    if weight <= 0.0:
                        continue      # noise does not get another step
                    produced.append((weight, step, out))
        produced.sort(key=lambda item: -item[0])
        frontier = [(step, out) for _weight, step, out in produced[:width]]
    return Result(tuple(hits), False, tried)
