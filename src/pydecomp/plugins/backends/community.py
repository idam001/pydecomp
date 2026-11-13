"""Community decoders, seen as backends.

``pydecomp.plugins`` is a separate, older contract: a function ``bytes -> bytes``
with no cost, no sniff, no name for what it does beyond its label.  This module
adapts it instead of requiring plugin authors to learn a second interface - the
chain search then treats a decoder from another package exactly like a built-in
one, which is the point of having a plugin system at all.

Registry order is priority, so a plugin that declares a high priority is tried
before the built-ins of the same cost.  A plugin that raises is skipped by
``Backend.candidates`` like any other failure.
"""

from __future__ import annotations

import importlib

#: the package defines a function called ``decoders`` *and* wants to be read as
#: a module: import it once here so the name below is the module, not a function
community = importlib.import_module("pydecomp.plugins")
from .spec import Backend

#: a plugin's declared priority is a nudge, not a promise: it moves the order
#: inside one cost band and never past a cheaper backend
COST_BY_PRIORITY = ((20, 0), (10, 1), (0, 2))


def _cost(priority: int) -> int:
    for threshold, cost in COST_BY_PRIORITY:
        if priority >= threshold:
            return cost
    return 3


def backends() -> list[Backend]:
    found: list[Backend] = []
    for name, entry in community.decoders():
        if entry.get("source", "local") == "local":
            continue                     # the built-in trees carry their own names
        found.append(Backend(
            f"plugin:{name}", "plugin", _cost(int(entry.get("priority", 0))),
            entry["fn"], None, f"community decoder from {entry.get('source', '?')}"))
    return found


def load() -> list[str]:
    """Import installed plugins once; returns the entry-point errors, if any."""
    community.load_plugins()
    return list(getattr(community.load_plugins, "errors", []) or [])
