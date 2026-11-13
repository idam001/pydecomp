"""Find the backends, once, in a stable order.

The trees are ordinary packages; a module is a backend bundle if it publishes
``BACKENDS``.  Discovery walks them with ``pkgutil`` so adding a subtree is
adding a directory - there is no list to remember and no import-time cost paid
by anyone who never asks for a backend.

The single-file build has no directories to walk: its modules are served by a
finder.  So discovery also asks the import machinery what it can serve, which is
the same question in a form that survives being packed into one file.

Order is ``(cost, name)``.  That is not a ranking of quality: it is a promise
that two runs on the same blob do the same work in the same sequence, which is
what makes a recipe in a report mean something.
"""
from __future__ import annotations

import importlib
import pkgutil
import sys

from .spec import Backend

TREES = ("codecs", "compress", "cipher", "containers", "alphabet")
#: not a directory: decoders registered by other packages, wrapped as backends
COMMUNITY = "community"

_cache: tuple[Backend, ...] | None = None


def _submodules(package) -> list[str]:
    """Every submodule name of ``package``, from the filesystem or a finder."""
    names = {info.name for info in pkgutil.iter_modules(getattr(package, "__path__", []))}
    for finder in sys.meta_path:
        lister = getattr(finder, "list_modules", None)
        if lister is None:
            continue
        try:
            served = lister(package.__name__)
        except Exception:                                  # noqa: BLE001
            continue
        names |= {name.rsplit(".", 1)[-1] for name in served}
    return sorted(names)


def _load_tree(tree: str) -> list[Backend]:
    package = importlib.import_module(f"{__name__.rsplit('.', 1)[0]}.{tree}")
    found: list[Backend] = []
    for name in _submodules(package):
        if name.startswith("_"):
            continue
        module = importlib.import_module(f"{package.__name__}.{name}")
        for backend in getattr(module, "BACKENDS", ()):
            if isinstance(backend, Backend):
                found.append(backend)
    return found


def _load_community() -> list[Backend]:
    from . import community
    return community.backends()


def backends(kind: str | None = None) -> tuple[Backend, ...]:
    """Every registered backend, ordered.  Cached after the first call."""
    global _cache
    if _cache is None:
        loaded: list[Backend] = []
        for tree in TREES:
            loaded.extend(_load_tree(tree))
        loaded.extend(_load_community())
        names = [backend.name for backend in loaded]
        duplicated = {name for name in names if names.count(name) > 1}
        if duplicated:
            raise RuntimeError(f"two backends share a name: {sorted(duplicated)}")
        _cache = tuple(sorted(loaded, key=lambda backend: (backend.cost, backend.name)))
    if kind is None:
        return _cache
    return tuple(backend for backend in _cache if backend.kind == kind)


def reset() -> None:
    """Forget the discovery cache.  For tests, and for a plugin registered late."""
    global _cache
    _cache = None


def by_name(name: str) -> Backend | None:
    for backend in backends():
        if backend.name == name:
            return backend
    return None


def describe() -> list[str]:
    """One line per backend, for the report and for the gate."""
    lines = []
    for backend in backends():
        lines.append(f"{backend.kind:10s} {backend.name:22s} cost {backend.cost}  "
                     f"{backend.note}".rstrip())
    return lines
