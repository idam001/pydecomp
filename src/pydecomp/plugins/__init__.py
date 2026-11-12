"""pydecomp.plugins - community decoders.

A plugin is a function ``(bytes) -> bytes | None`` registered under a name::

    from pydecomp.plugins import register_decoder

    @register_decoder("rot47", priority=10)
    def rot47(blob):
        ...

Distribution is an entry point, so a plugin ships as its own package::

    [project.entry-points."pydecomp.decoders"]
    rot47 = "my_pkg.decoder:rot47"

Rules that make this safe to run inside a recovery: a plugin that raises is
skipped, a plugin that returns the input unchanged is ignored (an infinite loop
is worse than a miss), and the registry is bounded.  Plugins run on *bytes*,
never on a live interpreter, so the no-execution guarantee holds.
"""
from __future__ import annotations

import importlib.metadata as metadata

#: name -> {"fn": callable, "priority": int, "source": str}
REGISTRY: dict[str, dict] = {}
MAX_PLUGINS = 64
ENTRY_POINT_GROUP = "pydecomp.decoders"
_LOADED = {"done": False, "errors": []}


def register_decoder(name: str, priority: int = 0, source: str = "local"):
    """Decorator adding one decoder to the registry."""
    def decorator(function):
        if len(REGISTRY) >= MAX_PLUGINS and name not in REGISTRY:
            raise RuntimeError(f"decoder registry is full ({MAX_PLUGINS})")
        REGISTRY[name] = {"fn": function, "priority": int(priority),
                          "source": source}
        return function
    return decorator


def unregister(name: str) -> bool:
    return REGISTRY.pop(name, None) is not None


def decoders() -> list[tuple[str, dict]]:
    """Registered decoders, highest priority first."""
    load_plugins()
    return sorted(REGISTRY.items(), key=lambda item: (-item[1]["priority"], item[0]))


def load_plugins() -> list[str]:
    """Import every installed plugin once.  A broken plugin is not fatal."""
    load_plugins.errors = _LOADED["errors"]
    if _LOADED["done"]:
        return [name for name in REGISTRY if REGISTRY[name]["source"] != "local"]
    _LOADED["done"] = True
    loaded = []
    try:
        entries = metadata.entry_points()
        found = (entries.select(group=ENTRY_POINT_GROUP)
                 if hasattr(entries, "select") else entries.get(ENTRY_POINT_GROUP, []))
    except Exception as exc:                         # noqa: BLE001 - metadata may fail
        _LOADED["errors"].append(f"{type(exc).__name__}: {exc}")
        return loaded
    for entry in found:
        try:
            function = entry.load()
        except Exception as exc:                     # noqa: BLE001 - one bad plugin
            _LOADED["errors"].append(f"{entry.name}: {type(exc).__name__}: {exc}")
            continue
        if callable(function):
            REGISTRY.setdefault(entry.name, {"fn": function, "priority": 0,
                                             "source": f"entry point {entry.value}"})
            loaded.append(entry.name)
    return loaded


load_plugins.errors: list[str] = []


def unwrap(data: bytes, limit: int = 4) -> tuple[bytes | None, str]:
    """First plugin that returns new bytes wins: ``(blob, name)``."""
    if not data:
        return None, ""
    tried = 0
    for name, entry in decoders():
        if tried >= limit:
            break
        tried += 1
        try:
            out = entry["fn"](data)
        except Exception:                            # noqa: BLE001 - a plugin may fail
            continue
        if isinstance(out, (bytes, bytearray)) and bytes(out) != data and out:
            return bytes(out), name
    return None, ""


def summary() -> str:
    decoders_found = decoders()
    if not decoders_found:
        return "no decoders registered"
    errors = getattr(load_plugins, "errors", [])
    text = f"{len(decoders_found)} decoder(s): " + ", ".join(n for n, _ in decoders_found[:6])
    if errors:
        text += f" · {len(errors)} plugin(s) failed to load"
    return text


__all__ = ["ENTRY_POINT_GROUP", "REGISTRY", "decoders", "load_plugins",
           "register_decoder", "summary", "unregister", "unwrap"]
