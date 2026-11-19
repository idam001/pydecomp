"""Compile-only syntax checks against requested Python grammar versions.

Nothing is imported, executed, or handed to another process.  The running
interpreter compiles the recovered text with ``compile(..., "exec")`` - which
performs the full compile stage (syntax, scope, ``return`` outside a function,
duplicate arguments) but never creates a module and never runs a line of it.
Older targets are checked with ``ast.parse(feature_version=...)``, which rejects
grammar that did not exist yet at that version, and the result says plainly when
a version is beyond what this interpreter can judge.
"""
from __future__ import annotations

import ast
import sys

_MAX_SOURCE = 64 * 1024 * 1024


def _current_target(actual: tuple[int, int]) -> tuple[int, int]:
    return actual


def check_source(source: bytes, versions: list[tuple[int, int]],
                 timeout: float = 8.0) -> list[dict]:
    """Check syntax only; never import or execute the recovered module.

    ``timeout`` is accepted for callers that used the earlier, process-based
    implementation.  Compilation here is in-process and bounded by the size cap,
    so the argument changes nothing.
    """
    del timeout                                    # kept for API compatibility
    if len(source) > _MAX_SOURCE:
        raise ValueError(f"source is larger than the {_MAX_SOURCE}-byte validation limit")
    actual = _current_target(sys.version_info[:2])
    results = []
    for major, minor in versions:
        label = f"{major}.{minor}"
        version = (major, minor)
        if version == actual:
            try:
                compile(source, "<recovered>", "exec", dont_inherit=True)
            except (SyntaxError, ValueError, TypeError, MemoryError) as exc:
                detail = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, SyntaxError) and exc.lineno:
                    detail = f"line {exc.lineno}: {exc.msg}"
                results.append({"version": label, "status": "invalid", "detail": detail[:300]})
            else:
                results.append({"version": label, "status": "ok", "precision": "compile"})
            continue
        if major == 3 and 7 <= minor <= actual[1]:
            try:
                ast.parse(source, filename="<recovered>", feature_version=version)
            except (SyntaxError, ValueError, TypeError) as exc:
                detail = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, SyntaxError) and exc.lineno:
                    detail = f"line {exc.lineno}: {exc.msg}"
                results.append({"version": label, "status": "invalid", "detail": detail[:300]})
            else:
                results.append({"version": label, "status": "ok", "precision": "grammar"})
            continue
        results.append({"version": label, "status": "unavailable",
                        "detail": ("grammar checks cover 3.7 through this interpreter; "
                                   "this target is outside that range")})
    return results


def parse_versions(value: str) -> list[tuple[int, int]]:
    versions = []
    for item in value.split(","):
        parts = item.strip().split(".")
        if len(parts) != 2 or parts[0] != "3" or not parts[1].isdigit():
            raise ValueError(f"invalid target version {item!r}; expected 3.MINOR")
        version = (3, int(parts[1]))
        if version[1] < 7 or version in versions:
            raise ValueError(f"unsupported or duplicate target version {item!r}")
        versions.append(version)
    if not versions:
        raise ValueError("at least one target version is required")
    return versions
