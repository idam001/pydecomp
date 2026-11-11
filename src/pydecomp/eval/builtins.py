"""pydecomp - builtins."""
from __future__ import annotations

import builtins

from ..eval.sentinel import _EXEC_SENTINELS
from ..exceptions import _ExprRefuse

def _safe_compile(source, filename="<string>", mode="exec", *args, **kwargs):
    """``compile`` returns its source, never a runnable code object."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    return source

_REFUSED_BUILTINS = {"open", "input", "breakpoint", "exit", "quit", "help",
                     "memoryview", "print", "id", "globals"}

def _safe_builtin(name: str, engine):
    """One builtin by name, with every dangerous one defused."""
    if name in _EXEC_SENTINELS:
        return _EXEC_SENTINELS[name]
    if name == "compile":
        return _safe_compile
    if name == "__import__":
        return engine.import_module
    if name in ("globals", "locals"):
        return engine.module_namespace
    if name == "vars":
        return engine.vars_of
    if name == "dir":
        return engine.dir_of
    if name in _REFUSED_BUILTINS:
        raise _ExprRefuse(f"builtin {name}")
    if hasattr(builtins, name):
        return getattr(builtins, name)
    raise _ExprRefuse(f"builtin {name}")
