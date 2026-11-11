"""pydecomp - limits."""
from __future__ import annotations


__version__ = "8.1.0"

MAX_DECOMPRESSED = 32 * 1024 * 1024   # 32 MiB per layer

MAX_LAYERS = 25

MAX_SOURCE = 8 * 1024 * 1024

EXEC_SINKS = {"exec", "eval", "compile", "builtins.exec", "builtins.eval",
              "builtins.compile", "__builtins__.exec"}
