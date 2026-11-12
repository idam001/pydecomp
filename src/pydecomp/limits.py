"""pydecomp - limits.

1.0.0 "the Almighty" - the caps here are deliberately generous.  pydecomp is a
static recovery tool: a padded limit is a silent truncation, and a truncation is
a wrong answer.  Nothing in this module may stop the engine from writing out the
full source it managed to recover.
"""
from __future__ import annotations


__version__ = "10.0.0"

CODENAME = "the Almighty"

#: hard ceiling for a single decompression / decode step (Almighty: 128 MiB)
MAX_DECOMPRESSED = 128 * 1024 * 1024

#: nested layers followed before the engine stops *looking* for more shells
#: (it still emits everything recovered so far - see engine.dig)
MAX_LAYERS = 64

#: largest recovered file the cosmetic passes will rewrite (bigger files are
#: emitted verbatim rather than risked)
MAX_SOURCE = 64 * 1024 * 1024

#: how many distinct layer chains are explored per input
MAX_CHAINS = 12

EXEC_SINKS = {"exec", "eval", "compile", "builtins.exec", "builtins.eval",
              "builtins.compile", "__builtins__.exec"}

#: the Almighty pipeline.  Every entry is a cosmetic, semantics-preserving pass
#: that ships on by default; ``--fast`` turns the expensive ones off.
ALMIGHTY_PASSES = ("mba", "opaque", "strarray", "alias", "fold", "dead",
                   "unflatten", "demangle")
