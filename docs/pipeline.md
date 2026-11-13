# The decompiler pipeline

There is one engine, it ships in this repository, and it is the only thing that
runs. `route()` answers the same for every version because there is no other
candidate: no subprocess, no optional package, no `pip install` of somebody
else's decompiler.

```console
>>> from pydecomp.bytecode.backends import route, candidates
>>> route((3, 9))
['pydecomp.lift']
>>> [b.name for b in candidates((3, 15))]
['pydecomp.lift']
```

## Two engines, one answer

| engine | how it works |
|---|---|
| **SSA IR pipeline** (`bytecode/ir.py`, `ir_build.py`, `ir_emit.py`) | bytecode → basic blocks → SSA values with phi nodes → AST. Structure is recovered from the control-flow graph, not from a stack walk |
| **stack simulator** (`bytecode/decompiler6.py`, `lift/`) | the original engine: instruction by instruction, pattern per construct |

Both are in-house. The IR pipeline runs first; its output is graded against the
original code object, and the stack simulator's answer stands when the IR answer
does not grade better, or when the emitter meets a construct it does not model.
That is why a construct the emitter has never seen costs nothing: the file is
still decompiled, by the other engine.

## Selecting an answer

Every candidate's text is graded against the *original code object* with the same
comparator the proof uses. The strongest tier wins; ties go to the longer text.
Text that reproduces the instructions beats text that merely looks right.

The decision is recorded in `pydecomp.bytecode.backends.LAST` and carried in the
proof:

```json
{"depth": 3, "transform": "lift to source", "backend": "pydecomp.lift",
 "tier": "semantic", "target": "CPython 3.15"}
```

## Adding an engine

```python
from pydecomp.bytecode.backends.base import Backend

class MyEngine(Backend):
    name = "mine"
    kind = "native"                  # it ships with the build
    versions = ((3, 8), (3, 15))

    def decompile(self, data, version):
        return some_text_or_None     # None means "the other engine's answer stands"
```

Register it in `backends.pool()`. Grading decides whether its text is kept, so a
new engine can only improve the result it is compared against.

## The rule

Nothing in the package shells out. `tests/unit/test_platform.py` walks every
module's AST and fails on an import of `subprocess`, on a foreign decompiler name
in executable code, and on a `backends` extra in `pyproject.toml`. The
single-file build carries the whole pipeline with it.
