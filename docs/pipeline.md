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
| **SSA IR pipeline** (`bytecode/ir.py`, `ir_build.py`, `ir_emit.py`, `ir_pipeline.py`) | bytecode → basic blocks → SSA values with phi nodes → AST. Structure is recovered from the control-flow graph, not from a stack walk |
| **stack simulator** (`bytecode/decompiler6.py`, `lift/`) | the original engine: instruction by instruction, pattern per construct |

Both are in-house. The IR pipeline runs first; its output is graded against the
original code object, and the stack simulator's answer stands when the IR answer
does not grade better, or when the emitter meets a construct it does not model.
That is why a construct the emitter has never seen costs nothing: the file is
still decompiled, by the other engine.

## What the SSA engine is asked to prove

The SSA engine's text is accepted on one condition: it recompiles to the same
instruction stream as the original code object. Anything short of that is
dropped and the stack engine's answer stands, so the IR can only ever replace a
correct answer with a proven one.

```console
$ python3 tools/ir_coverage.py
SSA engine: 16/47 cases instruction-identical (34.0%)
stack engine carries the other 31
```

That number is a floor, not a ceiling: the builder names the opcodes it models
and raises `Unsupported` on everything else, and each construct added to
`ir_build.py` moves a case across without touching a single existing answer. The
identity gate itself stays at **47/47** — whichever engine carries a case, the
instruction stream of the result matches the original.

The IR is version-neutral by construction: the builder reads opcode *names*, so
3.8's `CALL_FUNCTION` and 3.15's `CALL` produce the same IR node, and one emitter
serves every version the front end can read.

## The version matrix

Every version the front end reads goes through the same four steps - bytes,
code object, IR, source - and the opcode table each step uses is that release's
own numbering, not an approximation of it:

```console
$ python3 tools/fetch_opcode_tables.py --show
  3.8: 120 opcodes from opcode.py  (6 relative, 5 absolute jumps, 12 comparisons)
  ...
  3.15: 154 opcodes from _opcode_metadata.py  (19 relative, 0 absolute jumps)
```

| version | naming | jumps | IR |
|---|---|---|---|
| 3.8 | `opcode.py`, block stack for `try`/`with` | absolute, `hasjabs` | `while`/`if`/`for` from the CFG, `SETUP_FINALLY` regions named and handed back |
| 3.9 – 3.10 | `opcode.py`, block stack narrowed | absolute, `hasjabs` | same |
| 3.11 | `opcode.py`, split forward/backward jumps, `PRECALL` | relative to the instruction | same, plus `CACHE` skipping |
| 3.12 | `opcode.py`, jumps unified again, `RETURN_CONST` | relative | same |
| 3.13 | `_opcode_metadata.py`, flags in `COMPARE_OP`'s low bits | relative, measured from the *following* instruction | same |
| 3.14 – 3.15 | `_opcode_metadata.py`, `LOAD_FAST_BORROW`, `LOAD_SMALL_INT`, `NOT_TAKEN` | relative | same |

`tests/unit/test_version_matrix.py` assembles real bytecode for each version -
2-byte instructions, that version's jump encoding, that version's marshal layout
- puts it in a `.pyc` with that version's magic, and asserts the source comes
out: `bytes → parse_pyc → CodeObj → IR → AST → source`, eight versions, no other
interpreter on the machine.

The stack engine is still there and still selectable for one cycle:

```console
$ python3 -m pydecomp --legacy packed.pyc
```

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
