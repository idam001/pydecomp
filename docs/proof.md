# Proof-carrying output

Every recovery writes three files:

```
sample_deob.py          the program
sample_deob.proof.json  the evidence, machine-checkable
sample_deob.proof.md    the same evidence, readable
```

The point is that a reader does not have to trust pydecomp. They can re-run the
comparison, or write their own against the same schema.

## The three tiers

| tier | how it is earned | written as |
|---|---|---|
| `semantic` | recompile the recovered text, re-disassemble it, and diff **every** instruction and operand against the original code object | plain source |
| `structural` | the instruction streams differ, but the opcode profile and the constant table match | plain source; `--annotate` adds a header |
| `syntactic` | it compiles | plain source; `--annotate` adds a header |
| `unverified` | it does not compile | kept, because dropping it loses code; `--annotate` adds a header |

A module is reported at the **weakest** tier any of its units needed, and the
per-unit verdicts are in the JSON (`tiers.semantic`, `tiers.structural`, …) so
"97% proven" is never a rounding exercise.

### What counts as an instruction

Operands that change behaviour are compared: `BINARY_OP` (`+` vs `*`),
`COMPARE_OP` (`<` vs `>`), `IS_OP`, `CONTAINS_OP`, `LOAD_CONST` (by value),
names, and fast-local slots. Layout-only opcodes (`RESUME`, `CACHE`, `NOP`,
`EXTENDED_ARG`) and jump encodings are excluded, because the same program can be
laid out differently. Without the value-bearing set, `a + b` and `a * b` compare
equal — that was a real hole, closed in this release and pinned by a test.

## The schema

```json
{
  "tool": "pydecomp 1.0.0",
  "input": {"name": "worker.py", "sha256": "…", "bytes": 2883},
  "kind": "source",
  "layers": [
    {"depth": 1, "transform": "carve", "backend": "engine.carve", "verified": true},
    {"depth": 2, "transform": "parse code object",
     "backend": "bytecode.marshal_reader", "target": "CPython 3.13"},
    {"depth": 3, "transform": "lift to source", "backend": "pydecomp.lift"}
  ],
  "tiers": {"semantic": ["<module>", "collect", "ship"],
            "structural": [], "syntactic": [], "unverified": []},
  "inferred": [{"region": "cleaned identifiers", "reason": "renamed 3 names",
                "confidence": 0.9}],
  "lost": ["comments - the bytecode does not carry them"],
  "guarantee": "no input byte was executed, imported, or compiled"
}
```

`guarantee` is not a slogan: it is enforced by `tools/check_static_only.py`,
which scans every module in the package for `exec`, `eval`, `__import__` of a
sample, and `compile()` of anything but text this tool wrote.

## `--strict`

```console
$ pydecomp sample.py --strict ; echo $?
✘ strict: syntactic output (0 proven, 0 structural, 1 syntactic, 0 unverified) - nothing written
3
```

Nothing is written, not even the proof. Exit `3` distinguishes "refused to make
a claim" from "failed" (`1`) and "succeeded" (`0`), so a pipeline can gate on it.

## `--annotate`

The recovered file carries only the project stamp by default, because a file
full of banners is not source. `--annotate` adds one comment line naming the
tier:

```python
# STRUCTURAL - equivalent control flow, encoding differs
```

## Why a cleaning pass may be rolled back

Polish renames identifiers, folds constants and prunes dead branches. Any of
those can change the program. So the tier is computed **before and after**
cleaning, and if cleaning costs a tier the cleaned text is discarded and the
run says so:

```
cleaned   cleaning rolled back: semantic -> structural
```

That is the machine-checkable version of the rule this project has always had:
a cleaning pass may only be kept if the output is still the recovered program.
