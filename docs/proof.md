# Proof-carrying output

When proof output is enabled, a successful recovery writes the source and
machine-readable/readable proof companions:

```
sample_deob.py          the recovered program
sample_deob.proof.json  machine-checkable evidence
sample_deob.proof.md    readable evidence
```

`--no-proof` disables the companions; a strict/perfect refusal writes neither
source nor proof. A reader can independently re-run the comparison or implement
a checker against the schema.

## Proof tiers

| tier | how it is earned | written as |
|---|---|---|
| `perfect` | on the same interpreter version, every instruction record, canonical operand, and rendered argument matches | plain source |
| `semantic` | normalized instruction streams match after branch destinations are expressed as instruction indices rather than byte offsets | plain source; this is a comparator result, not a formal proof of all runtime behavior |
| `structural` | instruction streams differ, but opcode profile and constant table match | plain source; `--annotate` adds a header |
| `syntactic` | it compiles, but stronger equivalence checks did not pass | plain source; `--annotate` adds a header |
| `unverified` | it does not compile | retained only where policy allows; the failure is reported |

A module is reported at the **weakest** tier any of its units needed. The JSON
contains per-unit verdicts and exact-match evidence (`tiers.perfect`,
`tiers.semantic`, `tier_0_units`, and `perfect_match`), so a rounded percentage
cannot hide a weaker function. Cross-version samples cannot earn same-version
instruction tiers merely by compiling.

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
  "tiers": {"perfect": ["<module>", "collect", "ship"], "semantic": [],
            "structural": [], "syntactic": [], "unverified": []},
  "tier_0_units": ["<module>", "collect", "ship"],
  "perfect_match": "all compared instructions identical",
  "inferred": [{"region": "cleaned identifiers", "reason": "renamed 3 names",
                "confidence": 0.9}],
  "lost": ["comments - the bytecode does not carry them"],
  "guarantee": "no input byte was executed, imported, or compiled"
}
```

`guarantee` is not a slogan: it is enforced by `tools/check_static_only.py`,
which scans every module in the package for `exec`, `eval`, `__import__` of a
sample, and `compile()` of anything but text this tool wrote.

## `--strict` and `--perfect`

`--strict` requires every unit to reach at least `semantic` (a `perfect` unit
also satisfies that threshold). `--perfect` requires every unit to be exactly
`perfect`. Either option refuses without writing source or proof when its
threshold is missed.

```console
$ pydecomp sample.py --strict ; echo $?
✘ strict: syntactic output - nothing written
3

$ pydecomp sample.py --perfect ; echo $?
✘ perfect: semantic output - nothing written
2
```

Exit `3` means the strict threshold was not met; exit `2` means the stronger
perfect threshold was not met. Exit `1` is an execution/input failure and `0`
is success. These grades are static comparison evidence, not a guarantee that
arbitrary recovered code is safe to run.

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
