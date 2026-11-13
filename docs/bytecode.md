# The bytecode engine

This is where most of pydecomp's value lives, and where the hard bugs are. The
rule that shapes everything: **pydecomp must not need the interpreter that
produced the sample.**

## In-house marshal reader

`pydecomp/bytecode/marshal_reader.py` parses the `marshal` format directly:

- every type tag CPython emits (`i`, `l`, `s`, `t`, `z`, `Z`, `u`, `a`, `A`,
  `(`, `)`, `[`, `{`, `c`, …) including the reference table (`r`);
- code objects for 3.9 → 3.14, whose field sets differ (3.11 added the exception
  table and `co_qualname`, 3.12 changed slice handling, 3.13 renumbered opcodes,
  3.14 folded more into `BINARY_OP`);
- bounds on every read, so a hostile "declare 4 GB string" is refused before it allocates.

Consequence: you can decompile a 3.9 `.pyc` from a 3.13 interpreter, and a
malformed stream raises a caught error instead of a segfault-level surprise.

## Opcode tables

`pydecomp/bytecode/opcodes/tables.py` holds one table per version, and every
number in it is read from the release it belongs to rather than remembered:

```console
$ python3 tools/fetch_opcode_tables.py --show
  3.8: 120 opcodes from opcode.py  (6 relative, 5 absolute jumps, 12 comparisons)
  3.9: 119 opcodes from opcode.py  (5 relative, 6 absolute jumps, 6 comparisons)
  3.10: 127 opcodes from opcode.py  (5 relative, 6 absolute jumps, 6 comparisons)
  3.11: 110 opcodes from opcode.py  (15 relative, 0 absolute jumps, 6 comparisons)
  3.12: 129 opcodes from opcode.py  (9 relative, 0 absolute jumps, 6 comparisons)
  3.13: 150 opcodes from _opcode_metadata.py  (17 relative, 0 absolute jumps)
  3.14: 154 opcodes from _opcode_metadata.py  (19 relative, 0 absolute jumps)
  3.15: 154 opcodes from _opcode_metadata.py  (19 relative, 0 absolute jumps)
```

Each release contributes three facts, and the decoder needs all three:

| fact | why it matters |
|---|---|
| the table | `LOAD_CONST` is 100 on 3.10 and 82 on 3.14 |
| relative vs absolute jumps | 3.8's `FOR_ITER` counts from its own instruction while its `JUMP_IF_FALSE_OR_POP` names an address |
| the comparison list | before 3.12 `COMPARE_OP`'s operand indexes `cmp_op`, and 3.8's list also reaches `in`, `is` and `exception match` |

`tools/gen_opcode_tables.py --check` validates what is committed three ways:

1. coherence — no duplicates, no values outside a byte;
2. drift — an opcode that moves between versions must be in
   `KNOWN_RENUMBERED` or the check fails;
3. ground truth — for the running interpreter, the table must equal
   `dis.opmap` exactly (excluding `INSTRUMENTED_*` and pseudo-instructions
   above 255, which never appear in a real `.pyc`).

Regenerate rather than edit: `python3 tools/fetch_opcode_tables.py --write`.

## Lifting

```
bytes → CodeObj → instructions → statements → AST → source
```

- `disassembler.py` folds `EXTENDED_ARG` and resolves names from the code
  object's `co_names`, `co_varnames`, `co_consts`.
- `lifter.py` turns instructions into statements, tracking the value stack.
- `folding.py` folds constants and simplifies boolean expressions.
- `decompiler6.py` recovers structure: `if`/`else`, loops, `try`/`except`,
  `with`, comprehensions, nested functions and classes.

## The round-trip score

Every rebuild is scored by re-compiling it and comparing instruction streams
against the original code object:

```
score = matching instructions / original instructions
```

That single number decides which strategy wins:

| Score | Strategy |
|---|---|
| 100% | structural rebuild is instruction-identical — this is what the `identity` gate asserts for 47 shapes |
| ≥ 50% | structural rebuild is used, with a note in the preamble |
| < 50% | statement-by-statement lift is used; frames become `# comments` |

Nothing is thrown away silently: a statement the lifter could not place appears
as a comment with its opcode offset.

## Known soft spots

- **Module-level `try`** on 3.13: the statements survive, the `try` frame is
  commented out (`test_module_level_try_keeps_its_statements`).
- **Generators with `yield from`** inside comprehensions: recovered as plain
  loops when the structure is ambiguous.
- **Match statements**: recovered as the equivalent `if`/`elif` chain.
- **3.14 `TAIL_CALL`**: recognised, but the tail-call shape is emitted as a
  normal call.

Each of these is a `probes` case in the gate suite, so a regression shows up as
a number rather than a user report.
