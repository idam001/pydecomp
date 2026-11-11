# Architecture

pydecomp is a pipeline of small, testable stages. Each stage takes bytes (or a
code object, or source text) and returns the same kind of thing, so the engine
can keep unwrapping without knowing how many layers it will find.

```
            ┌──────────────┐
  bytes ───▶│   triage     │  sniff: text? pyc? marshal? zip? ELF?
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │   decoders   │  base64/85/32, hex, emoji, rot13, xor, rc4,
            │   + crypto   │  zlib, gzip, bz2, lzma, zip
            └──────┬───────┘
                   ▼  (repeat, ≤25 layers, cycle-safe)
            ┌──────────────┐
            │   bytecode   │  marshal reader → CodeObj → disassemble
            │              │  → lifter → AST → source (decompiler6)
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │    eval      │  pure-expression evaluator (whitelisted)
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │   polish     │  demangle, fold, unflatten, strip dead code
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │   output     │  write one file, audit, render the report
            └──────────────┘
```

## Stages

### Triage — `pydecomp/triage/`

Cheap, decisive checks: does it start with a magic number (`.pyc`), an ELF
header, a zip, a known container signature? Is it mostly printable text? Is it
a `marshal` image? Triage also fingerprints the family from structure
(mangling pattern, decoder chain shape, encryption constants) — the label never
drives the recovery, it only describes it.

### Decoders and crypto — `pydecomp/decoders/`, `pydecomp/crypto/`

Every decoder is `bytes -> bytes | None`, and says "not mine" quickly. The
engine tries them in parallel and recurses on every success, which is why
`base64(gzip(zip(...)))` and `gzip(base64(...))` both work without a special
case. Crypto is standard library only (RC4, XOR, Blowfish, AES helpers), because
the delivery format for phones is one file with no dependencies.

### Bytecode — `pydecomp/bytecode/`

The core of the project:

- `marshal_reader.py` — pydecomp's own `marshal` parser. It reads code objects
  for CPython 3.9 → 3.14 regardless of the interpreter running, and never uses
  `marshal.loads` on sample data.
- `opcodes/tables.py` — one table per version, validated against `dis.opmap` in
  CI (`tools/gen_opcode_tables.py --check`).
- `disassembler.py` — the version's opcode stream, with `EXTENDED_ARG` folding.
- `lifter.py`, `folding.py` — opcodes up to statements, constants folded.
- `decompiler6.py` — structure recovery: blocks, loops, `try`, `with`,
  comprehensions.
- `roundtrip.py` — scores a rebuild by how many of the original instructions it
  reproduces. That score decides between the structural rebuild and the
  statement-by-statement fallback.

### Eval — `pydecomp/eval/`

A whitelisted interpreter for decoder chains: `chr`, `ord`, `join`, slices,
comprehensions over literals… `EXPR_MODULES` names the modules allowed to be
resolved; anything else becomes `_PydecompUnknown`. Nothing can touch the
filesystem, the network or a process.

### Polish — `pydecomp/polish/`

Readability passes that never change behaviour:

- `demangle.py` — restores names from mangling schemes, and *reports* each
  rename rather than silently rewriting.
- `fold.py`, `dead.py` — constant folding, dead-branch removal.
- `unflatten.py` — control-flow flattening (the `while True: match state:` shape)
  back to real branches.

### Output — `pydecomp/output/`

Writes exactly one file by default, prepends the stable preamble, runs the
audit (compile + unbound-name scan) and renders the panel or the reports.

## Why the layers are shaped this way

The package is layered `engine → eval → bytecode → crypto/decoders` with no
import cycles — 75 modules and 15 package inits, ~11,200 lines of engine plus a
2,400-line native sidecar, zero cycles. That is a hard
requirement, not a style preference: the single-file build emits modules in a
table and imports them at runtime, so a cycle would surface as an import error
only on the phone. `tools/build_single.py` and the `identity` gate catch it
first.

## Reading a recovery

```
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

That is the whole header: one line, always the same. The provenance that used to
live above the code — round-trip percentage, degraded-mode note, hash,
fingerprint, layers, imports, indicators — is still computed and is printed in
the console panel and written to `--reports`. It is deliberately *not* mixed
into the recovered source any more.

| Where the detail lives | What it says |
|---|---|
| console panel `result` | `python source` or `lifted from bytecode`, plus the stage count |
| `--reports` JSON `trace` | each layer, in order, with byte counts |
| `--reports` JSON `audit` | does it compile, which names are unbound |
| native `.report.md` | which recovery tier won (S/B/A/C) |

Statements the lifter could not line up are still emitted as `# comments` with
the opcode offset that produced them, so nothing is silently dropped.
