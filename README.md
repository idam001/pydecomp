# pydecomp

**Static Python deobfuscator and decompiler.** Recovers supported PyInstaller,
Nuitka, freezer, marshal, `.pyc`, and common encoded-layer formats without
running the sample. PyArmor-format recovery is key-dependent and experimental:
the end-to-end fixture is synthetic, so it does not establish compatibility with
every vendor build. See the per-format limits and test evidence below.

**Successful output includes machine-checkable proof by default; strict modes
refuse to write when their proof threshold is missed.** By
[Idam Emmanuel](https://github.com/idam001).

[![CI](https://github.com/idam001/pydecomp/actions/workflows/ci.yml/badge.svg)](https://github.com/idam001/pydecomp/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-1.0.0-3fb950)
![host CI matrix](https://img.shields.io/badge/host%20CI%20matrix-CPython%203.9%E2%80%933.15-58a6ff)
![deps](https://img.shields.io/badge/runtime%20dependencies-none-3fb950)

```
sample_deob.py          the recovered program
sample_deob.proof.json  what was peeled, which backend decompiled it,
                        which functions are instruction-identical, and what
                        was inferred or lost
```

```
$ pydecomp suspicious.py
   ▸ Decompiling suspicious.py
   ▸ stage 1   layer 1: base64 → zlib · 1,204 B
   ▸ stage 2   layer 2: marshal → code object · 12,884 B
   ▸ writing output   suspicious_deob.py
   ▸ verifying   sha256 9f2c1ab0…

   ╭─ DONE ─────────────────────────────────────────────────────────────╮
   │ source    suspicious.py   2,499 bytes                              │
   │ result    lifted from bytecode   3 stages                          │
   │ output    suspicious_deob.py   5,386 bytes                         │
   │ elapsed   0.03s                                                    │
   ╰────────────────────────────────────────────────────────────────────╯
```

One source file out, with its proof beside it. No telemetry, no `exec`, and no
network unless you ask for it (`--fetch-iocs`).

Every recovered file carries exactly one line above the code, and nothing else:

```python
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

---

## What the proof says

Every run grades the recovered program against the code it came from, unit by
unit, and writes the result next to the output:

| tier | meaning | written as |
|---|---|---|
| **perfect** | same-version instruction records match exactly, including operands and rendered branch targets | plain source |
| **semantic** | normalized instruction streams match, with layout-dependent jump offsets normalized | plain source; not a formal proof of behavior for arbitrary programs |
| **structural** | opcode profile and constant table match, but instruction streams differ | `--annotate` marks it |
| **syntactic** | it compiles; equivalence is not established | `--annotate` marks it |
| **unverified** | it does not compile; retained only where policy allows, with the failure reported | `--annotate` marks it |

![Synthetic PyArmor-shaped fixture: static recovery and proof output](docs/assets/proof-pyarmor.svg)

The image below is generated from `tests/fixtures/pyarmor_case.py`; it is a
format-shaped test fixture, not a vendor-produced PyArmor sample.

```console
$ pydecomp worker.py          # runtime beside the sample, if a key candidate is recoverable
   runtime   ~/case/pyarmor_runtime_000000/pyarmor_runtime.so  (used for the runtime key)
   ▸ stage 5   PyArmor 8+ blob · serial 000000 · CPython 3.13 · AES-CTR across the code objects
   ▸ stage 6   static unpack: 1 code object(s) recovered · key 11223344… verified by marshal structure
   fidelity   output verified: still the recovered program
   proof      proven 3/3 units (100%) · tier perfect
```

`--strict` writes **nothing** unless every unit reaches at least the `semantic`
tier, and exits `3` on refusal. `--perfect` requires every unit to reach the
stronger `perfect` tier and exits `2` on refusal. Both leave no source or proof
file when their threshold is not met; neither is a formal proof of arbitrary
runtime behavior.

![pydecomp --strict writes only what it proves](docs/assets/strict-refusal.svg)

### Verify a proof yourself

A proof is only worth something if somebody else can check it. One flag
re-derives it from the sample and the file that was written:

```console
$ pydecomp --check-proof out/worker_deob.proof.json
   proof  worker_deob.proof.json
     ok   schema           all keys present
     ok   guarantee        no input byte was executed, imported, or compiled
     ok   input sha256     recorded 58c1b15b93f2c34b… / now 58c1b15b93f2c34b…
     ok   output sha256    ~/out/worker_deob.py
     ok   tiers reproduce  recomputed perfect=3, semantic=0, structural=0
   verified: this file is what the proof says it is
```

Change one line of the output and the same command exits `4` with
`DRIFT: the proof no longer describes these files`. `--html` writes a
self-contained `.report.html` (source, proof, indicators, guarantee) that opens
offline — no CDN, no fonts, no scripts.

![PyInstaller CArchive to source](docs/assets/pyinstaller.svg)

## What it handles

| | |
|---|---|
| **Protectors** | PyArmor-shaped blobs: experimental, key-dependent recovery; the committed end-to-end fixture is synthetic. Missing or unverified keys leave the code opaque. Other named schemes are reported with their tested limits. |
| **Freezers** | PyInstaller CArchive + PYZ and listed freezer formats; check the fixture matrix for which container versions have end-to-end tests. |
| **Bytecode** | Opcode tables include CPython 3.8–3.15; table presence means the stream can be decoded, not that every construct is lifted. The CI host matrix is configured for CPython 3.9–3.15; exact per-target reconstruction coverage is narrower and versioned. |
| **Interpreter recognition** | CPython, PyPy, MicroPython `.mpy`, Jython, IronPython, Brython signatures can be identified; recognition does not imply source decompilation support |
| **Obfuscators** | 21 named schemes with their contract (marker or shape), then the generic peeler |
| **Backends** | the bundled SSA and stack lifters; no third-party decompiler backend is currently wired into selection |
| **Agents** | MCP server (`pydecomp --mcp`): `identify`, `peel`, `triage`, `decompile_pyc`, `deobfuscate` |
| **Plugins** | `pip install`able decoders via the `pydecomp.decoders` entry point |

## The board

Running `pydecomp` with no arguments shows the banner: the block logo, the
author's welcome band, the network and country of the machine doing the
analysis (read offline — no sockets, no DNS), and the identity card.

```
   ꧁✿❀✿꧂─────────────────────────────────────────────────────────────꧁✿❀✿꧂

   ████  █   █ ████  █████  ████  ███  █   █ ████
   █   █ █   █ █   █ █     █     █   █ ██ ██ █   █
   ████   ███  █   █ ████  █     █   █ █ █ █ ████
   █       █   █   █ █     █     █   █ █   █ █
   █       █   ████  █████  ████  ███  █   █ █

   ꧁✿❀✿꧂─────────────────────────────────────────────────────────────꧁✿❀✿꧂
                    WELCOME TO IDAM EMMANUEL TOOLS

   [ NETWORK ] : WLAN0, RMNET_DATA0
   [ COUNTRY ] : Nigeria
   ═══════════════════════════════════════════════════════════════════════
   [•] Owner   : [Idam Emmanuel]
   [•] Tool    : [PYDECOMP]
   [•] Edition : [THE ALMIGHTY]
   [•] Status  : [OPEN SOURCE]
   [•] Version : [1.0.0]
   ═══════════════════════════════════════════════════════════════════════
```

`--no-color` or a pipe prints the same board as plain text. Override the
detected values with `PYDECOMP_NETWORK` / `PYDECOMP_COUNTRY`, and rebrand a fork
with `PYDECOMP_AUTHOR` / `PYDECOMP_SIGNATURE`.

---

## Selected format support and limits

| Input | What pydecomp does, statically |
| --- | --- |
| base64 / zlib / bz2 / lzma / hex / base85 / z85 / base58 / base45 / base91 / uu chains | bounded layer peeling; see configured depth and size limits |
| marshal / `.pyc` | versioned readers and opcode tables; source lifting is partial and unsupported constructs fall back |
| PyInstaller (CArchive + PYZ) | parses supported cookies and entries; coverage depends on container version |
| Cython `.so` / ELF payloads | extracts supported metadata and embedded payloads; native machine code is not decompiled to equivalent Python |
| PyArmor-shaped 8/9 format | key-dependent decryption path; current end-to-end test uses a synthetic fixture and does not establish compatibility with vendor-produced builds |
| Hyperion | recovers the `__code__` program |
| pyobfuscate.com (paid tier) | base85 → PBKDF2-SHA256 ×1e6 → AES-GCM, decrypted offline |
| string tables + rotation | rotation replayed, accessors resolved, decoders folded |
| MBA / opaque predicates / CFF / unicode aliases / dynamic builtins | rewritten to plain Python |

## Why this exists

Most "deobfuscators" are either a pile of regexes for one family, or a wrapper
that `exec`s the sample inside a container and hopes for the best. pydecomp takes
the third road: it **models the bytecode**. It parses the sample as text, walks
`marshal` images with its own reader, disassembles and lifts opcodes up to
statements, folds constants, evaluates pure expressions in a private namespace,
and demangles the naming schemes the popular obfuscators emit. Nothing from the
sample is ever imported or executed — the only `exec` in the codebase loads
pydecomp's own native sidecar.

The result is a tool that behaves the same on your laptop, in CI, in a Docker
container and on a phone: one directory tree, or one file.

## Highlights

| | |
|---|---|
| **Static only** | The sample is data. No `exec`, no `eval`, no subprocess, no import. |
| **Layered** | 25 nesting layers, 32 MiB per layer, cycle-safe. |
| **Both engines** | Text/expression engine for source-level obfuscation, bytecode engine for `marshal`/`pyc`/`compile()` payloads. |
| **Version-aware** | Versioned `marshal` readers and opcode tables; bytecode parsing does not imply complete source lifting or exact reconstruction for every target version. |
| **Runs anywhere** | Pure standard library, single file if you want it, Termux included. |
| **Honest output** | Every recovery is compiled, audited for unbound names, and reported — a file that would not run is caught before it is written. |

## Cleaning may never cost you the program

The last thing that happens before a file is written is a fidelity check: the
cleaned source is compared with the program as it came out of the container.  It
is kept only if it still parses, still holds its definitions, and is not a wall
of literals.  If an upgrade would degrade the result, the unpacked program is
written instead and the tool says so:

```
   fidelity   rolled back to the unpacked program — cleaning lost 3 of 4 definition(s)
```

You lose a little tidiness, never the recovered script.

## Install

```console
$ pip install pydecomp-tool      # the command is still `pydecomp`
```

**Q: is this the `pydecomp` on PyPI?** No — that is an unrelated project. This
repo installs as `pydecomp-tool` (or `pip install
git+https://github.com/idam001/pydecomp.git`); the module and the command are
`pydecomp`.

## Install (from a checkout)

> The PyPI name `pydecomp` is taken by an **unrelated** project, so
> `pip install pydecomp` gives you the wrong tool. Install from Git:

```bash
pip install "git+https://github.com/idam001/pydecomp.git"
pipx install "git+https://github.com/idam001/pydecomp.git"   # isolated CLI
```

From a checkout:

```bash
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
pip install -e ".[dev]"
```

**No pip at all?** Build the single file and copy it anywhere:

```bash
python3 tools/build_single.py           # -> dist/pydecomp.py (~273 KB)
scp dist/pydecomp.py phone:/sdcard/     # Termux guide: docs/termux.md
```

Requires CPython 3.9 or newer. Nothing else. The single-file build carries the
whole package — including the native/ELF sidecar — inside one compressed blob.

## Quick start

```bash
pydecomp sample.py                       # recover next to the input
pydecomp sample.py -o out/               # choose the output folder
pydecomp sample.py --reports             # also write .report.json and .report.md
pydecomp sample.py --no-anim --no-color  # plain text for CI
pydecomp --selftest                      # check the install
```

Interactive menu (no arguments):

```bash
$ pydecomp
  [1]  deobfuscate a script       peel every layer  ·  save one file
  [2]  Cython module (.so)        rebuild the source from a compiled module
  [3]  ELF binary                 hunt for Python payloads inside a binary
```

Python API:

```python
import pydecomp

result = pydecomp.dig(open("sample.py", "rb").read(), "sample.py")
print(result.text)          # recovered source
print(result.stages)        # [Stage(1, "base64", "zlib", 1204), ...]

pydecomp.peel("sample.py", out_dir="out")   # CLI-equivalent, returns paths
```

## What it recovers

The engine is a pipeline, and every stage reports what it did:

1. **Sniff** — text, `marshal` image, `pyc`, zip, or ELF.
2. **Unwrap** — base64 / base85 / base32 / hex / emoji / raw-zlib / gzip /
   bz2 / lzma / zip, recursively, in any order, up to 25 layers.
3. **Decompile** — `marshal` → code object → opcode walk → AST → source, with
   a table of opcodes for the *declared* version, not the running one.
4. **Fold & evaluate** — constant folding, dead-branch removal, and a pure
   expression evaluator with a whitelist (no I/O, no imports outside the
   whitelist) for decoder chains like `''.join(chr(...))`.
5. **Polish** — demangle `lIIllIlI`-style identifiers, undo control-flow
   flattening, and stamp the result with the project signature.
6. **Audit** — compile the result, list unresolved names, keep `_PydecompUnknown`
   where the value is not in the bytecode, `_PydecompUnknown` names the hole.

## Measured results

Measured on the current working tree with CPython 3.13, Linux x86-64. The full
suite passed, but this is not a claim that every host OS or bytecode target has
been tested:

| Check | Result |
|---|---|
| Unit suite | passed |
| Full gate suite | 36/36 passed |
| Identity integration | 50/50 instruction-identical |
| Corpus | 296/296 cases recovered |
| SSA exact-identity coverage | 26/50 cases; the stack backend carries the other 24 |
| Backend matrix | 49 forged cases, 0 failures, 7 carried |
| Stress | 200/200 generated stacks recovered (floor 196) |

Run `python3 tools/run_gates.py` to reproduce the gates and
`python3 tools/ir_coverage.py` to inspect SSA versus fallback coverage. Results
must be refreshed when the corpus, fixtures, or gate definitions change.

## The corpus is the data centre

No claim in this README rests on one lucky file. `corpus/` currently contains
**74 generated families × 4 cases = 296 cases**, each with a `truth.json` that
identifies its expected payload by digest. These are reproducible fixtures, not
74 independently sourced real-world malware samples.

`tools/eval_corpus.py` grades every recovered file: it must compile and retain at
least 90% of the payload's behavior-bearing tokens. Latest measured run on this
working tree:

| | cases | recovered | mean token recall | time |
|---|---|---|---|---|
| all families | 296 | **296** | 98.6% | 9.88 s |

The per-family table is [docs/corpus-results.md](docs/corpus-results.md). Beyond the
named families, `tools/stress_corpus.py` builds **random stacks nobody wrote
down** from the same layer table and grades them the same way. The gate runs
**200 stacks over five seeds, up to twenty-four layers deep**, drawn from all
eighteen reversible codecs the families use — including base58, base62, base45
and z85, whose loaders are counting loops rather than one-line calls, so the
harness generates the same loop a real loader spells out. Each loader is also
dressed in one of thirteen shapes an obfuscator actually ships: bare, inside a
`def`, inside a class method called through an instance, behind a decoy `exec`,
behind `getattr(__import__('builtins'), 'exec')`, behind a dict-dispatch table,
inside a `while True:` driver, behind three hidden spellings of `exec`
(`_b.exec`, a split `getattr`, `sys.modules['builtins']`), and with the loader
*itself* stored as string
chunks or as reversed lines joined at runtime. Latest run: **200/200
recovered**, floor **196**, mean depth 8.0 — and 100/100 on seeds 6 and 7,
which the gate never sees. A case that used to be recovered and stops being
recovered fails the `corpus` gate, so the number can only go up with the code,
never down with the prose.

Five things the corpus forced out of the engine, because a family failed and
the gate would not let it slide:

- **`marshal.loads(_p)` is a payload sink.** A packer that ships a marshalled
  code object rarely calls `exec()` on a literal; it loads it into a name. The
  sink scan now knows the code-loader calls too, and reads the bytes with the
  static marshal reader — 20 more cases recovered.
- **base45 and z85 were wrong.** RFC 9285 puts the high byte of a triple first;
  the decoder read it second, so every base45 payload came out byte-swapped and
  `8U-R3` raised instead of returning `Hello!!`. z85 ran its input through the
  separator stripper, and Z85's alphabet *contains* `.`, `-`, `:`, `+`, `=`, so
  the strip destroyed the encoding. Both fixed against published vectors, with
  `tests/unit/test_codec_vectors.py` holding them down.
- **Loaders are sloppy about base64, and the evaluator refused all three ways.**
  They use the url-safe alphabet and call the plain decoder, call the url-safe
  decoder on plain text, and strip the `=` padding to fit the blob on one line.
  Each one ended a chain that could have been finished; the evaluator now accepts
  the right alphabet either way and restores padding. That alone took the random
  stack run from 85/100 to 97/100.
- **A nested stack is followed to the bottom.** `an_nested_exec` is the
  TrustedSec bytecode stack: a loader inside a marshalled code object, which was
  itself marshalled, three deep. Lifting one level and stopping hands the operator
  stage two and calls it the program. A lifted module that is itself a loader is
  now followed down until the text stops being a loader.
- **A decoded payload that is not Python must not be re-emitted as `exec(b'…')`.**
  Folding a decode into an exec sink produced a file that ran garbage and never
  existed. A refusal now leaves the file as written; the `z_refuse` family holds
  that behaviour in place.

## Learned priors

An unknown blob could start with any of 22 decoders. Trying them in table order
is a guess. `pydecomp.learn` ranks them from features of the bytes alone (size,
entropy, alphabet membership, container magic, quadratic tells), trained on the
corpus by `tools/train_learn.py` — an averaged perceptron in plain Python,
weights committed as integers in `src/pydecomp/learn/weights.py`.

Measured with a **payload held out of training** (`text` never seen), so the
number is generalisation, not memory:

| order | top-1 decoder | decodes before the right one |
|---|---|---|
| registry order | 37.5% | 7.81 |
| learned | **75.0%** | **1.62** |

The ranking is only an *order*: every decoder is still tried, so a wrong guess
costs a decode and never a payload. `learn` gate re-trains from the corpus and
fails if the committed weights stop beating table order, or if the corpus moved
out from under them.

## Where the corpus goes next

Every case that defeats the tool becomes a family. That is the whole method: a
failure is a test, not a paragraph.
## Configuration

| Variable | Meaning |
|---|---|
| `PYDECOMP_MAX_BYTES` | Size ceiling for one layer (default 32 MiB). |
| `PYDECOMP_MAX_LAYERS` | Nesting ceiling (default 25). |
| `NO_COLOR` | Same as `--no-color`. |

No config files, no cache directory, no state. Everything lives in
`src/pydecomp/limits.py`.

## Project layout

```
src/pydecomp/          engine (75 modules + 15 package inits, ~14.2k lines)
  engine/            dig, digest, follow-the-source pipeline
  decoders/          base64/85/32, hex, emoji, zip, compression
  crypto/            stdlib-only RC4, XOR, Blowfish, AES helpers
  eval/              pure expression evaluator + namespace + whitelist
  bytecode/          marshal reader, disassembler, opcodes, lifters, decompiler6
  lift/              module-level rebuild, import repair, hoisting
  polish/            demangle, dead code, folding, control-flow unflattening
  symbolic/          integer domain, proved identity library, executor
  triage/            fingerprints, behaviour hints, risk indicators
  output/            writer, report renderer, signature
  terminal/          banner, panels, colour, animation, menu
  native/            Cython/ELF sidecar (option 2/3 front-end)
tests/               unit, integration gates, benchmarks, fixtures
tools/               build_single, run_gates, gen_opcode_tables, fixtures, release
docs/                mkdocs site (26 pages)
examples/            runnable examples and their expected output
```

## Contributing

Issues with a *sample* are the most useful contribution — see
[CONTRIBUTING.md](CONTRIBUTING.md) and the "new sample" issue template. Please
do not paste live malware; use a hash plus a redacted or defanged snippet.

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Governance](GOVERNANCE.md)
- [Security policy](SECURITY.md) — for vulnerabilities *in pydecomp*
- [Changelog](CHANGELOG.md)
- [Documentation](docs/index.md)

## Legal

pydecomp is a defensive and research tool. Use it on files you own or are
authorised to analyse. The authors do not accept liability for misuse. The
tool never executes the sample; what you do with the recovered code is your
responsibility.

MIT licensed, © 2026 Idam Emmanuel — see [LICENSE](LICENSE).
