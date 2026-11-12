# pydecomp

**Python deobfuscator and decompiler.** Unpacks PyArmor 8/9, PyInstaller,
Nuitka, cx_Freeze, py2exe, PEX, shiv, briefcase, Cython, marshal, `.pyc`
1.0–3.15, and Base64/zlib/XOR/emoji chains — statically, on your machine.

**Every output ships with a machine-checkable proof. pydecomp refuses to write
source it cannot verify.**  By [Idam Emmanuel](https://github.com/idam001).

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
| **semantic** | recompiles to the *same instruction stream* as the original | plain source |
| **structural** | same control-flow shape and constant table, encoding differs | `--annotate` marks it |
| **syntactic** | it compiles; equivalence not proven | `--annotate` marks it |
| **unverified** | it does not compile; kept because dropping it loses code | `--annotate` marks it |

```console
$ pydecomp worker.py          # a real PyArmor 9 payload, runtime beside it
   runtime   ~/case/pyarmor_runtime_000000/pyarmor_runtime.so  (used for the runtime key)
   ▸ stage 5   PyArmor 8+ blob · serial 000000 · CPython 3.13 · AES-CTR across the code objects
   ▸ stage 6   static unpack: 1 code object(s) recovered · key 11223344… verified by marshal structure
   fidelity   output verified: still the recovered program
   proof      proven 3/3 units (100%) · tier semantic
```

`--strict` writes **nothing** unless every unit is instruction-identical, and
exits `3`. It is the only Python recovery tool that will refuse its own output.

## What it handles

| | |
|---|---|
| **Protectors** | PyArmor 8/9 **static unpack** (header parse → key hunt in `pyarmor_runtime` → AES-CTR → marshal → lift, key accepted only when the plaintext parses), PyArmor 7 detect-only, Hyperion, pyobfuscate.com |
| **Freezers** | PyInstaller CArchive + PYZ (2.0 and 2.1+ cookies, stripped `.pyc` headers rebuilt), cx_Freeze, py2exe, PEX, shiv, briefcase |
| **Bytecode** | CPython 3.8–3.15 by table, `.pyc` 1.0–3.15 sniffed, PyPy lifted with the closest table (marked *approximate*) |
| **Interpreters** | CPython, PyPy, MicroPython `.mpy`, Jython, IronPython, Brython — named by signature, never guessed |
| **Obfuscators** | 21 named schemes with their contract (marker or shape), then the generic peeler |
| **Backends** | the bundled lifter, plus `pycdc-rs`, `pycdc`, `depyo`, `uncompyle6`, `decompyle3` when installed — chosen by proof tier, not by order |
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

## Named packers it reconstructs

| Container | What pydecomp does, statically |
| --- | --- |
| base64 / zlib / bz2 / lzma / hex / base85 / z85 / base58 / base45 / base91 / uu chains | peels 64 layers, 12 chains |
| marshal / `.pyc` (`3.9 → 3.14`) | own marshal reader + lifter |
| PyInstaller (CArchive + PYZ) | cookie → TOC → entries → PYZ → modules |
| Cython `.so` / ELF payloads | tier-S exact / structural |
| PyArmor 8–9 | bootstrap + build banner + carved payload strings, with an honest "the code objects stay encrypted" |
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
| **Version-aware** | Own `marshal` reader and opcode tables for CPython 3.9 → 3.14, without needing that interpreter installed. |
| **Runs anywhere** | Pure standard library, single file if you want it, Termux included. |
| **Honest output** | Every recovery is compiled, audited for unbound names, and reported — a file that cannot run is never sold as success. |

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
$ pip install "pydecomp-tool[backends]"   # + pycdc-rs / depyo if you have them
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
   where a value genuinely cannot be known.

## Measured results

Run on this checkout (`python3 tools/run_gates.py`), CPython 3.13, Linux x86-64 —
26 gates, plus 249 unit tests:

| Gate | Result |
|---|---|
| `test_v4` — classic packing cases | 20/20 |
| `test_v5` — CLI, output layout, static-only | 26/26 |
| `test_v6` — policy chatter, fallbacks, round trip | all good |
| `test_v7` — menu and prompts | all good |
| `test_v8` — polish, folding, demangling | 44/44 |
| `test_identity` — instruction-identical round trips | 47/47 |
| `test_probes` — obfuscator shapes | 37/37 |
| `test_native` — Cython/ELF recovery | 41/41 |
| `test_proof` — proof schema, `--strict` exit codes | all good |
| `test_pyarmor` — PyArmor 8/9 static unpack, CLI | all good |
| `test_freezers` — six freezers + PyInstaller PYZ | all good |
| `test_agents` — MCP handshake/tools, plugins, cross-impl | all good |
| `obf_bench` — hardest-obfuscation suite | 33/44 semantic · 11/11 rebuilt as source |
| `bench_core` — peel/decompile/AES budgets | 3/3 budgets met |
| `examples` — the six worked examples | 6/6 recovered |

Real samples (byte-for-byte stable across releases):

| Sample | Input | Output | Time |
|---|---|---|---|
| `All-nasa-hacker.py` | 2,499 B | 5,386 B | 0.03 s |
| `Kamrul.py` | 647,813 B | 42,246 B | 0.47 s |
| `Old.py` | 1,136,184 B | 723,362 B | 3.55 s |

## Honest limits

pydecomp is not magic, and the report tells you where it stopped:

- **`exec`-at-runtime construction** — code assembled at run time from data
  that only exists on the attacker's server cannot be recovered statically.
  pydecomp gives you the decoder, not the payload.
- **Native code** — the ELF path recovers Cython-style stubs and Python
  payloads *appended* to a binary. It does not decompile machine code into C.
- **Opaque predicates over external state** — a branch that depends on
  `time.time()` or a network reply is folded only when the value is provable.
- **`_PydecompUnknown`** — where a name cannot be bound, the sentinel appears in
  the output and in the runnability report. That is deliberate: a file that
  silently changes meaning is worse than a file that says "unknown here".
- **PyArmor 7 and earlier** — the `PYARMOR` header predates the AES-CTR blob
  layout entirely: the runtime encodes the payload with its own scheme, so what
  exists in the file is the bootstrap and carved strings. 8/9 are unpacked.
- **Cross-implementation lifts** — PyPy/MicroPython/Jython/IronPython bytes are
  named by signature; a PyPy lift is marked *approximate* in the proof because
  it is not instruction-verified against that interpreter.

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
  triage/            fingerprints, behaviour hints, risk indicators
  output/            writer, report renderer, signature
  terminal/          banner, panels, colour, animation, menu
  native/            Cython/ELF sidecar (option 2/3 front-end)
tests/               unit, integration gates, benchmarks, fixtures
tools/               build_single, run_gates, gen_opcode_tables, fixtures, release
docs/                mkdocs site (13 pages)
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
