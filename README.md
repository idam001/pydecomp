# pydecomp

**Static Python deobfuscator — by [Idam Emmanuel](https://github.com/idam001).**
Feed it a packed, encoded, mangled or partly-compiled Python file and get
readable source back — without ever running the sample.

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

One file in, one file out. No network, no telemetry, no `exec`.

Every recovered file carries exactly one line above the code, and nothing else:

```python
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

---

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

```bash
pip install pydecomp                 # from PyPI
pipx install pydecomp                # isolated CLI
```

From a checkout:

```bash
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
pip install -e ".[dev]"
```

**No pip at all?** Build the single file and copy it anywhere:

```bash
python3 tools/build_single.py           # -> dist/pydecomp.py (~199 KB)
scp dist/pydecomp.py phone:/sdcard/       # Termux: python3 pydecomp.py sample.py
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
10 gates, 8.8 s, plus 90 unit tests:

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
| `obf_bench` — hardest-obfuscation suite | 33/44 semantic · 11/11 rebuilt as source |
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
