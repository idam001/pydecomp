# CLI reference

```
pydecomp [PATH] [options]
```

With no path, pydecomp opens the interactive menu. With a path, it analyses that
file and writes one output file (plus reports when asked).

## Options

| Option | Default | Meaning |
|---|---|---|
| `PATH` | — | File to analyse. `.py`, `.pyc`, `.so`, ELF, or any opaque blob. |
| `-o, --out DIR` | next to the input | Output folder. Created if missing. |
| `--reports` | off | Also write `.report.json` / `.report.md` - now including per-function tiers, the recovery-method table and the hints. Without it, **exactly one file** is written. |
| `--no-color` | auto | Disable ANSI colour. Also honoured by `NO_COLOR`. |
| `--no-anim` | auto | Disable spinner and staged printing. Automatically on when stdout is not a tty. |
| `--native` | auto | Force the Cython/native front-end (option 2). |
| `--elf` | auto | Force the ELF payload front-end (option 3). |
| `--mode MODE` | `auto` | `auto`, `cython`, `elf` or `script`. |
| `--legacy` | off | Use the stack engine alone and skip the SSA pipeline. |
| `--html` | off | Also write a self-contained `.report.html`: source, proof, per-function confidence, methods, indicators and hints. Opens offline. |
| `--recipe` | off | Write a path-free `.recipe.json`: input/output hashes and the ordered recovery steps. |
| `--source-map` | off | Write `<stem>.sourcemap.json`: every recovered definition with its line span and proof tier. |
| `--target-versions 3.9,3.10` | — | Compile-only syntax check of the recovered output for each target (see below). |
| `--offline` | off | Refuse network-capable options (`--fetch-iocs`); everything else still runs. |
| `--disassemble` | off | For a `.pyc`: write `<stem>.dis.txt`, a bounded instruction dump with constants and children. Static: nothing is executed. |
| `--pylingual` | off | Print the exact offline command to run a local PyLingual on this `.pyc`. Nothing is executed. |
| `--pylingual-import FILE` | — | Adopt PyLingual's output: compile-checked, then diffed per function against pydecomp's own answer. |
| `--compare-with PATH` | — | Static diff between this source and another recovered file: functions, indicators, unified diff. |
| `--selftest` | — | Check the install end to end. |
| `--version` | — | Print the version. |
| `-h, --help` | — | Usage. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Recovered something and wrote it. |
| 1 | Nothing recoverable (empty file, unknown container, or an error while writing). |
| 2 | Usage error (bad flag, missing path), or `--target-versions` could not judge a target. |
| 4 | `--check-proof` found drift, or `--target-versions` found syntax that target rejects. |

CI-friendly: `pydecomp sample.py --no-anim --no-color || echo "not recoverable"`.

## What gets written

```
out/
  sample_deob.py            # the recovery: always
  sample_deob.report.json   # only with --reports
  sample_deob.report.md     # only with --reports
```

Native inputs add their own sidecars, again only with `--reports`:

```
  module_deob.py
  module_report.md
  module_lines.txt
```

## Confidence, methods, and what to try next

Every recovery already carried a proof — tier per unit, layers, guarantee. Three
additions put that where an analyst reads it:

**Per-function confidence.** `--reports`, `--html` and the console now list each
definition with its own tier, so a module that is `semantic` overall no longer
hides the one function that is only `syntactic`:

```console
$ pydecomp sample.py --html -o out
units      6 definition(s); weakest here: decode_loop, _stub
```

**Recovery-method comparison.** The run reports which engine answered — the SSA
emitter or the statement lifter — with the tier each earned:

```json
"methods": [{"method": "ssa-ir", "tier": "semantic", "chosen": true, "detail": "emitted"}]
```

To compare against a *different* method, `--legacy` produces the stack engine's
answer for the same sample, and `--compare-with` (or `--pylingual-import`) diffs
two recovered files per function and per indicator:

```console
$ pydecomp sample_deob.py --compare-with legacy/sample_deob.py
pydecomp vs legacy/sample_deob.py: same definitions, 2 with a different body
  functions changed: decode, main
  url added: https://c2.example/gate
```

**Hints.** When a construct stops the lifter, the run says what to try instead —
`--legacy`, `--disassemble`, or reading the names table — and the same list goes
into the JSON, Markdown and HTML reports under *what to try next*. Hints are
keyed to something the run actually recorded, never invented about a payload.

## Source-to-layer mapping

`--source-map` writes `<stem>.sourcemap.json`: every definition in the recovered
output with its line span, its proof tier, and the run's whole-module stage list.

```json
{"schema": "pydecomp-source-map-v1",
 "definitions": [{"name": "decode", "kind": "FunctionDef", "start_line": 4,
                  "end_line": 11, "proof_tier": "semantic"}],
 "recovery_stages": ["base64 → zlib · 12 B", "no further text layer → lifting bytecode"],
 "attribution_note": "definition spans refer to recovered output lines; the stage list is whole-module provenance, not a guessed per-line original offset"}
```

The line spans are real — they are `ast` line numbers in the file just written.
The stage list is per module, and the file says so: claiming a per-line original
byte offset would be a guess dressed as evidence.

## Target-version syntax checks

`--target-versions 3.9,3.10` answers "does this output still parse as that
version?" without needing that interpreter installed, and without executing
anything:

| target | how it is checked | `precision` |
|---|---|---|
| the running interpreter | `compile(text, ..., "exec")` — full compile, never run | `compile` |
| 3.7 up to the running version | `ast.parse(..., feature_version=)` — grammar only | `grammar` |
| newer than the running interpreter | reported `unavailable` | — |

Compilation **is not execution**: `compile()` builds a code object and stops. A
syntax the target does not have is reported `invalid` with the line, and the
command exits 4. A target this interpreter is too old to judge is reported
`unavailable` (exit 2) rather than guessed.

## Bytecode without running it

```console
$ pydecomp suspicious.pyc --disassemble
wrote suspicious.dis.txt
```

The dump names the version, every code object, its names, and every instruction
with its rendered operand — read by pydecomp's own bounded marshal reader, with
a code-object and instruction cap. It is the same view the lifter had, so when a
recovery stops short the analyst can see the instruction it stopped on.

## An external decompiler, without weakening the guarantee

pydecomp does not ship a second decompiler and does not shell out. PyLingual is
strong on CPython bytecode, so it is supported as an **optional method run by the
analyst**:

```console
$ pydecomp sample.pyc --pylingual
{"argv": ["pylingual", "--out-dir", "/lab/out/pylingual", "--version", "3.11", "/lab/sample.pyc"],
 "env": {"UV_OFFLINE": "1", "HF_HUB_OFFLINE": "1", ...}, "shell": false,
 "uploads": "none - the command reads one local .pyc and writes to a local folder", ...}
```

Copy that command into your own shell (the environment pins every cache offline),
then adopt the result:

```console
$ pydecomp sample.pyc --pylingual-import out/pylingual/sample.py -o out
compile-only check passed; the sample and the output were not executed
wrote out/sample_pylingual.py
pydecomp vs sample_pylingual.py: same definitions, 1 with a different body
  functions changed: main
```

The import is bounded, compile-checked, stamped with the same one-line
provenance, and diffed against pydecomp's own answer — so the two methods are
compared, not merged on trust. PyLingual's accuracy varies by version and sample;
the compile check says the text is valid Python, never that it is faithful.

## Archive and path limits

Archives are read with ceilings, because a `zip` bomb is a hostile sample too:

| limit | value | where |
|---|---|---|
| members inspected | 512 | `containers/base.py`, `engine/dig.py` |
| one expanded member | 32 MiB | both |
| total expanded per archive | 128 MiB | both |
| disassembly input / output | 64 MiB | `bytecode/dump.py` |
| PyLingual hand-off / import | 64 MiB | `plugins/backends/pylingual.py` |
| source comparison input | 64 MiB each | `triage/compare.py` |

Members are read through `Archive.open()` with a bounded reader — the declared
size is checked *and* the read is capped — so a lying header cannot expand past
the limit.

## Semantics worth knowing

**One file by default.** The single output invariant is tested by
`tests/integration/test_v5.py` — a recovery that scatters files into the output
folder is treated as a bug.

**The signature line is stable.** Every recovered file starts with exactly one
comment line and nothing else:

```
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

Everything the old multi-line header carried — hash, fingerprint, peeled
layers, imports, behaviour, indicators — now goes to `--reports` and to the
console panel, so the recovery reads like source instead of a lab report.

**Recovered text is never executed.** The audit compiles it to check that it
parses; nothing more.

**Reports are additive.** Turning them off never changes the recovered source.

## Interactive menu

```
  [1]  deobfuscate a script       peel every layer  ·  save one file
  [2]  Cython module (.so)        rebuild the source from a compiled module
  [3]  ELF binary                 hunt for Python payloads inside a binary
  [q]  quit
```

Option 1 auto-detects the rest: a `.so` picked from option 1 is routed to the
native front-end, because the menu is a convenience, not a mode switch.

## Environment

| Variable | Effect |
|---|---|
| `PYDECOMP_MAX_BYTES` | Ceiling for one decompressed layer (default 33,554,432). |
| `PYDECOMP_MAX_LAYERS` | Nesting ceiling (default 25). |
| `NO_COLOR` | Same as `--no-color`. |
| `TERM=dumb` | Disables animation. |
| `PYDECOMP_AUTHOR` | Name shown on the board and in the panel. |
| `PYDECOMP_NETWORK` | Overrides the detected network (e.g. `MTN NG`, `WLAN0`). |
| `PYDECOMP_COUNTRY` | Overrides the detected country. |
| `PYDECOMP_SIGNATURE` | Replaces the one-line stamp on recovered files. |

### The board

With no arguments the CLI prints the banner: the block logo, the author's
welcome band, the host's network and country, and the identity card.

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

The network and country are read **offline**: interface names from
`/sys/class/net`, the country from the timezone (`/etc/timezone`, `TZ`, or the
`/etc/localtime` link). No socket is opened, so the board works in an
air-gapped lab and on Termux.

## Examples

```bash
# a single packed script
pydecomp packed.py

# a compiled module, with reports
pydecomp module.so --reports -o analysis/

# an ELF with an appended payload
pydecomp binary --elf -o analysis/

# batch, quiet, and keep going
for f in samples/*.py; do pydecomp "$f" -o out --no-anim --no-color; done
```
