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
| `--reports` | off | Also write `.report.json` and `.report.md`. Without it, **exactly one file** is written. |
| `--no-color` | auto | Disable ANSI colour. Also honoured by `NO_COLOR`. |
| `--no-anim` | auto | Disable spinner and staged printing. Automatically on when stdout is not a tty. |
| `--native` | auto | Force the Cython/native front-end (option 2). |
| `--elf` | auto | Force the ELF payload front-end (option 3). |
| `--mode MODE` | `auto` | `auto`, `cython`, `elf` or `script`. |
| `--selftest` | — | Check the install end to end. |
| `--version` | — | Print the version. |
| `-h, --help` | — | Usage. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Recovered something and wrote it. |
| 1 | Nothing recoverable (empty file, unknown container, or an error while writing). |
| 2 | Usage error (bad flag, missing path). |

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
   [•] Status  : [OPEN SOURCE]
   [•] Version : [8.1.0]
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
