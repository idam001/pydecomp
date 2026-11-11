# Quick start

## One file

```bash
pydecomp suspicious.py
```

You get `suspicious_deob.py` next to the input and a panel telling you what
happened:

```
   ╭─ DONE ─────────────────────────────────────────────────────────────╮
   │ source    suspicious.py   2,499 bytes                              │
   │ result    lifted from bytecode   3 stages                          │
   │ fingerprint identifier-mangling obfuscator (Mr.X / pyobfus style)  │
   │ output    suspicious_deob.py   5,386 bytes                         │
   │ behaviour persistence, expiry                                      │
   │ saved to  /home/you/suspicious_deob.py                             │
   │ elapsed   0.03s                                                    │
   ╰────────────────────────────────────────────────────────────────────╯
```

Read those fields as a contract:

| Field | Means |
|---|---|
| `result` | `python source` (text recovered), `lifted from bytecode` (decompiled), or `data` (decoded payload only) |
| stages | how many layers were peeled, in order |
| fingerprint | best guess at the family, with the signals behind it |
| behaviour | indicators found in the recovered text (persistence, network, expiry…) |
| output | the single file written |

## Choose the output folder

```bash
pydecomp suspicious.py -o out/
```

## Ask for the reports too

```bash
pydecomp suspicious.py --reports
```

Writes `suspicious_deob.py`, `suspicious_deob.report.json` and
`…report.md`. The audit answers: does it compile, which names are unbound,
which stage produced which bytes.

## Keep it quiet for CI

```bash
pydecomp suspicious.py --no-anim --no-color
```

Exit codes: `0` recovered and written, `1` nothing recoverable, `2` usage
error.

## Nested layers

```
$ pydecomp dropper.py
   ▸ stage 1   layer 1: base64 → gzip · 3,204 B
   ▸ stage 2   layer 2: gzip → zip · 8,912 B
   ▸ stage 3   layer 3: zip entry payload.pyc · 12,204 B
   ▸ stage 4   layer 4: marshal → code object · 18,004 B
```

Each line is one unwrap. pydecomp keeps going until the payload stops changing,
up to 25 layers, and stops on a cycle instead of spinning.

## Interactive menu

```bash
pydecomp
```

```
  [1]  deobfuscate a script       peel every layer  ·  save one file
  [2]  Cython module (.so)        rebuild the source from a compiled module
  [3]  ELF binary                 hunt for Python payloads inside a binary
```

Paste a path or drag the file into the terminal; quotes are stripped for you.

## A worked example

Take a two-layer dropper:

```python
import base64, zlib
exec(zlib.decompress(base64.b64decode("eJxL...")), )
```

```bash
$ pydecomp dropper.py -o out --reports
$ head -3 out/dropper_deob.py
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
import os
KEY = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
$ python3 -c "import json;print(json.load(open('out/dropper_deob.report.json'))['audit'])"
{'compiles': True, 'missing': []}
```

## Next

- [CLI reference](cli.md) — every flag.
- [Architecture](architecture.md) — why the output looks the way it does.
- [FAQ](faq.md) — when a recovery stops short, and what to send us.
