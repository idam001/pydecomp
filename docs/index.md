# pydecomp

**Static Python deobfuscator.** Recover readable source from packed, encoded,
mangled or partly-compiled Python — without executing the sample.

```
$ pydecomp suspicious.py
   ▸ stage 1   layer 1: base64 → zlib · 1,204 B
   ▸ stage 2   layer 2: marshal → code object · 12,884 B
   ▸ writing output   suspicious_deob.py
   ▸ verifying   sha256 9f2c1ab0…
```

## Start here

| I want to… | Page |
|---|---|
| install it in 30 seconds | [Install](install.md) |
| run it on a file right now | [Quick start](quickstart.md) |
| know every flag | [CLI reference](cli.md) |
| understand how it works | [Architecture](architecture.md) |
| call it from Python | [API](api.md) |
| analyse a `.so` or an ELF | [Native and ELF](native.md) |
| extend it | [Development](development.md) |
| know what it recovers | [FAQ](faq.md) · [Roadmap](roadmap.md) |

## The board

```
   ꧁✿❀✿꧂─────────────────────────────────────────────────────────────꧁✿❀✿꧂
   ████  █   █ ████  █████  ████  ███  █   █ ████
   █   █ █   █ █   █ █     █     █   █ ██ ██ █   █
   ████   ███  █   █ ████  █     █   █ █ █ █ ████
   █       █   █   █ █     █     █   █ █   █ █
   █       █   ████  █████  ████  ███  █   █ █
   ꧁✿❀✿꧂─────────────────────────────────────────────────────────────꧁✿❀✿꧂
                    WELCOME TO IDAM EMMANUEL TOOLS
   [ NETWORK ] : <detected offline>      [ COUNTRY ] : <from the timezone>
   [•] Owner   : [Idam Emmanuel]   [•] Version : [1.0.0]
```

Every recovered file opens with one line and nothing else:

```python
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

## The three promises

1. **The sample is data, never code.** No `exec`, no `eval`, no import, no
   subprocess — enforced by a scanner in CI, not by good intentions.
2. **One file in, one file out.** Unless you ask for `--reports`.
3. **Honest output.** Every recovery is compiled, audited for unbound names and
   reported. Where a value is not in the bytecode, `_PydecompUnknown` names the
   runnability report says so.

## Measured checks

On the current CPython 3.13/Linux working tree, the unit suite passed and all
36/36 gates were green. The identity integration was 50/50 and the recovery
corpus was 296/296. The SSA engine alone matched exact instruction records for
26/50 cases; the stack engine handled the remaining 24. These results describe
that checkout and interpreter, not every supported bytecode target or host OS.
Run `python3 tools/run_gates.py` to reproduce the gates.

## Licence

MIT. See [LICENSE](https://github.com/idam001/pydecomp/blob/main/LICENSE).
