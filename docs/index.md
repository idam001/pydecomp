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
| know what it cannot do | [FAQ](faq.md) · [Roadmap](roadmap.md) |

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
   [•] Owner   : [Idam Emmanuel]   [•] Version : [8.1.0]
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
   reported. Where a value cannot be known, `_PydecompUnknown` appears and the
   runnability report says so.

## Numbers

Run `python3 tools/run_gates.py` on a checkout — ten gates, all green on
CPython 3.13/Linux in under ten seconds:

| Gate | Result |
|---|---|
| classic packing cases | 20/20 |
| CLI contract | 26/26 |
| fallbacks and round trip | all good |
| menu and prompts | all good |
| polish passes | 44/44 |
| instruction-identical round trips | 47/47 |
| obfuscator probes | 37/37 |
| native (Cython/ELF) | 41/41 |
| hardest-obfuscation benchmark | 33/44 semantic · 11/11 rebuilt as source |
| worked examples | 6/6 recovered |

## Licence

MIT. See [LICENSE](https://github.com/pydecomp/pydecomp/blob/main/LICENSE).
