# FAQ

## Does pydecomp run the sample?

No. Nothing in the package executes, imports or spawns the sample — the single
`exec` in the codebase loads pydecomp's own compressed sidecar, and the audit only
`compile()`s text pydecomp itself produced. `tools/check_static_only.py` enforces
this in CI and is part of the unit suite.

## Why is the output not identical to the original?

Because bytecode does not contain comments, formatting, or most names. What
pydecomp guarantees is different: the recovered file must **compile, be
instruction-identical where possible, and never silently change meaning**.
The console panel and the `--reports` audit tell you which of those it achieved.

## What is `_PydecompUnknown`?

A sentinel for a value that could not be resolved statically. It is callable,
subscriptable, iterable and falsy, so a half-known expression produces readable
source instead of crashing:

```python
token = _PydecompUnknown("token")
url = "https://api.example/" + str(token(1)["key"])
```

If you see it, the audit will also list the name in `missing`. That is the tool
being honest, not failing.

## Why only one output file?

Because the common failure mode of analysis tooling is drowning you in artefacts.
`--reports` adds the JSON and Markdown reports when you want them. The invariant
is a test (`test_v5`), not a preference.

## It stopped after N layers. Why?

Either the ceiling (25), the per-layer size ceiling (32 MiB), a cycle, or nothing
scored better. The panel and the report say which. Raise the ceilings with
`PYDECOMP_MAX_LAYERS` / `PYDECOMP_MAX_BYTES` if you know the sample is legitimate
and just deep.

## It says "degraded payload". Is the output usable?

Usually yes: statements are trustworthy, control-flow frames are approximated
and unplaced statements appear as `# comments` with their opcode offsets. The
alternative — pretending a 40% rebuild is complete — is worse. Check the round
trip percentage in the preamble.

## Can it handle `pyarmor`, `pyinstaller`, `nuitka`?

- **pyarmor**: shapes are recognised and reported; the runtime-protected parts
  are not recoverable statically (that is the point of the tool).
- **pyinstaller**: yes for the embedded `marshal` payload, once you get the
  `PYZ` entry out; pydecomp carves it from a binary in `--elf` mode.
- **nuitka**: compiled to C. Only strings and structural hints come back.

## Can it decompile a `.so` back to Python?

For Cython modules, yes — up to tier S when the generated `.c` is available
(byte-exact), tier B from DWARF line tables, tier A from method tables and
docstrings. It does not decompile machine code into C.

## Why is the single file smaller than the old monolith?

The package is ~14,200 lines across 90 files; the single file stores them
zlib-compressed and base85-encoded, then serves them through an import hook.
~199 KB instead of ~508 KB of readable source, with identical behaviour.

## Does it need the interpreter version of the sample?

No. pydecomp carries its own marshal reader and opcode tables for CPython
3.9 → 3.14, so a 3.9 `.pyc` decompiles on 3.13.

## Windows?

The engine is platform-neutral; the CLI prints the same box-drawing panels in
Windows Terminal. `--no-color` for legacy consoles.

## How do I report a sample it mishandles?

Open a **new sample** issue with the sha256, the size, the layer order you know,
and what pydecomp produced. Do not attach live malware — a defanged excerpt or a
synthetic reproducer is better and becomes a fixture.

## Is this legal?

Analysing files you own or are authorised to analyse is ordinarily fine; the
rules differ by jurisdiction. pydecomp does not execute anything, and the authors
accept no liability for misuse. See [LICENSE](https://github.com/pydecomp/pydecomp/blob/main/LICENSE).
