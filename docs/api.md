# API

```python
import pydecomp
```

The package re-exports its whole surface (369 symbols) so you rarely need to
import a submodule. Anything not listed here is internal and may move.

## Recover source

### `pydecomp.dig(data, name="sample") -> Artifact`

The engine. Give it bytes; it returns an `Artifact`:

```python
result = pydecomp.dig(open("sample.py", "rb").read(), "sample.py")
result.text      # recovered source, as text
result.kind      # 'source' | 'code' | 'text' | 'data'
result.trace     # ['layer 1: base64 → zlib · 1,204 B', ...]
result.score     # the ranking score of the winning candidate
```

`dig` never raises on malformed input; an unrecoverable blob comes back as the
best-effort text with the trace explaining where it stopped.

### `pydecomp.peel(source, max_layers=25, on_layer=None) -> (layers, notes)`

The layer-peeling pass on its own: give it the *text* of a sample, get back the
`Layer` objects it found and any notes about layers it deliberately did not
unwrap (a `marshal` payload is never fed to `marshal.loads`).

```python
layers, notes = pydecomp.peel(open("sample.py").read())
for layer in layers:
    print(layer.index, layer.recipe, layer.size)
```

To go from a file to a written recovery, use `dig` plus your own writer, or the
CLI (`pydecomp sample.py`).

## Bytecode

### `pydecomp.parse_pyc(blob) -> (version, code_object)`

Parses a `.pyc` (or a bare `marshal` image) with pydecomp's own reader. `version`
is a tuple like `(3, 13)`; the code object is pydecomp's `CodeObj`, not CPython's.

### `pydecomp.lift_module(module, version) -> str`

Whole-module rebuild. Returns source that starts with the one-line signature
(`#[ Deobfuscated by idam Emmanuel ] only through pydecomp`), then the code.

### `pydecomp.decompile_object(code, version, name, kind, tolerant=False) -> (text, score)`

One function. `score` is the fraction of instructions reproduced; `tolerant`
keeps going past unsupported opcodes instead of failing.

### `pydecomp.MarshalReader`

Low-level reader, useful when you want the object graph without the lifter:

```python
reader = pydecomp.MarshalReader(blob, version=(3, 13))
module = reader.read()
```

## Audit and polish

### `pydecomp.audit_source(text) -> dict`

```python
{"compiles": True, "error": None, "missing": [], "imports": [...]}
```

`missing` lists names the file reads but never defines.

### `pydecomp.polish_source(text, clean=True) -> (text, actions)`

Readability passes (demangling, folding, dead branches, unflattening).
`actions` is a list of human-readable notes about what changed.

### `pydecomp.with_unknown_preamble(text) -> str`

Adds the `_PydecompUnknown` shim to a file that needs it. Idempotent.

### `pydecomp._PydecompUnknown(name)`

The sentinel: callable, subscriptable, iterable, falsy. It exists so an
an unresolved value never turns into `None(...)` and changes behaviour silently.

## Triage

```python
analysis = pydecomp.analyse_recovered(text)   # everything the report needs
analysis["fingerprint"]   # 'single-stage base64 loader', 'pyarmor shape', ...
analysis["imports"]       # ['requests', ...]
analysis["iocs"]          # urls, ips, paths, telegram tokens
analysis["risks"]         # behaviour hints: network, persistence, expiry
analysis["execs"]         # further exec()/compile() sites inside the recovery

pydecomp._fingerprint(text, trace)            # just the family label
```

## Errors

| Exception | When |
|---|---|
| `pydecomp.D6Unsupported` | the structural decompiler met an opcode it has no rule for. The tolerant path usually still returns source, so catch this only when you call `decompile_object(..., tolerant=False)`. |

Everything else fails soft: a truncated `marshal` stream or an unknown container
comes back as best-effort text plus a note in the trace, because analysers are
run against files that are *supposed* to be broken.

## Guarantees

- No function executes, imports or spawns the input.
- No function writes anywhere except the folder you pass.
- `dig` and `lift_module` are deterministic for a given input and version.
