# Plugins

A decoder is `(bytes) -> bytes | None`. Register it and the engine will try it
when no built-in chain opens a blob.

```python
from pydecomp.plugins import register_decoder

@register_decoder("rot47", priority=10)
def rot47(blob: bytes):
    return bytes(33 + ((byte - 33 + 47) % 94) for byte in blob)
```

Ship it as a package instead of a patch:

```toml
[project.entry-points."pydecomp.decoders"]
rot47 = "my_pkg.decoder:rot47"
```

`pydecomp.plugins.load_plugins()` imports the group once per process and lists
the plugins that failed to load in `load_plugins.errors`.

## Rules that make this safe inside a recovery

* a plugin that raises is skipped, and the run continues;
* a plugin that returns its input unchanged is ignored (an infinite loop is worse
  than a miss);
* the registry is capped at 64 decoders;
* plugins receive **bytes**, never a live interpreter. Nothing here can execute
  a sample, so the no-execution guarantee survives third-party code.

```console
>>> from pydecomp.plugins import summary
>>> summary()
'1 decoder(s): rot47'
```

## An external decompiler as an optional method (PyLingual)

pydecomp keeps one non-negotiable promise: nothing in the package spawns a
process, imports a sample, or uploads one. A second decompiler would break that,
so PyLingual is supported **out of process, by you**:

```console
$ pydecomp sample.pyc --pylingual        # prints the command; runs nothing
$ pydecomp sample.pyc --pylingual-import out/sample.py -o out
```

The plan pins every model cache offline (`UV_OFFLINE`, `HF_HUB_OFFLINE`,
`PIP_NO_INDEX`, `TRANSFORMERS_OFFLINE`, `HF_DATASETS_OFFLINE`), passes one local
`.pyc` path, and says `uploads: none`. The import bounds the file, runs a
**compile-only** check, writes `sample_pylingual.py` with the same one-line
provenance stamp, and diffs it per function against pydecomp's own answer
(`triage/methods.py`).

Why an out-of-process method rather than a bundled backend: PyLingual needs a
model runtime and an interpreter matched to the target version, and its accuracy
varies by version and sample. Handing pydecomp's guarantee to that dependency
would make the guarantee conditional. This way the comparison is available, the
guarantee is unchanged, and the analyst sees both answers instead of trusting
one.

## Comparing methods

| method | how you get it | what it is |
|---|---|---|
| `ssa-ir` | default | SSA-built IR, emitted and graded against the original code object |
| `stack` | automatic fallback, or `--legacy` | statement-by-statement lifter, no SSA |
| `pylingual` | `--pylingual` plan, `--pylingual-import` | external model-based decompiler, run by the analyst |

The run reports the first two in `"methods"` (JSON/Markdown/HTML), and any two
recovered files can be compared — across a rebuild, a legacy run, or an imported
method — with `--compare-with`, which reports functions added/removed/changed,
indicator deltas, and a unified diff.
