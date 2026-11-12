# Decompiler backends

One decompiler is not best at everything, and 3.15 bytecode is not 3.8 bytecode.
So the decompiler is a slot, and the tool decides which answer to keep **by
evidence**.

```console
>>> from pydecomp.bytecode.backends import route, candidates
>>> route((3, 9))
['decompyle3', 'pydecomp.lift']
>>> [b.name for b in candidates((3, 15))]        # what this machine can run
['pydecomp.lift']
```

## The routes

| version | order |
|---|---|
| 1.0 – 3.8 | `uncompyle6` → `decompyle3` → `pydecomp.lift` |
| 3.9 – 3.10 | `decompyle3` → `pydecomp.lift` |
| 3.11 – 3.13 | `pydecomp.lift` → `pycdc-rs` → `depyo` → `pycdc` |
| 3.14 – 3.15 | `pycdc-rs` → `depyo` → `pydecomp.lift` → `pycdc` |

`route()` is pure and testable. `candidates()` drops everything this machine
cannot run. **A missing backend is never an error**: it is simply not a
candidate, and the single-file build on a phone behaves exactly as before.

## Selecting an answer

Every candidate's text is graded against the *original code object* with the same
comparator the proof uses. The strongest tier wins; ties go to the longer text,
then to route order. A backend that produces pretty but wrong source loses to one
that reproduces the instructions.

The decision is recorded in `pydecomp.bytecode.backends.LAST` and in the proof:

```json
{"depth": 3, "transform": "lift to source", "backend": "pycdc-rs",
 "verified": true, "target": "CPython 3.15"}
```

## Writing one

```python
from pydecomp.bytecode.backends.base import Backend

class MyBackend(Backend):
    name = "mine"
    kind = "external"
    versions = ((3, 11), (3, 15))

    def available(self):
        return True                      # or check for the tool/package

    def decompile(self, data, version):
        return some_text_or_None
```

Register it in `orchestrator.pool()`; `route()` decides when it is tried. If it
raises, the orchestrator moves on — a backend may fail, a run may not.

External backends are invoked statically: the sample's bytes are written to a
temporary `.pyc` and a decompiler reads them. The sample is never imported or
executed, which is the one line this project does not cross.
