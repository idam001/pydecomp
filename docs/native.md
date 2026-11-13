# Native and ELF (preview)

Options 2 and 3: a compiled module (`.so`) or a binary with a Python payload
appended to it. This front-end is shipped as a **preview** and is developed at a
slower cadence than option 1.

```bash
pydecomp module.so --native      # Cython-style recovery
pydecomp binary --elf            # hunt for payloads inside an ELF
pydecomp module.so               # auto-detects and picks the right one
```

## Recovery tiers

The analyser reports which tier it managed. Higher is better.

| Tier | Name | How | Fidelity |
|---|---|---|---|
| **S** | source | the generated `.c` sits next to the binary and quotes the original lines (`/* "demo.py":42 */`) | **byte-exact** |
| **B** | line | DWARF `.debug_line` maps addresses to source lines | line numbers, not text |
| **A** | structural | `PyMethodDef` tables, docstrings, class layout, mangled symbol names | every method, real docstrings |
| **C** | carving | strings only | names, literals, URLs |

Tier S is the interesting one: given `demo_module.c` + `demo_module.so`,
pydecomp reconstructs `demo_module.py` **byte for byte**. On the 58-line fixture
it reproduces all 58 lines, which is what the `fixtures` workflow asserts on
every push.

## What comes out

```
analysis/
  demo_module_deob.py        # best rebuilding of the source
  demo_module_report.md      # tier, limits, method table, what was lost
  demo_module_lines.txt      # the address → line dump (tier B and up)
```

## Payload carving from an ELF

For a binary with Python embedded in it, the tier is different: pydecomp looks for
hex and base64 blobs in `.rodata`, zip archives appended after the last section,
and zlib streams holding a `marshal` code tree. Each payload is rebuilt on its
own and audited.

```
$ pydecomp tool --elf -o analysis/
   ▸ payload 1   zip entry payload.pyc → marshal → code object · 18,004 B
   ▸ writing output   analysis/tool_payload1_deob.py
```

The recovered payload is scored like any other recovery: how many instructions
of the original code object it reproduces.

## What this does **not** do

- No machine-code decompilation. Cython's generated C is not recovered from
  registers.
- No DWARF variable recovery beyond line tables.
- No unpacking of a bespoke ELF crypter: if the payload is only assembled in
  memory at run time, which is the value the static carve reports as run-time-only.

## Building the fixtures

```bash
pip install cython
python3 tests/fixtures/native/make_native_fixtures.py
python3 tests/integration/test_native.py       # 41 checks
```

The generator produces four builds of the same 58-line module (plain, `-O0`,
`-g`, stripped) plus hex, base64, zip and zlib/`marshal` carriers — so the gate
covers every tier without shipping a real malicious binary.

## Why it is not in the single file's critical path

The sidecar lives in `pydecomp/native/sidecar.py` and is imported lazily. A phone
running `dist/pydecomp.py` carries it inside the same compressed blob, so option 1
keeps working even if the sidecar is somehow unavailable — the CLI prints an
actionable message instead of a traceback.
