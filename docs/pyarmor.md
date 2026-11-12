# PyArmor 8/9: static unpack

PyArmor replaces a module with a bootstrap that hands a blob to a native runtime:

```python
# Pyarmor 9.0.0 (trial), 000000, non-profits, 2026-11-01T00:00:00
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\r\x00…')
```

The blob is `PY` + six digits, a packed header, and AES-CTR ciphertext that
contains a **marshal stream of code objects**. The key lives in
`pyarmor_runtime_*.so/.pyd` — which a real build always ships beside the script.

## What pydecomp does

1. **Parse the header** with bounds checks: tag, serial, interpreter version
   (bytes `0x09`/`0x0A`), protection byte (`0x14`: `0x09` = BCC), 12-byte
   nonce (`0x2C`).
2. **Find the runtime by itself.** `--pyarmor-runtime` wins; otherwise the
   sibling `pyarmor_runtime_*` file or directory is used. On a phone the run
   prints which library it used — you are never told to go and find it.
3. **Hunt the key**: 32-character hex strings and high-entropy 16-byte windows
   carved from the runtime, plus any key you pass with `--pyarmor-key`.
4. **Accept a candidate only when the decryption proves itself.** AES-CTR output
   must parse as a marshal stream containing a code object. A wrong key cannot
   pass that test, so a hit is evidence rather than a guess:

   ```
   static unpack: 1 code object(s) recovered · key 11223344… verified by
   marshal structure · CPython 3.13 · carved from the runtime · 1 candidate(s) tried
   ```
5. **Lift** the recovered code objects with the bundled decompiler and **prove**
   the result — the fixture in `tests/fixtures/pyarmor_case.py` comes out at
   `tier semantic` (3/3 units instruction-identical).

Mixed strings (`b'\x81' + ciphertext`) are decrypted with the same key and nonce.

## Usage

```console
$ pydecomp dist/worker.py                 # runtime found beside the sample
$ pydecomp worker.py --pyarmor-runtime /path/pyarmor_runtime.so
$ pydecomp worker.py --pyarmor-key 11223344556677889900aabbccddeeff
```

## Boundaries, stated once

* **PyArmor 8 and 9** — unpacked. The payload is an AES-CTR stream, and this
  release recovers it without executing anything.
* **PyArmor 7 and earlier** (`PYARMOR` header) — the payload is encoded by the
  runtime's own scheme, not this blob layout. The tool emits the bootstrap, the
  build banner and every carved string, and says exactly that.
* **BCC mode** (functions compiled to C) — the header flag is reported; those
  functions have no Python bytecode to lift, and the proof says so instead of
  silently emitting a stub.
* **A runtime where no carved candidate verifies** — the run reports how many
  candidates it tried and asks for `--pyarmor-key`, which is the one piece of
  information that is not in the file.

## The fixture

`tests/fixtures/pyarmor_case.py` builds a `PY`-tagged blob from first
principles — header, AES-128-CTR over a marshalled code object, a runtime
stand-in carrying the key where a real one does — so the whole path is tested
against known bytes with a known answer. See `tests/integration/test_pyarmor.py`
for the end-to-end gate.
