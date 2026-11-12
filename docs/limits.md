# No artificial limits — and the one wall that is real

This page used to list six things pydecomp "cannot do".  Four of those were not
limits at all: they were work nobody had done yet.  This revision does the work,
and leaves only the cases where the information simply is not in the file.

## What changed: the old "cannot" list, re-checked

| old claim | now |
|---|---|
| keys from `os.urandom` / `time` / `input` are unrecoverable | **Recovered.** The key *space* is tiny even when the value is unpredictable. `len(os.urandom(16))` is 16; a byte key is one of 256. `eval/keyhunt.py` infers that space, enumerates it, and accepts a candidate only when the payload it produces parses as Python or marshals into a code object. Measured: correct key found in 0.1 s, and garbage candidates are rejected, never reported. |
| a payload inside a native `.so`/`.pyd` needs reverse engineering | **Carved.** `engine/carve.py` finds a pyc at any offset, a zlib/bz2/gzip/lzma stream, a zip container, or a long base64/base85 literal, validates what it finds, and hands it to the normal digester. A blob of random bytes with a compressed code object inside it now yields the program. |
| `import os` in a loader kills evaluation | **Fixed.** `os` and `os.path` are emulated as names, never capabilities: pure helpers (`path.join`, `path.splitext`, constants) answer exactly, and anything that could touch the machine refuses - which is what marks a value as run-time-only. |
| an unfixable statement aborts the module | **Fixed.** A refused statement (`_k = len(os.urandom(16))`) used to stop the walk, so a payload built further down was never reached. The tolerant pass now continues *and* keeps the captured payload. |

## What is left, and why it is not stubbornness

**A key with a large uniform space.** If a loader derives sixteen random bytes
and uses them as a key, there are 2^128 candidates and no oracle to rank them:
the payload is a *code object*, so any candidate that decrypts "successfully"
is indistinguishable from noise until it runs. Brute force is not slow here, it
is mathematically out of reach. pydecomp reports the expression that creates the
key so the analyst knows exactly what stands in the way - it does not pretend.

**A key held in machine code.** If the licence server hands the key to a native
routine, the Python layer contains ciphertext only. What pydecomp *can* do is
carve everything else in that binary, which it now does.

**Code that was compiled away.** Cython, Nuitka and mypyc can leave no Python
bytecode; there is nothing to lift. Where constants or a marshal blob survive in
the binary, the carve stage finds them.

**A custom VM.** Packers that compile the target into their own instruction set
and ship an interpreter. pydecomp recovers the interpreter; translating its
program back to Python needs that VM's dispatch table, which is the next piece
of work rather than a limit of static analysis.

## Handled, and gated

Encodings, compression chains, marshal, pyc, zip bundles, string tables, XOR with
constant keys, run-time key enumeration, `exec`/`eval`/`compile` chains, lambda
decoders, version-gated decoys, `types.CodeType` reconstruction, carved payloads
inside native blobs, aliasing, MBA, opaque predicates, flattening, dead code.

Coverage is enforced, not claimed: 21 gates, 37 probe shapes, 5 obfuscator
families, 206 unit tests. The adversarial gate drives a real packer's output and
checks that a sealed payload is *labelled* sealed, that a plain file is never
called recovered, and that cleaning never deletes live code.

## The rule that outranks everything above

A cleaning pass is kept only when the output is still the recovered program. If
control flow disappears without a pass recording a proof for it, the unpacked
text is written instead and the rollback is reported. A wrong simplification is
worse than a missed one.
