# What pydecomp can and cannot do

"Deobfuscate any Python script" is a promise no static tool can keep, and this
page is the honest accounting.  Everything under **handled** is covered by a gate
that fails the build if it regresses.  Everything under **cannot** is a limit of
static analysis, not a missing afternoon of work — where a limit is real, the
tool names it in the report instead of guessing.

## Handled, and gated

| layer | what it looks like |
|---|---|
| encodings | base64, base85, ascii85, base32, hex, `chr()` arrays, integer lists joined into bytes |
| compression | zlib, gzip, bz2, lzma, and stacked chains of all of them in any order |
| serialisation | `marshal` of a compiled code object, `.pyc` containers, zip bundles |
| string layers | string tables with index lookups, reversed strings, per-character XOR with a constant key, `format`/`%` assembly |
| loaders | `exec`/`eval`/`compile` chains, lambda decoders, `__import__` name assembly, version-gated payloads with decoy branches |
| code objects | `types.CodeType(...)` reconstruction from XOR-encoded bytecode, including line tables and exception tables |
| source polish | unicode/identifier aliasing, MBA identities, opaque predicates, control-flow flattening, dead branches, constant propagation |

The published gates cover 37 probe shapes, 5 named obfuscator families and 11
benchmark samples; `bench` currently reports a semantic score of 33/44 with
11/11 rebuilt as source.  Those numbers are in the build, not in a slide.

## Cannot, and says so

| situation | why it is impossible statically |
|---|---|
| the key comes from `os.urandom`, `time.time()`, `input()`, `hash()` or an environment variable | the plaintext does not exist until the program runs; recovering it would require running the sample, which pydecomp never does |
| the key is fetched from a server, or unlocked by a licence file | same reason, plus it needs the network |
| the key lives in a native `.so`/`.pyd` (PyArmor 9 licensing, commercial packers) | the Python layer holds ciphertext only; reading the key means reverse-engineering machine code |
| the code was compiled away — Cython, Nuitka, mypyc | there is no Python bytecode left to lift; the artifact is machine code |
| the obfuscator destroyed information — names and literals generated at run time, code built from a custom VM plus an encrypted opcode table | the recovered artifact is the VM, not a program; pydecomp will hand you the VM and say so |
| comments, docstrings and original formatting | they are not in the bytecode; nothing can bring them back |

When pydecomp hits one of these it should never quietly produce a plausible
file.  That is what the `loader`, `copy` and `NOT VERIFIED` verdicts are for: a
sealed payload is named `_loader`, a plain file is named `_copy`, and the
fidelity line refuses to claim a recovery it does not have.

## Where the frontier actually is

Measured on this project's own adversarial packer, the blockers in order:

1. **Runtime-derived keys.**  A payload whose key is `len(os.urandom(16))` is
   unreachable for any static tool.  What is missing is not recovery but a
   *diagnosis*: the report should name the expression that makes it impossible,
   so an analyst stops trying.
2. **Custom-VM bytecode.**  Packers that compile the target into a bespoke
   instruction set and ship an interpreter for it.  Recovering readable source
   means recovering the interpreter's dispatch table first; today pydecomp
   recovers the interpreter and stops.
3. **Control-flow structuring.**  Un-flattening recovers the state machine's
   order, but not always the original `for`/`while` shapes.  The output runs
   correctly; it may not read like the original.
4. **Scale.**  A 1.2 MB packed sample takes about a minute.  That is fine for
   triage and slow for a corpus.

## The rule that outranks all of the above

A cleaning pass may only be kept when the output is still the recovered program.
When a pass cannot prove that, the unpacked text is written instead and the
rollback is reported with its reason.  A wrong simplification is far worse than a
missed one — and an earlier revision of this tool proved that the hard way by
deleting a live `elif` from a program that had never been obfuscated.
