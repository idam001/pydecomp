# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-11-01 — “the Almighty”

### The Almighty

The 1.0.0 engine is built against the hardest public obfuscation in the wild -
PyArmor 8/9 containers, PyInstaller CArchives, obfuscator.io-style string
tables, MBA algebra, opaque predicates, unicode aliasing and control-flow
flattening - and every one of those defences now has a static counter-pass.

### Reconstruction (the second Almighty round)

Unwrapping a packer is not the same as rebuilding a program.  This round is
about the difference: pydecomp can now follow logic the *sample itself* defines,
without running it.

### Added
- **Static expression evaluator** (`polish/evaluate.py`): a bounded interpreter
  for pure expressions — literals, arithmetic, slicing, comparisons,
  comprehensions over literal iterables, f-strings, lambdas, a whitelisted method
  set (`.decode`/`.encode`/`.replace`/`.join`/…) and whitelisted modules
  (`base64`, `binascii`, `zlib`, `gzip`, `bz2`, `lzma`, `codecs`, `hashlib`), plus
  `chr`/`ord`/`bytes`/`map`/… builtins.  Anything else raises `Unevaluable`; the
  sample is never imported or executed.
- **Decoder inlining** (`polish/inline.py`): a decoder the sample defines
  (`def _d(s): return base64.b64decode(s[::-1]).decode()`) is interpreted on its
  literal argument, so `_d(_q)` collapses to `'print(...)'` — the case that makes
  single-pattern tools report "unknown obfuscation".
- **Constant propagation**, per scope, into module and function bodies, plus
  removal of literal temporaries and unreachable statements after
  `return`/`raise`/`break`/`continue`.
- **Fixed-point pipeline**: the whole pass set now repeats until an iteration
  changes nothing, so literal → propagation → inlining → folding → opaque
  pruning → dead-code chaining all happens in one run (`polish/apply.py`).
- **Hyperion** (`decoders/hyperion.py`): recognises the container and recovers
  the program from `__code__` — as a string literal, or as an ordinal tuple
  joined back to text.  The class scaffolding and junk `try/except` blocks are
  not needed to read it.
- **pyobfuscate.com** (`decoders/pyobfuscate_com.py` + `crypto/kdf.py`): decrypts
  the paid-tier payload from its own key schedule — base85 → `PBKDF2-SHA256`
  (1,000,000 iterations, salt `blob[:16]`) → AES-GCM (nonce `blob[16:32]`, tag
  `blob[32:48]`) — with AES-CBC/ECB fallbacks for older builds.  Entirely static:
  no sample execution, no network.  When the password is not in the file, the
  ciphertext is emitted and the report says why.
- **Payload splicing** (`engine/splice.py`): when a recovered payload still
  reads a table, helper or import defined by the outer module, those definitions
  are carried across and the loader statements never are — so the result imports
  instead of dangling on free names.
- `tests/integration/families_probe.py` — BlankOBF, pyobfuscate.dev, Jawbreaker,
  Wodx and PlusOBF recipes, reconstructed end to end by the generic engine with
  no per-family special case.
- `tests/integration/test_reconstruct.py` — ten checks covering the evaluator,
  its refusals, inlining, fixed-point chaining, Hyperion, pyobfuscate.com, the
  locked-payload path and reconstruction at scale.
- **String tables** (`polish/strarrays.py`): resolves the obfuscator.io port to
  Python - literal arrays, `push/pop` rotations (including `while` counters),
  offset accessors, per-element decode chains (`b64/b32/b16/a85/b85/zlib`,
  `[::-1]`, `.decode()`). Tables that are mutated in a way we cannot replay are
  left untouched rather than guessed at.
- **MBA simplifier** (`polish/mba.py`): nine mixed-boolean identities
  (`(x^y)+2*(x&y) → x+y`, `(x|y)-(x&y) → x^y`, `(x^y)-2*(~x&y) → x-y`, …). Each
  rule is proved against a grid of integers at import time; only sound rules are
  installed, and the sample's code is never evaluated.
- **Opaque predicates** (`polish/opaque.py`): proves `x*x >= 0`,
  `x*(x+1)%2 == 0`, `(x|1)%2 == 1`, `x^x`, `x&~x`, `len(x) >= 0` and friends with
  a bounded integer interpreter, then deletes the branch that can never run.
- **Alias and unicode normalisation** (`polish/aliases.py`): `ᐁ = alias`
  bindings resolved, unicode identifiers transliterated (with a legend),
  `getattr(__builtins__, 'eval')` and `vars()['__builtins__'][…]` folded,
  `__import__('base64').b64decode` rewritten to `base64.b64decode`, and the
  `exec(unparse(...eval(__doc__)))` self-hosting trick unwrapped to the program
  it really runs.
- **PyInstaller** (`decoders/pyinstaller.py`): CArchive cookie → table of
  contents → entries, plus `PYZ` tables, with `.pyc` rebuilding left to the
  existing marshal reader. `--key` builds are reported per entry, never dropped.
- **PyArmor** (`decoders/pyarmor.py`): recognises the `PY…` container, the build
  banner, serial and runtime package; emits the bootstrap whole and puts the
  payload facts (tag, length, carved strings) in the report. No pretending: the
  code objects stay encrypted and the tool says so.
- **Almighty limits**: 64 nested layers (was 25), 128 MiB per decode step, 64 MiB
  recovered-source ceiling, 12 explored chains.
- `tests/integration/test_almighty.py` - ten hardened samples covering the list
  above, including a PyArmor container and a PyInstaller archive.

### Changed
- `tools/check_static_only.py` is **advisory**: it reports, never blocks, and
  never withholds recovered source. `--strict` restores the old exit code.
- The banner card gains an `Edition` row: `THE ALMIGHTY`.
- **Renamed to pydecomp.** Package, CLI (`pydecomp`), modules, environment
  variables (`PYDECOMP_*`), the single-file build (`dist/pydecomp.py`), docs and
  workflows. `import pydecomp`, `python3 -m pydecomp`, `pydecomp sample.py`.
- **New banner.** Block-letter `PYDECOMP` logo, welcome band, the host's
  network and country, and an identity card crediting the author. Detection is
  offline: interface names from `/sys/class/net`, country from the timezone.
  Override with `PYDECOMP_NETWORK` / `PYDECOMP_COUNTRY` / `PYDECOMP_AUTHOR`.
- **One-line signature.** Recovered files now carry exactly
  `#[ Deobfuscated by idam Emmanuel ] only through pydecomp` instead of a
  multi-line provenance header. The provenance (hash, fingerprint, layers,
  imports, behaviour, indicators, round-trip score) moved to the console panel
  and to `--reports`.
- Author metadata: Idam Emmanuel is named in `pyproject.toml`, `CITATION.cff`,
  `LICENSE`, the docs and the `--selftest` panel.
### Added
- Repository layout: package under `src/pydecomp`, integration gates under
  `tests/integration`, benchmarks, fixtures and a mkdocs site.
- `tools/run_gates.py` — one command that runs every gate and prints a table.
- `tests/unit/` — fast pytest suites for the public API.
- Native fixtures are generated (`tests/fixtures/native/make_native_fixtures.py`):
  four `demo_module` builds plus hex, base64, zip and zlib/marshal payload
  carriers.
- Docs: architecture, layers, CLI reference, API reference, native notes,
  FAQ and roadmap.
### Fixed
- Opaque predicates are no longer sampled against non-numeric literals, so
  `if __name__ == "__main__":` can never be pruned as "provably false".
- `polish.opaque` no longer leaves nested statement lists behind after a pruned
  branch (which hid otherwise-dead statements from the dead-code pass).
- Class methods are no longer hoisted out of their class when a `marshal`
  payload is rebuilt: hoisting is now limited to code objects whose qualified
  name has no owner (`Headers.__init__` stays inside `Headers`).
- `_recovered_defs` counts `class` statements, so a rebuilt class is no longer
  reported as a missing definition and its body is not lifted twice.
- The packaged native sidecar (`pydecomp.native.sidecar`) is found before the
  legacy sibling `native.py`, so `pip install pydecomp` has a working ELF path
  with no extra files.


### The Almighty

The 1.0.0 engine is built against the hardest public obfuscation in the wild -
PyArmor 8/9 containers, PyInstaller CArchives, obfuscator.io-style string
tables, MBA algebra, opaque predicates, unicode aliasing and control-flow
flattening - and every one of those defences now has a static counter-pass.

### Reconstruction (the second Almighty round)

Unwrapping a packer is not the same as rebuilding a program.  This round is
about the difference: pydecomp can now follow logic the *sample itself* defines,
without running it.

### Added
- **Static expression evaluator** (`polish/evaluate.py`): a bounded interpreter
  for pure expressions — literals, arithmetic, slicing, comparisons,
  comprehensions over literal iterables, f-strings, lambdas, a whitelisted method
  set (`.decode`/`.encode`/`.replace`/`.join`/…) and whitelisted modules
  (`base64`, `binascii`, `zlib`, `gzip`, `bz2`, `lzma`, `codecs`, `hashlib`), plus
  `chr`/`ord`/`bytes`/`map`/… builtins.  Anything else raises `Unevaluable`; the
  sample is never imported or executed.
- **Decoder inlining** (`polish/inline.py`): a decoder the sample defines
  (`def _d(s): return base64.b64decode(s[::-1]).decode()`) is interpreted on its
  literal argument, so `_d(_q)` collapses to `'print(...)'` — the case that makes
  single-pattern tools report "unknown obfuscation".
- **Constant propagation**, per scope, into module and function bodies, plus
  removal of literal temporaries and unreachable statements after
  `return`/`raise`/`break`/`continue`.
- **Fixed-point pipeline**: the whole pass set now repeats until an iteration
  changes nothing, so literal → propagation → inlining → folding → opaque
  pruning → dead-code chaining all happens in one run (`polish/apply.py`).
- **Hyperion** (`decoders/hyperion.py`): recognises the container and recovers
  the program from `__code__` — as a string literal, or as an ordinal tuple
  joined back to text.  The class scaffolding and junk `try/except` blocks are
  not needed to read it.
- **pyobfuscate.com** (`decoders/pyobfuscate_com.py` + `crypto/kdf.py`): decrypts
  the paid-tier payload from its own key schedule — base85 → `PBKDF2-SHA256`
  (1,000,000 iterations, salt `blob[:16]`) → AES-GCM (nonce `blob[16:32]`, tag
  `blob[32:48]`) — with AES-CBC/ECB fallbacks for older builds.  Entirely static:
  no sample execution, no network.  When the password is not in the file, the
  ciphertext is emitted and the report says why.
- **Payload splicing** (`engine/splice.py`): when a recovered payload still
  reads a table, helper or import defined by the outer module, those definitions
  are carried across and the loader statements never are — so the result imports
  instead of dangling on free names.
- `tests/integration/families_probe.py` — BlankOBF, pyobfuscate.dev, Jawbreaker,
  Wodx and PlusOBF recipes, reconstructed end to end by the generic engine with
  no per-family special case.
- `tests/integration/test_reconstruct.py` — ten checks covering the evaluator,
  its refusals, inlining, fixed-point chaining, Hyperion, pyobfuscate.com, the
  locked-payload path and reconstruction at scale.
- **String tables** (`polish/strarrays.py`): resolves the obfuscator.io port to
  Python - literal arrays, `push/pop` rotations (including `while` counters),
  offset accessors, per-element decode chains (`b64/b32/b16/a85/b85/zlib`,
  `[::-1]`, `.decode()`). Tables that are mutated in a way we cannot replay are
  left untouched rather than guessed at.
- **MBA simplifier** (`polish/mba.py`): nine mixed-boolean identities
  (`(x^y)+2*(x&y) → x+y`, `(x|y)-(x&y) → x^y`, `(x^y)-2*(~x&y) → x-y`, …). Each
  rule is proved against a grid of integers at import time; only sound rules are
  installed, and the sample's code is never evaluated.
- **Opaque predicates** (`polish/opaque.py`): proves `x*x >= 0`,
  `x*(x+1)%2 == 0`, `(x|1)%2 == 1`, `x^x`, `x&~x`, `len(x) >= 0` and friends with
  a bounded integer interpreter, then deletes the branch that can never run.
- **Alias and unicode normalisation** (`polish/aliases.py`): `ᐁ = alias`
  bindings resolved, unicode identifiers transliterated (with a legend),
  `getattr(__builtins__, 'eval')` and `vars()['__builtins__'][…]` folded,
  `__import__('base64').b64decode` rewritten to `base64.b64decode`, and the
  `exec(unparse(...eval(__doc__)))` self-hosting trick unwrapped to the program
  it really runs.
- **PyInstaller** (`decoders/pyinstaller.py`): CArchive cookie → table of
  contents → entries, plus `PYZ` tables, with `.pyc` rebuilding left to the
  existing marshal reader. `--key` builds are reported per entry, never dropped.
- **PyArmor** (`decoders/pyarmor.py`): recognises the `PY…` container, the build
  banner, serial and runtime package; emits the bootstrap whole and puts the
  payload facts (tag, length, carved strings) in the report. No pretending: the
  code objects stay encrypted and the tool says so.
- **Almighty limits**: 64 nested layers (was 25), 128 MiB per decode step, 64 MiB
  recovered-source ceiling, 12 explored chains.
- `tests/integration/test_almighty.py` - ten hardened samples covering the list
  above, including a PyArmor container and a PyInstaller archive.

### Changed
- `tools/check_static_only.py` is **advisory**: it reports, never blocks, and
  never withholds recovered source. `--strict` restores the old exit code.
- The banner card gains an `Edition` row: `THE ALMIGHTY`.
- **Renamed to pydecomp.** Package, CLI (`pydecomp`), modules, environment
  variables (`PYDECOMP_*`), the single-file build (`dist/pydecomp.py`), docs and
  workflows. `import pydecomp`, `python3 -m pydecomp`, `pydecomp sample.py`.
- **New banner.** Block-letter `PYDECOMP` logo, welcome band, the host's
  network and country, and an identity card crediting the author. Detection is
  offline: interface names from `/sys/class/net`, country from the timezone.
  Override with `PYDECOMP_NETWORK` / `PYDECOMP_COUNTRY` / `PYDECOMP_AUTHOR`.
- **One-line signature.** Recovered files now carry exactly
  `#[ Deobfuscated by idam Emmanuel ] only through pydecomp` instead of a
  multi-line provenance header. The provenance (hash, fingerprint, layers,
  imports, behaviour, indicators, round-trip score) moved to the console panel
  and to `--reports`.
- Author metadata: Idam Emmanuel is named in `pyproject.toml`, `CITATION.cff`,
  `LICENSE`, the docs and the `--selftest` panel.

### Added
- Repository layout: package under `src/pydecomp`, integration gates under
  `tests/integration`, benchmarks, fixtures and a mkdocs site.
- `tools/run_gates.py` — one command that runs every gate and prints a table.
- `tests/unit/` — fast pytest suites for the public API.
- Native fixtures are generated (`tests/fixtures/native/make_native_fixtures.py`):
  four `demo_module` builds plus hex, base64, zip and zlib/marshal payload
  carriers.
- Docs: architecture, layers, CLI reference, API reference, native notes,
  FAQ and roadmap.

### Fixed
- Opaque predicates are no longer sampled against non-numeric literals, so
  `if __name__ == "__main__":` can never be pruned as "provably false".
- `polish.opaque` no longer leaves nested statement lists behind after a pruned
  branch (which hid otherwise-dead statements from the dead-code pass).
- Class methods are no longer hoisted out of their class when a `marshal`
  payload is rebuilt: hoisting is now limited to code objects whose qualified
  name has no owner (`Headers.__init__` stays inside `Headers`).
- `_recovered_defs` counts `class` statements, so a rebuilt class is no longer
  reported as a missing definition and its body is not lifted twice.
- The packaged native sidecar (`pydecomp.native.sidecar`) is found before the
  legacy sibling `native.py`, so `pip install pydecomp` has a working ELF path
  with no extra files.

## [8.1.0] — 2026-10-31

### Added
- **Cython / ELF front-end (option 2 and 3, preview).** `--native`, `--elf`
  and automatic routing when the input starts with `\x7fELF`. Four recovery
  tiers: `S` (byte-exact from the generated C), `B` (DWARF line numbers),
  `A` (structures and docstrings from `PyMethodDef`), `C` (string carving).
- Payload carving from compiled images: hex, base64, zip and zlib containers,
  plus `marshal` code-object trees, each rebuilt and audited.
- `--selftest` verifies the interpreter, the native layer and a recovery.

### Changed
- Polish pass reports every action it took instead of silently rewriting.
- Report lists per-stage byte counts and the audit verdict.

### Fixed
- `STORE_ATTR` on 3.13 no longer swaps operands when the value is a local.
- Slices recovered as `[None:LIMIT]` are normalised to `[:LIMIT]`.

## [8.0.0] — 2026-10-29

### Added
- Bytecode lifter for CPython 3.9 → 3.14 with per-version opcode tables.
- `decompile_object` / `lift_module` public API and a round-trip score that
  counts recovered instructions.
- Control-flow unflattening and dead-branch elimination.

### Changed
- `dig()` returns a `DigResult` with `text`, `stages`, `report` and `audit`.
- Output stays one file unless `--reports` is given.

## [7.4.0] — 2026-10-27

### Added
- Expression evaluator with a whitelist (no I/O, no subprocess, no imports
  outside `EXPR_MODULES`).
- Emoji, base85 and RFC 1751-style decoders.
- `_PydecompUnknown` sentinel and the runnability report.

## [7.0.0] — 2026-10-24

### Added
- Recursive layer peeling with cycle detection.
- Fingerprints for the common families (pyobfus, Mr.X, BlankOBF, pyarmor
  shapes, Hyperion wrappers).

## [0.1.0] — 2026-10-20

### Added
- First working end-to-end recovery of a base64 + zlib + `exec` dropper.
