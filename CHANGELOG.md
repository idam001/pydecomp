# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
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
