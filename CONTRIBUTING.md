# Contributing to pydecomp

Thanks for helping. This project exists because people kept sending in samples
that no other tool could peel, and the fixes that came back made it better for
everyone. Two rules frame everything below:

1. **The sample is never executed.** Not in a test, not in a fixture, not "just
   to check" inside a container. pydecomp reads bytes and models bytecode.
2. **A recovery that cannot run is not a recovery.** Keep `_PydecompUnknown`, keep
   the audit, keep the report honest.

## Ways to contribute

| You have | Do this |
|---|---|
| A sample pydecomp mishandles | Open a **new sample** issue with the hash, the version, and the smallest reproducer you can share. |
| A crash or a wrong recovery | Open a **bug report** with the gate name and the exact command. |
| A decoder or obfuscator family to support | Open a **feature request** describing the shape, then follow the recipe below. |
| Typo / docs fix | Just send the PR. |

Please do not attach live malware. A hash plus a defanged excerpt, or a
minimised synthetic case that reproduces the same shape, is far more useful and
much safer to keep in the repository.

## Development setup

```bash
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Optional, for the native gate (needs `gcc`):

```bash
pip install cython
python3 tests/fixtures/native/make_native_fixtures.py
```

## The gates

Everything is verified by scripts that print a pass count, not by vibes:

```bash
python3 tools/run_gates.py           # all of them, one table at the end
python3 tools/run_gates.py v8 probes # a subset
PYTHONPATH=src python3 tests/integration/test_v8.py
python -m pytest tests/unit -q
```

A pull request is mergeable when `run_gates.py` is green and the single-file
build still passes:

```bash
python3 tools/build_single.py --check
```

Gate map:

| Gate | Covers |
|---|---|
| `v4` | classic packing cases, output layout |
| `v5` | CLI contract, one output file, static-only proof |
| `v6` | fallbacks, policy-free output, round trip |
| `v7` | menu, prompts, non-interactive behaviour |
| `v8` | polish: demangling, folding, dead branches |
| `identity` | instruction-identical round trips for 47 shapes |
| `probes` | 37 known obfuscator shapes |
| `native` | Cython/ELF tiers S/B/A, payload carving |
| `bench` | the hardest-obfuscation benchmark (`obf_bench`) |
| `examples` | the six worked examples under `examples/` |

## Adding a decoder

1. Put it in `src/pydecomp/decoders/` or `src/pydecomp/crypto/` as a small function
   that takes and returns `bytes`, or `None` when the input is not yours.
2. Register it in the decoder chain used by `engine/dig.py` — the chain tries
   every decoder, so make the "not mine" answer cheap and certain.
3. Add a fixture under `tests/fixtures/` built by a script, never a real sample.
4. Add a probe to `tests/integration/test_probes.py` that asserts the recovery.

Decoders must be **pure**: no imports outside the standard library, no I/O, no
network, no `eval` of sample text. `crypto/` stays stdlib-only because the
single-file build is the delivery format for phones.

## Adding an obfuscator fingerprint

Fingerprints live in `src/pydecomp/triage/`. A fingerprint returns
`(family, confidence, indicators)` and must never be the only path to a
recovery — it only labels what the pipeline already found. Include: a short
description, the structural signals you key on, and one synthetic fixture.

## Code style

- `ruff` and `mypy` run in CI; `pre-commit` runs them locally.
- Line length 100, double quotes, `from __future__ import annotations` in every
  module.
- Comments explain *why*, especially where a heuristic is deliberately
  permissive. If you accept a technically-wrong-but-useful parse, say so and
  add it to the documented permissive list in `tests/integration/test_v5.py`.
- Public API changes need a docstring and a docs page update.

## Commits and pull requests

- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `build:`, `chore:`.
- One logical change per PR. Keep unrelated reformatting out.
- Describe the *before/after* on a concrete sample, with numbers.
- PRs that add a decoder should show the byte delta on at least one real file.

## Releasing (maintainers)

```bash
python3 tools/bump_version.py 8.2.0     # updates limits.py, pyproject, CITATION
python3 tools/run_gates.py
python3 tools/build_single.py
git commit -am "release: 8.2.0" && git tag v8.2.0 && git push --tags
```

The `release` workflow builds the sdist, the wheel, the single file and the
Docker image, then publishes to PyPI via trusted publishing.

## Licence

By contributing you agree your work is released under the MIT licence in
[LICENSE](LICENSE).
