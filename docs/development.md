# Development

## Setup

```bash
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

The engine is pure standard library, so `PYTHONPATH=src python3 -m pydecomp` works
from a bare checkout with no install at all.

## The gates

Everything is verified by scripts that print a count, not by opinion:

```bash
python3 tools/run_gates.py             # all of them, one table, ~110 s
python3 tools/run_gates.py v8 probes   # a subset
python3 tools/run_gates.py --list
python3 tools/run_gates.py --json g.json
python3 -m pytest tests/unit -q        # 90 fast API tests
```

| Gate | What it protects |
|---|---|
| `v4` | classic packing cases end to end |
| `v5` | the CLI contract: one output file, static-only, no chatter |
| `v6` | fallbacks and round trip |
| `v7` | menu, prompts, non-interactive behaviour |
| `v8` | polish passes: demangling, folding, dead branches |
| `identity` | instruction-identical rebuilds for 47 shapes |
| `probes` | 37 known obfuscator shapes |
| `native` | Cython/ELF tiers and payload carving |
| `differential` | every polish pass, checked by running the code it rewrote |
| `fuzz` | the marshal/`.pyc`/freezer readers, over mutated bytes |
| `bench` | the hardest-obfuscation benchmark |

## The tools

| Tool | Purpose |
|---|---|
| `tools/run_gates.py` | run the gates, print a table, exit non-zero on red |
| `tools/build_single.py` | build/verify `dist/pydecomp.py` |
| `tools/check_static_only.py` | prove nothing executes the sample |
| `tools/gen_opcode_tables.py` | validate opcode tables against `dis` |
| `tools/make_fixtures.py` | regenerate the text fixtures (byte-identical) |
| `tools/bump_version.py` | bump the version everywhere it is written |
| `tools/fetch_cpython.py` | download CPython's `opcode.py` / `marshal.c` to compare |
| `tools/diff_polish.py` | run each polish pass and compare behaviour, not structure |
| `tools/fuzz_parsers.py` | mutate bytes into the readers and require a declared refusal |

## Adding a decoder

1. Put it in `src/pydecomp/decoders/` (or `crypto/`): `bytes -> bytes | None`,
   returning `None` fast when the input is not yours.
2. Register it in the chain used by `engine/dig.py`.
3. Add a generator for the fixture — never a real sample.
4. Add a probe to `tests/integration/test_probes.py`.

Rules: stdlib only, no I/O, no network, no `eval` of sample text, bounded
output.

## Adding an opcode or a version

1. `python3 tools/gen_opcode_tables.py --write` for the running interpreter, or
   write the entry by hand from `Include/opcode_ids.h`.
2. `python3 tools/gen_opcode_tables.py --check` must be clean.
3. Teach `bytecode/decompiler6.py` any new structure; add a shape to
   `tests/unit/test_roundtrip.py` and to `test_identity.py`.

## Working on the single file

The bundle is generated, never edited:

```bash
python3 tools/build_single.py           # writes dist/pydecomp.py
python3 tools/build_single.py --check   # fails if it is stale
```

It embeds every module as zlib+base85 and serves it through a meta-path finder,
so a relative-import mistake or an import cycle shows up immediately — which is
why the package has zero cycles.

## Debugging a bad recovery

```bash
PYTHONPATH=src python3 -m pydecomp sample.py --reports -o /tmp/dbg
python3 -c "import json;print(json.dumps(json.load(open('/tmp/dbg/sample_deob.report.json')),indent=2))"
```

The report lists the stage trace, the score of every candidate and the audit.
From Python:

```python
import pydecomp
art = pydecomp.dig(open("sample.py", "rb").read(), "sample.py")
print(art.trace, art.score)
print(pydecomp.audit_source(art.text))
```

## Style

- `ruff` (lint + format) and `mypy` run in CI and in `pre-commit`.
- Line length 100, double quotes, `from __future__ import annotations`.
- Comments explain *why*. If a heuristic is deliberately permissive, say so and
  add a case to the documented permissive list in `tests/integration/test_v5.py`.

## Releasing

```bash
python3 tools/bump_version.py 8.2.0
python3 tools/run_gates.py
python3 tools/build_single.py
git commit -am "release: 8.2.0" && git tag v8.2.0 && git push --tags
```

The tag triggers `release.yml`: verify (tag == package version, gates green),
build sdist + wheel + single file, publish to PyPI via trusted publishing, and
create the GitHub release from the changelog section.
