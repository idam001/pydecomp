# Roadmap

Ordered by what makes the next real sample recoverable, not by what is fun to
write. Items move up when someone sends a sample that needs them.

## Now (option 1: pure-Python scripts)

- **Module-level `try`/`with` frames** on 3.13 — statements survive today, the
  frame becomes a comment. Target: structural rebuild.
- **`match` statements** back to `match` rather than an `if`/`elif` chain.
- **Generator expressions with `yield from`** inside larger expressions.
- **Better demangling**: keep the original name when the mangled one is longer
  than the recovered meaning, and note every rename in the report.
- **Honest benchmark denominator.** The score reads 33/44, but nine of those
  eleven missing points are unattainable: several generated cases never contain
  all three truth strings (`01_plain_pyc` has no marker, `05_flattened` and
  `07_mba` have no endpoint). Derive `truth.json` per case from the source that
  was generated; the reachable maximum is 35/44 and the tool is at 33/35.
- **Case `11_nightmare`** is the only real shortfall (1/4): six layers plus a
  decoder reassigned inside a counted loop. See `docs/UPGRADES.md` P1-6.

## Next

- **Per-version opcode coverage for 3.14** once its opcode set settles
  (`BINARY_OP` folding widened considerably).
- **A `--diff` mode**: recover two samples and show which functions changed,
  useful for tracking a dropper family across builds.
- **A `--stdout` mode** that writes the recovery to stdout and nothing to disk,
  for pipelines.
- **Structured reports**: SARIF output so findings land in a code-scanning UI.

## Later (options 2 and 3, preview)

- **Tier B from `.debug_line` without DWARF 5 gaps**: a few compiler/linker
  combinations produce line rows pydecomp currently skips.
- **More payload carriers**: `PKZIP` split across sections, payloads with a
  length-prefixed header, and `marshal` trees inside `bss`.
- **PyInstaller `PYZ` extraction** as a first-class mode rather than `--elf`
  carving.

## Explicitly not planned

| Idea | Why not |
|---|---|
| Running the sample in a sandbox | pydecomp is static; use a real sandbox for that |
| A network service | the tool must work offline, on a phone, with no dependencies |
| Machine-code → C decompilation | a different project; pydecomp only handles Python payloads |
| Auto-submitting samples upstream | privacy and consent |
| A GUI | the menu and the reports cover the use case without a dependency |

## How items get added

Open a **feature request** with the shape of the problem, or a **new sample**
issue if pydecomp already fails on something real. Items with a reproducer and a
test case jump the queue — see [GOVERNANCE.md](https://github.com/pydecomp/pydecomp/blob/main/GOVERNANCE.md).
