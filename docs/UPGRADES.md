# What I would upgrade next

Written after a session on this codebase, so every item below carries the evidence
that put it here. Ordered by what can produce a *wrong answer* first, what loses
*recovered code* second, speed third, convenience last.

---

## 0. Fixed while writing this list

**Mutable literals were being constant-propagated.** `results = []` followed by
`results.append(x)` was rewritten to `[].append(x)`, and `return results` to
`return []` — the function silently became a no-op.

```python
def report(items):           # before cleaning
    results = []
    for item in items:
        results.append(item * 2)
    return results
```
```python
def report(items):           # what it produced
    for item in items:
        [].append(item * 2)
    return []
```

Cause: `propagate_constants` treated any evaluable binding as a constant, and a
list literal evaluates fine. Only immutable scalars (and tuples of them) may be
substituted now — aliasing and mutation mean a mutable literal is never a
constant. Three regression tests added, and bench case `01_plain_pyc` now lifts
`out.append(...)` instead of `[].append(...)`.

That this survived 17 gates is the single most important thing on this list —
see P0-1.

---

## P0 — correctness: nothing should be able to ship wrong code quietly

1. ~~**A differential-execution harness for the rewriters.**~~
   **Done** — `tools/diff_polish.py`, gate `differential`
   (`26 fixtures × 11 passes, 0 divergences`).

   Every pass that rewrites structure — `mba`, `opaque`, `dead`, `eval`, `fold`,
   `inline`, `propagate`, `aliases`, `loops`, `unflatten`, `strarrays` — is now
   applied to 26 generated programs and the original and rewritten program are
   **executed** in separate `-I` interpreter processes over a table of inputs; the
   returned values are compared. Fixtures only: the sample is never involved.

   Two properties keep the gate from going quiet. It plants a wrong rewrite
   (`a + b` → `a - b`) and refuses to run if it does not catch it, and every pass
   must have changed at least one fixture, so a pass that was not exercised fails
   the gate instead of counting as clean.

   It found a real bug on its first run, which no existing gate had:

   ```python
   def run(n):
       return n + 1
       n = 99            # dead, below the return
   ```

   `propagate_constants` substituted the later binding backwards into the return:
   `return 99 + 1` → `100` for every input. The pass required a name to be bound
   once but never that the binding *preceded* the use, and it treated a function
   parameter as a constant once the body reassigned it. Both rules are enforced
   now (`polish/inline.py`), with nine unit tests in
   `tests/unit/test_propagate_order.py` pinning the ordering and the parameter
   case.

2. **Coverage should fail loudly, not just report.**
   `--diff` printed `verdict: complete` for the broken `report()` above: the
   definition survived, so the check said complete. Add a *suspicion* signal —
   a function whose statement count falls by more than half, or whose returned
   names disappear — surfaced as `suspicious` rather than `kept`. Then wire it
   into the gate suite for the fixtures.

3. **Opaque-predicate prover: prove only what can be proved.**
   Sampling is currently over integers; `_numeric_only` blocks the obvious
   string cases, but `len(x) >= 0` and `x != x` style facts are handled only by
   name-specific rules. Adding a tiny symbolic layer (interval + truthiness) would
   let it prove `if 2 + 2 == 4:` chains *and* refuse `if user_input:` honestly.

4. **Fuzz the parsers that take hostile input.**
   `marshal` reader, `.pyc` header reader, CArchive/PYZ reader, YARA-subset
   parser: none are fuzzed. A `hypothesis`-driven gate over byte mutations would
   find the crashes that a real sample will eventually find.

---

## P1 — the benchmark is mis-scored, and that undersells the tool

5. **Derive `truth.json` from the generated source.** The bench scores
   `secret`/`endpoint`/`marker` against a *fixed triple*, but several cases never
   contain all three:
   `01_plain_pyc` has no `MARKER`, `05_flattened` has no `ENDPOINT`,
   `07_mba`/`06_opaque_dead` have no `ENDPOINT`, case `11_nightmare` has no
   `ENDPOINT`. So 9 of the 11 "missing" points are unattainable by construction.

   Reachable maximum: **35/44**; achieved: **33/35** — and 10 of 11 cases are at
   their ceiling. Fix the generator, and the headline becomes honest
   (`35/35 reachable`) instead of a number that reads like a failure.

6. **Case `11_nightmare` is the one real shortfall (1/4).**
   Its payload is six layers deep *and* re-decoded inside a loop:

   ```python
   _d = _p
   for _ in range(1):
       _d = base64.b64decode(_d)
       _d = zlib.decompress(lzma.decompress(_d))
   ```
   The peeler does not replay a reassignment loop feeding one name. *Build:* a
   static "decoder loop replay" — trace a single-assignment chain through a
   counted loop body, up to N iterations where N is a literal. That is the same
   machinery the string-array rotation already has; reuse it.

---

## P2 — obfuscator coverage (what a new sample will hit)

7. **Loop recovery beyond step-one ascending indices.** Currently: start 0, step
   1, `<` bound, index used only to subscript. Missing: `range(len(x) - 1)` /
   `> 0` descending loops, `step != 1`, `enumerate`-shaped loops, `while x:`
   over a shrinking list, `for` over `dict.items()`.
8. **De-flattener: other dispatcher shapes.** Dict jump tables
   (`{0: label, …}` with lookups), `while True:` + `break`-on-condition,
   string-valued states (partly handled), and nestings deeper than `_MAX_DEPTH`.
9. **String arrays: incremental builders.** `s = ''; for c in …: s += chr(c)` and
   `bytes(arr).decode()` are extremely common in packers; the current pass
   resolves static tables and rotations only.
10. **Evaluator surface.** Add `re`, `str.format`/`%`-formatting, `int(x, 16)`,
    `bytes.fromhex`, `bytes(arr)`, `itertools.chain`, `''.join(map(chr, …))`
    over generators. Each is a small, testable addition that folds whole families
    of decoders instead of inlining them.
11. **PyArmor: attempt the carve we currently only describe.** When
    `pyarmor_runtime` and a `license.lic` travel with the sample, the runtime
    blob and the key material are both present; today the tool states the truth
    ("the code objects stay encrypted") but does not try. A bounded attempt that
    fails honestly is strictly better than a refusal.

---

## P3 — performance and scale

12. **`lift/quality.ensure_parseable` compiles 23,807 times** on the 1.6 MB
    sample — 13.2 s of a 56 s run. Memoise on the AST digest; should halve total
    runtime on large inputs.
13. **`_TIME_BUDGET = 25 s` truncates silently.** Large samples stop the
    fixed-point loop early with no word to the user. Report
    `budget reached after N rounds — output may not be fully settled`.
14. **Batch runs are serial** (`for entry in todo[:400]`). `--jobs N` with a
    process pool, and per-file results collected into the combined report.
15. **No cache.** Re-running the same sample redoes everything. A
    `~/.cache/pydecomp/<sha256>/` keyed on input hash + tool version would make
    batch triage of 400 files cheap on the second pass.

---

## P4 — analyst-facing output

16. **IOC export beyond Markdown:** STIX 2.1 bundle and MISP event JSON, so the
    sheet lands in a platform instead of a ticket.
17. **YARA:** hex strings and file-type guards (`uint16(0) == 0x5A4D`,
    `extension == "py"`), plus one *family* rule built from the batch sheet's
    shared infrastructure. Also validate with the real `yara` binary when it is
    installed, falling back to the built-in parser.
18. **`--diff` as an actual diff.** Statement counts are useful; a unified diff
    per function, or `--diff-base other_sample.py` for tracking a dropper family
    across builds, is what an analyst actually wants next.
19. **`--report html`** — the console panel and the Markdown reports are good;
    one self-contained HTML file with the source, the sheet and the layers is
    what gets attached to a case.

---

## P5 — engineering hygiene

20. **Semantic version of the pipeline:** the pass order is a compatibility
    surface. Record it in the report (`passes: [strarrays, aliases, …]`) so two
    runs can be compared meaningfully.
21. **Property tests for the evaluator:** round-trip `repr(literal) → evaluate`
    over generated scalars, and `evaluate(expr) == eval(expr)` for a curated
    pure subset in a subprocess.
22. **Docs:** `docs/roadmap.md` still says the remaining bench points "need
    opaque-predicate resolution over string constants" — item 5 shows that is not
    where the points went. Roadmap entries should carry the same evidence this
    file does.
