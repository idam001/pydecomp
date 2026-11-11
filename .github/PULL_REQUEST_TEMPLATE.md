## What changed

<!-- One paragraph. What does this PR do, and why now? -->

## Why

<!-- The problem. Link the issue: Fixes #123 -->

## How it was verified

<!-- Numbers, not adjectives. -->

- [ ] `python3 tools/run_gates.py` is green
- [ ] `python3 tools/build_single.py --check` is clean
- [ ] `python -m pytest tests/unit -q` passes
- [ ] new behaviour has a fixture or a probe (no real malware, please)

Concrete before/after, if this touches recovery quality:

| Sample | Before | After |
|---|---|---|
|  |  |  |

## Checklist

- [ ] The sample is never executed, imported or spawned — still true
- [ ] Static-only scan passes (`tools/check_static_only.py`)
- [ ] Public API changes are documented in `docs/api.md` and `CHANGELOG.md`
- [ ] No new runtime dependency (the engine stays stdlib-only)
- [ ] Comments explain *why* for any deliberate heuristic
- [ ] Commits follow `feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `build:`

## Notes for reviewers

<!-- Anything risky, anything you were unsure about, anything you left out. -->
