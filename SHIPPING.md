# Shipping these upgrades

**Status: shipped.** These six commits are on `origin/main`
(`https://github.com/idam001/pydecomp`), authored and committed as
`idam001 <idamemmanuel@gmail.com>`.

The token pasted earlier in the chat was never used and never stored; **revoke
it**. The push used a token supplied for it, passed through an environment
variable and never written to a file, a remote URL or `.git/config` — **revoke
that one too** now that the commits are visible.

The sections below are kept as the record of how it was verified, and as the
fallback if the history ever has to be replayed.

## What went out

```
HEAD     Add SHIPPING.md (this file)
40527f8  A wrong XOR key could be reported as text, and only on some runs
c1edd67  Rebuild the single-file bundle
d0d04a0  Document the new artefacts, limits and the offline method boundary
87252a8  Per-function confidence, recovery-method comparison, hints, batch summary
b4f5b50  PyLingual as an optional out-of-process method, never a bundled backend
6a37db4  Read static artefacts: bounded archives, .pyc disassembly, indicator evidence
34cd043  (was origin/main before this push)
```

Author and committer on all six: `idam001 <idamemmanuel@gmail.com>`.

Ready-to-apply copies, both verified against a fresh clone of your repo:

- **`/home/user/pydecomp-patches/`** — six numbered `git am` patches (no auth,
  no bundle support needed). Tested: clone → `git am` → 590 tests pass.
- **`/home/user/pydecomp-upgrades.bundle`** — the same history in one file.

The tree produced by both is byte-identical to this workspace
(`4ca8306…`), on top of `34cd043`. Every path below is a fast-forward.

## Push it yourself — pick one

**A. From this checkout, with a fresh token** (the token is read from an
environment variable, never written to disk or to `.git/config`):

```bash
cd /home/user/pydeob
read -rs GITHUB_TOKEN && export GITHUB_TOKEN

git -c credential.helper= \
    -c credential.helper='!f() { echo "username=idam001"; echo "password=$GITHUB_TOKEN"; }; f' \
    push origin main
unset GITHUB_TOKEN
```

Give the token the `repo` scope only, and delete it once the push lands.

**B. From this checkout, with a deploy key — no token typed anywhere.**

This sandbox already holds a throwaway keypair. Paste the line below into
**GitHub → idam001/pydecomp → Settings → Deploy keys → Add deploy key**, tick
*Allow write access*, then run the script:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINujJCER0OgxzSHl+OHKehcRUR/IySIybdTcRDzoQwSZ pydecomp-deploy@arena-sandbox
```

```bash
bash /home/user/push-with-key.sh
```

It verifies the key, pushes `main`, restores the HTTPS remote, and prints the
remote head so you can see it landed. Delete the deploy key afterwards in the
same GitHub screen.

**C. On any machine that can push — from the patch files (simplest):**

```bash
git clone https://github.com/idam001/pydecomp.git pydecomp && cd pydecomp
git am /path/to/pydecomp-patches/*.patch
git push origin main
```

**D. On any machine that can push — from the bundle:**

```bash
git clone https://github.com/idam001/pydecomp.git pydecomp && cd pydecomp
git fetch /path/to/pydecomp-upgrades.bundle main:upgrades
git merge --ff-only upgrades
git push origin main
```

Both were run against a fresh clone of `idam001/pydecomp` while preparing this
file: `git am` applied all six commits cleanly, the suite passed, and
`build_single.py --check` was clean.

Because the local commits are already on top of the current `origin/main`,
every path above is a fast-forward — no merge commit, no rewrite.

## What was verified before committing

| check | result |
|---|---|
| unit suite (`pytest`) | **590 passed**, and `test_plugins.py` 3× in a row after the XOR fix |
| integration gates (`tools/run_gates.py`, all 36) | **36/36 green**, 151 s |
| corpus | 296/296 cases recovered (100%) |
| bench | semantic 35/35 reachable; rebuilt as source 11/11 |
| single-file bundle | 489,868 B, `build_single.py --check` clean |
| static-only invariant | `check_static_only.py` unchanged vs. baseline (7 pre-existing network notes in `fetch.py`/codecs, all `--fetch-iocs`-gated) |
| lint on new modules | `ruff check` clean on every file added |
| new flags exercised **through the bundle** | `--disassemble`, `--recipe`, `--source-map`, `--reports`, `--target-versions`, folder run → `batch-summary.json` |

The one pre-existing unstaged deletion (`dist/pydecomp.py`) was left alone as
instructed; the bundle was regenerated from source and committed separately, so
the file is present and current in the tree.

Verifying the bundle on a fresh clone turned up a pre-existing bug: a unit test
in `test_plugins.py` failed about 8% of runs on `main`. It was not flake - the
XOR key search accepted random bytes as text. Fixed in `274e95e`; see the
changelog entry "A wrong key was being accepted as text, and only sometimes".

## The 21 upgrades — where each one landed

| # | upgrade | status | where |
|---|---|---|---|
| 1 | `.pyc` recovery + fallbacks | already present; hardened | `bytecode/magic.py`, `ir_pipeline.py`; new cap in `bytecode/dump.py` |
| 2 | optional PyLingual | **new, out-of-process** | `plugins/backends/pylingual.py`, `--pylingual`, `--pylingual-import` |
| 3 | per-function confidence | **new** | `triage/confidence.py` → console, JSON/MD, HTML |
| 4 | encrypted-loader diagnostics | already present; surfaced | `triage/sealed.py`, `engine/dig.py` stall path, now a hint |
| 5 | IOC source evidence | **new** | `triage/iocs.py` `evidence`, all three reports |
| 6 | batch mode | extended | `deobfuscate_tree` + `batch-summary.json` |
| 7 | adversarial tests | **new** | `tests/unit/test_feature_upgrades.py`, `test_cli_upgrades.py` |
| 8 | recovery-method comparison | **new** | `triage/methods.py`, `--compare-with` |
| 9 | trace and hashes | extended | `triage/recipe.py`, `--recipe` |
| 10 | source-to-layer mapping | **new** | `triage/source_map.py`, `--source-map` |
| 11 | target-version syntax checks | **new** | `bytecode/target.py`, `--target-versions` |
| 12 | bounded archive inventory | **new** | `containers/base.py`, `engine/dig.py` |
| 13 | source diffing | **new** | `triage/compare.py` |
| 14 | offline profile | **new** | `--offline` (refuses `--fetch-iocs`) |
| 15 | recovery recipe export | **new** | `triage/recipe.py` |
| 16 | offline HTML report | extended | `output/html.py`: functions, methods, hints, IOC evidence |
| 17 | unsupported-pattern hints | **new** | `triage/confidence.py` `hints()` |
| 18 | decoder plugins | already present; verified | `plugins/__init__.py`, `plugins/backends/community.py` |
| 19 | cross-version testing | already present; extended | `tests/unit/test_version_matrix.py` + new target checker |
| 20 | structured bytecode view | **new** | `bytecode/dump.py`, `--disassemble` |
| 21 | docs for all of it | **new** | `docs/cli.md`, `docs/bytecode.md`, `docs/plugins.md`, README, CHANGELOG |

## Two design calls worth knowing

**PyLingual is a plan/import pair, not a backend.** `tests/unit/test_platform.py`
fails the build if any module imports `subprocess`, and that rule is the reason
the tool is trustworthy. So `--pylingual` prints the exact offline command and
`--pylingual-import` compiles and diffs what you produced with it. You get the
second opinion; the guarantee stays intact.

**`--source-map` claims only what is true.** Line spans are real `ast` numbers in
the file just written, and the stage list is labelled whole-module provenance.
Inventing a per-line original byte offset would have looked more impressive and
been wrong.
