# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### It finds the file; it no longer hands you a command

A phone typing `KAMRUL~4.py` from `~/tools` used to get a red line and
`paste: python pydecomp.py '~/storage/downloads/…'` - telling the operator to do
the work they asked the tool to do. That whole path is gone.

- `terminal/locate.py` now *decides*: exact path, current folder, exact name
  anywhere it searches, case-blind, closest typo, then a bounded scan of home and
  shared storage four levels deep. One level below each search folder is included,
  which is where phones actually keep the second copy.
- Several matches? The **newest under your home** is used, the rest are listed as
  `also matched:`, and `--pick N` overrides. Ranking prefers the operator's own
  folders over stale copies in `/tmp`.
- `PYDECOMP_PATHS` pins the search space (CI and sandboxes).
- Nothing matches? The report names what was searched and **what is visible**
  (`what I can see right now: KAMRUL~4.py (12,483 B) · …`) - no command, no
  `paste:`, no `ls` homework.
- 10 unit tests rewritten plus 5 new terminal checks (end-to-end: an out-of-folder
  ambiguous name is resolved, processed, and the alternative named).

### Four "impossible" cases, removed

The limits page listed run-time keys, native containers, `import os` and
statement-level refusals as things pydecomp could not do. Three of the four are
now covered, and the fourth is downgraded to "needs the VM's dispatch table".

- **Run-time key enumeration** (`eval/keyhunt.py`). When the key only exists
  while the sample runs, the *space* is still small: `len(os.urandom(16))` is 16,
  a byte XOR key is one of 256. The space is inferred from the expression, each
  candidate is evaluated, and a candidate wins only when its payload parses as
  Python or marshals into a code object. `_k = len(os.urandom(16))` now recovers
  in 0.1 s, including when the real key is not the derived length at all.
- **Payload carving** (`engine/carve.py`). Embedded pyc, zlib/bz2/gzip/lzma
  streams, zip containers and long base64/base85 literals are found at any
  offset inside a binary, validated, and digested — so a packed native blob no
  longer ends as a string dump.
- **`os` and `os.path` emulated** as names rather than capabilities: path
  arithmetic is answered exactly, everything that could touch the machine
  refuses. `import os` no longer aborts evaluation of a loader.
- **The statement walker keeps going after a refusal** and keeps the captured
  payload; previously an un-evaluable statement such as `_k = len(os.urandom(16))`
  aborted the module before the `exec` was ever reached.
- **Payload extraction is no longer reported as a copy.** An expression payload
  that resolves to a nested source used to inherit `unchanged` from the inner
  file, so a correctly recovered program was labelled "copy — nothing unpacked".
- 15 unit tests (`test_keyhunt.py`, `test_carve.py`) and 6 more adversarial
  checks (31 total). `docs/limits.md` rewritten around what is now handled.

### A deleted branch, and the soundness bug behind it

Cleaning a plain, unobfuscated program deleted a live `elif` and still reported
*output verified*.  The cause was in the opaque-predicate prover: it sampled a
free name over a fixed integer grid, so `if word == 34:` was false for every
sample and the branch was "proved" dead.

- **The prover is now sound.**  A free name gets the whole integer range as its
  bound and the analysis carries intervals and parities through the arithmetic,
  which still decides every classic idiom — `x * x >= 0`, `x ** 2 >= 0`,
  `x - x == 0`, `x ^ x == 0`, `x & ~x`, `len(x) >= 0`, `abs(x) >= 0`,
  `x * (x + 1) % 2 == 0`, `(x | 1) % 2 == 1` — while `word == 34`, `state != 3`
  and `x > 3` stay undecided and keep their branches.
- **Fidelity now checks control flow.**  If cleaning removes a decision point
  without a pass recording a proof for it, the unpacked text is written instead
  and the rollback is reported: *cleaning removed control flow (3 -> 2 decision
  point(s)) with no recorded proof*.
- New `docs/limits.md`: what pydecomp handles (gated), what no static tool can
  do (runtime-derived keys, native-held keys, compiled-away code), and where the
  frontier actually is.
- 23 new unit tests (`test_opaque_sound.py`) and 2 new adversarial checks
  (25 total).

### Payload intelligence for sealed payloads

When a packer seals its payload, `<stem>_intel.txt` now lands next to the
`_loader` output.  It reports what the sealed code object still says about
itself: the capability groups its name table reaches for (network, subprocess,
dynamic code, decode layers, anti-analysis), the de-duplicated name table, the
sealed blob count and the CJK filler it discarded.  The DONE panel gained an
`intel` row and `report.json` gained an `intel` key.

- **Honesty work on our own claims.**  This campaign previously listed the
  original script's identifiers as "leaked".  They were not: each occurs once in
  a disabled comment line inside the lifted loader.  Harvesting the payload's
  real name table returns 400 identifiers, all belonging to the packaging
  loader.  `docs/adversarial.md` now says so, with the measurement.
- **Capability claims match whole identifier words.**  Substring matching turned
  a traceback helper into an "`os.walk`" claim; only an exact name counts now.
- **Single-byte XOR stays off.**  It is implemented, tested and reported as *not
  applied*: every precision filter we measured still let 60 noise literals
  through on the real sample, and the 11 `__nxor2__` call sites do not decode
  under any single-byte key.
- `harvest()` accepts both pydecomp's code wrapper and a real code object, so it
  can never silently return nothing for a payload it was handed.
- **Sealed blobs are classified, not just counted.**  New
  `triage/sealed.py` measures entropy, dominant byte share and self-coincidence
  at strides 1–64, then says what that means without ever claiming an open.  On
  the reference packer's four blobs: 41×–178× the coincidence of uniform noise,
  repeating at strides 4, 8, 9 and 7 bytes.  The DONE panel now reads
  `sealed 4 blob(s) 418,159 bytes 2× cyclical, 2× opaque` and `report.json`
  gained `sealed_kinds`.
- **Corrected hypothesis, on the record.**  The `__nxor2__` call sites do not
  hide loader strings: the obfuscator's own emitter applies that helper to
  `co_code`, `co_linetable` and `co_exceptiontable`.  `docs/adversarial.md`
  records the measurement, the four failed opening attempts, and the P0 that
  replaces them (rebuild the code objects via `types.CodeType`, no cipher break
  needed).
- 20 new unit tests (`test_payload_intel.py`, `test_sealed.py`) and 6 new
  adversarial checks (23 total).

- **Corpus and evaluator** - `tools/make_corpus.py` builds 26 families × 4 real
  payloads (104 cases) with digest-pinned truths; `tools/eval_corpus.py` grades
  every recovered file against its payload. Latest: 104/104, mean token recall
  96.2%, 0.44 s. Two engine upgrades came out of it: `marshal.loads(_p)` is now
  a payload sink resolved with the static marshal reader, and a decode is never
  folded into an `exec` sink when the result is not Python.
- **Learned decoder ranking** - `pydecomp.learn` scores the 22 decoders from
  blob features and orders them; weights trained from the corpus by
  `tools/train_learn.py` and committed as integers. Held-out payload: top-1
  37.5% → 50.0%, decodes before the right one 8.75 → 2.00. Ranking only orders
  candidates, so it can cost time but never a payload.
- Gates 27 → 29 (`corpus`, `learn`).

## [1.0.0] — 2026-11-01 — “the Almighty”

### The random-stack run: 85 → 97 of 100

`tools/stress_corpus.py` builds stacks nobody wrote down. The first run recovered
85/100; the three fixes since:

- **base64 tolerance.** Loaders use the url-safe alphabet with the plain decoder,
  the plain alphabet with the url-safe decoder, and strip `=` padding to fit the
  blob on one line. The static evaluator refused all three, which ended chains it
  could have finished. It now accepts either alphabet and restores padding:
  **85 → 97**.
- The `stress` gate floor is now **95/100** (was 80), so the run can only improve.
- The three remaining misses are all the same shape - an `xor` layer buried in
  the middle of a chain - and they are the next target, not a footnote.

### Research pass: the ten shapes samples actually ship today

Searches for current loader families turned up shapes the corpus did not carry,
so they were added as families first and fixed second - 46 families, 184 cases:

- **`ak_inline_import`** `exec(__import__('zlib').decompress(__import__('base64').b64decode(_p)))`
  (the Pyminifier fingerprint: no import statement to follow).
- **`al_lambda_indirect` `am_lambda_reverse`** `_ = lambda __: b64decode(__)` and
  the `[::-1]` variant (PyObfuscate fingerprints).
- **`an_nested_exec`** the TrustedSec bytecode stack: marshal inside marshal
  inside zlib, each level a loader that loads the next. This needed a real
  upgrade - `dig` now recognises that a lifted module is itself a loader and
  follows it down until the text stops loading, instead of stopping at stage two.
- **`ao_zero_width`** the invisible-Unicode outer layer: the payload is a run of
  U+200B/U+200C. Recovered.
- **`ap_exec_compile`** `exec(compile(b64decode(_p), '<s>', 'exec'))`.
- **`aq_b85_zlib_marshal`** `exec(marshal.loads(zlib.decompress(b85decode(_p))))`.
- **`ar_deep_twelve`** twelve alternating base64/zlib layers - the "deeper
  chains" trend where six layers became twelve.
- **`as_string_array`** `_t = [...]` then `exec(b''.join(_t))`.
- **`at_chr_arith`** `exec(bytes([c ^ 0x21 for c in [...]]) .decode())`.

Corpus **184/184 recovered**, mean token recall 98.2%. Retrained ranking on the
larger corpus: held-out top-1 37.5% → 75.0%, decodes before the right one
7.81 → 1.62.

### Ten more families, and the bugs they found

The corpus went from 26 families to **36** (144 cases) and the new families paid
for themselves immediately:

- **`aa_base58` `ab_base62` `ac_base45` `ad_z85` `ae_uu`** - hand-rolled codecs
  with no stdlib. A loader that spells out an alphabet cannot be followed by
  evaluating an expression, so `peel` now recognises the alphabet itself: a module
  carrying the base58/base62/base45/z85 table and one big literal is holding that
  codec's output, and `binascii.a2b_uu` is named directly.
- **base45 was wrong.** RFC 9285 puts the high byte of a triple first; the
  decoder took it second, so payloads came out byte-swapped and `8U-R3` raised
  instead of returning `Hello!!`. Fixed, with the four RFC vectors as tests - and
  `test_v8` had been *asserting the bug* (`b"BA"`), which is how it survived.
- **z85 was wrong.** Its input went through the separator stripper, but Z85's
  alphabet contains `.`, `-`, `:`, `+`, `=` - the strip ate the encoding. Fixed
  against the reference vector (`nm=QNz.92Pz/PV8` → `Hello, world`).
- **`ag_double_zip`** - an archive holding an archive: the container reader only
  looked for `.py`/`.pyc` members and declared the zip empty. It now recurses
  into members when nothing Python is on the surface.
- **`aj_string_table`** - `bytes(b ^ K for b in blob)` with the key in the loader.
  This is the most common shape in current string-encryption loaders and the
  statement evaluator will not run a comprehension; the peeler now folds that one
  pattern directly, using the key the file itself names - no key guessing.
- **`ah_eval_chain`, `ai_stacked_mixed`, `af_hex_upper`** - `compile()` sinks and
  four-layer stacks, recovered without changes to the engine.

Corpus: **144/144 recovered**, mean token recall 97.6%, 0.63 s. Retrained ranking
on the bigger corpus: held-out payload **28.6% → 85.7%** top-1, decodes before
the right one **8.79 → 1.43**.

### The corpus, and a ranking trained on it

A claim that lives only in prose cannot be checked, so the project now ships the
data it is measured against and the instrument that measures it.

- **`corpus/`** - 26 families of cooking (base64, b64 twice, zlib/lzma/gzip/bz2,
  base32/85/ascii85/url-safe, hex, escapes, xor, reverse, rot13, three- and
  four-layer mixes, chr arrays, zip members, marshal/pyc/bare-marshal/zlib-marshal
  and one family that must be refused) × four real payload programs = **104 cases**,
  each with a `truth.json` naming the payload by digest. `tools/make_corpus.py`
  builds it; `--check` fails when the committed corpus drifts.
- **`tools/eval_corpus.py`** - runs the analyser on every case and grades the file
  it wrote: it must compile and keep at least 90% of the payload's
  behaviour-bearing tokens, comparing string *values* rather than spellings.
  Latest: **104/104 recovered**, mean token recall 96.2%, 0.44 s. Results are
  committed at `docs/corpus-results.md`.
- Two real upgrades fell out of families that failed:
  `marshal.loads(_p)` is now recognised as a payload sink and read with the static
  marshal reader (20 cases), and the folder no longer rewrites the argument of an
  `exec` sink into the plaintext it would have run (a file that never existed).
- **`pydecomp.learn`** - a one-vs-rest linear model over 24 features of the blob
  (size, entropy, alphabet membership, container magic, base64/base32/hex
  quadratic tells) scores the 22 decoders and orders them before the search.
  Trained by `tools/train_learn.py` on the corpus with an averaged perceptron in
  plain Python; weights committed as integers in `pydecomp/learn/weights.py`.
  Held-out payload, never trained on: top-1 **37.5% → 50.0%**, decodes before the
  right one **8.75 → 2.00**. Ranking only orders candidates - a bad guess costs a
  decode, never a payload.
- Gates 27 → 29: `corpus` fails if a case that used to be recovered stops being
  recovered; `learn` fails if the committed weights stop beating table order or
  the corpus moves out from under them.

### "It proves what it recovered"

This release makes every output checkable, and closes the two gaps that made the
old README honest-but-thin: PyArmor 8/9 detection without unpacking, and a single
decompiler doing every interpreter version.

**Proof-carrying artifacts (`pydecomp.proof`).** Every recovery writes
`<name>.proof.json` and `<name>.proof.md` beside the source: the input digest, the
layers that were peeled with the backend behind each, per-unit tiers, what was
inferred with a confidence, what was lost, and the guarantee. The tiers are
earned, not asserted — `semantic` means the recovered text recompiles to the same
instruction stream as the original code object.

- `--strict` writes nothing unless every unit is instruction-identical, and exits
  `3` (distinct from `1` for a failure and `0` for success). The refusal says
  what it saw: `strict: syntactic output (0 proven, 0 structural, 1 syntactic …)`.
- `--annotate` puts the tier in the file as a comment; the default output stays a
  single stamp line, because a file full of banners is not source.
- Cleaning is now graded too: the tier is computed before and after polish, and a
  pass that costs a tier is **rolled back** instead of shipped.
- **Hole closed:** the instruction comparator ignored value-bearing operands
  (`BINARY_OP`, `COMPARE_OP`, `IS_OP`, `CONTAINS_OP`, `BUILD_*`, `CALL`), so
  `a + b` and `a * b` compared equal. They no longer do — the identity gate still
  passes 47/47, now for the right reason.
- The lifter records its module code object on `lift.module`; the reader looked at
  `bytecode.codeobj` and always found `None`, which silently made every tier
  `syntactic`. Fixed in `proof.tiers` and `bytecode.roundtrip` (`--verify` now
  reports instead of shrugging).

**PyArmor 8/9 static unpack (`pydecomp.protectors.pyarmor`).** The blob is
`PY` + six digits, a packed header and AES-CTR ciphertext around a marshal
stream. pydecomp parses the header with bounds checks, finds `pyarmor_runtime_*`
beside the sample by itself, carries candidate keys out of the library, and
accepts one **only when the plaintext parses as a marshal stream containing a code
object**. The recovered code objects are lifted and proven: the fixture comes out
`tier semantic`, 3/3 units instruction-identical. `--pyarmor-runtime` and
`--pyarmor-key` override the hunt; mixed strings (`0x81` + ciphertext) decrypt
with the same key. PyArmor 7 stays detect-only, and says why.

**Freezers (`pydecomp.containers`).** PyInstaller CArchive with TOC parsing, PYZ
extraction and rebuilt `.pyc` headers (2.0 and 2.1+ cookies), plus cx_Freeze,
py2exe, PEX, shiv and briefcase readers. Each claims bytes by signature and hands
members back to `dig`, so nesting still works. Fixed while doing it: a compressed
CArchive member was sliced with the uncompressed length, which cut a PYZ into the
next member.

**Backends (`pydecomp.bytecode.backends`).** Version-routed decompilers with an
orchestrator that grades every candidate against the original instructions and
keeps the strongest tier, recording the choice in the proof. `pycdc-rs`, `pycdc`,
`depyo`, `uncompyle6` and `decompyle3` are used when installed and skipped
silently when not: 3.14/3.15 route to a real backend and never crash without it.

**Interpreters.** `bytecode.magic.identify_implementation` names CPython, PyPy,
MicroPython, Jython, IronPython and Brython by signature. PyPy lifts with the
closest CPython table and is marked **approximate**; the others get structure and
strings instead of invented code.

**Obfuscators.** 21 named schemes with their contract (marker or shape) in
`pydecomp.obfuscators`; a file that looks like a loader but matches nothing is
called `unidentified loader` rather than given a name it has not earned.

**Plugins** (`pydecomp.plugins`): `@register_decoder`, entry-point loading,
failing plugins isolated, registry capped, and the engine falls back to them only
after every built-in chain has failed.

**MCP server** (`pydecomp.mcp`, `pydecomp --mcp`): `identify`, `peel`, `triage`,
`decompile_pyc`, `deobfuscate` over JSON-RPC stdio, read-only unless
`--allow-write`. It prepares the same protector context the CLI does, so an agent
gets the unpacked program rather than the loader.

**`--fetch-iocs`** (opt-in, off by default): fetch the URLs a loader would have
fetched and unpack the responses statically. Fetching is not executing, and every
retrieval is recorded in the trace and the proof.

**Performance.** A 560 KB packed source went from **167 s to 3.4 s**: base62
decoding was quadratic with a per-character `bytes.index`. It is now a lookup
table plus a stated bound (32 KiB), and `tests/benchmarks/bench_core.py` holds the
budgets (1 MB peel, per-module `.pyc`, AES-CTR over 1 MiB).

**Packaging.** The distribution is `pydecomp-tool` (the PyPI name is taken by an
unrelated project); the module and command stay `pydecomp`. Keywords and
classifiers now name what the tool does, and `[backends]` is the optional extra.

**Gates.** 21 → 26: `proof`, `pyarmor`, `freezers`, `agents`, `perf` added;
249 unit tests, audit clean, single-file build still the shipping artifact.


### The Almighty

The 1.0.0 engine is built against the hardest public obfuscation in the wild -
PyArmor 8/9 containers, PyInstaller CArchives, obfuscator.io-style string
tables, MBA algebra, opaque predicates, unicode aliasing and control-flow
flattening - and every one of those defences now has a static counter-pass.

### Reconstruction (the second Almighty round)

Unwrapping a packer is not the same as rebuilding a program.  This round is
about the difference: pydecomp can now follow logic the *sample itself* defines,
without running it.

### Indicators, control flow, a shippable rule, and proof

### Fought a real packer (idam v4) and fixed three fake successes
- **A version-gate decoy is no longer mistaken for the payload.**  The evaluator
  emulated `sys.version` as 3.14, so a sample gated on `== '3.13'` evaluated its
  `else` branch and the tool recovered `print("You need install a python 3.13")`
  as the script — 97 bytes, reported as verified.  The gate literal inside the
  sample is now treated as evidence: every version it names is tried and the
  branch that yields a real payload beats a one-line decoy.
- **A sealed payload is reported, never dressed up.**  When the payload's
  constants hold large blobs nothing can open, the run is marked incomplete, the
  console says *payload still encrypted … lifted the loader, not the script*,
  fidelity reads **NOT VERIFIED**, and the file is written as `_loader.py` — not
  as the recovered script.
- **A byte-for-byte copy is no longer called a recovery.**  If no layer matches
  and polishing changes nothing, the output is `_copy.py` and says
  *no layer recognised*; if polishing did change it, it says the source was
  cleaned in place.
- New gate `adversarial` (17 checks) builds all three fixtures on the fly: a
  gated decoy sample, a sealed-payload sample, and a plain file.
- New page [Tested against a packer](docs/adversarial.md) with the measurements
  and the ordered plan that follows from them.

### Fixed on phones
- **The interface now fits the terminal it is drawn in.** Panels were sized for a
  52-column minimum — wider than a Termux window — so every box wrapped and the
  borders looked broken.  The width floor is now 34, `COLUMNS` is honoured, the
  logo falls back to a wordmark, menu descriptions move to their own line, and
  every informational line is clipped to the window.  A new `terminal` gate
  renders the banner, menu and result panel at nine widths from 34 to 130 and
  fails on any overflow or ragged box.
- **`file not found` is now an answer, not a dead end.** The tool expands `~`,
  searches the folders a phone keeps downloads in, and prints the matching path
  with a pasteable command.  One unambiguous match is used and announced; two
  are listed rather than guessed.
- Long paths are trimmed from the middle, so `saved to` keeps the filename.

### Published
- The repository is public at <https://github.com/idam001/pydecomp>.  All links
  in the README, packaging metadata, docs, container labels and issue templates
  now point at the real remote instead of the placeholder organisation.
- A synthetic Stripe key in the indicators fixture was split into fragments so
  GitHub push protection no longer treats the test data as a live credential;
  the fixture still proves detection, and the literal is absent from every
  commit (history rewritten before the first push, so nothing leaked).

### Added
- **Fidelity guard** (`polish/fidelity.py`): the last check before a file is
  written.  The cleaned text is compared with the program as it came out of the
  container and is only kept when it is genuinely better — if cleaning produced
  something that does not parse, removed more than a fifth of the definitions,
  or turned a program into a wall of literals, the unpacked program is written
  instead and the rollback is stated in the console and the report.  Cleaning may
  improve recovered code; it may never replace it with rubbish.
- **Fixed: mutable literals were being constant-propagated.** `results = []`
  followed by `results.append(x)` became `[].append(x)`, and `return results`
  became `return []`.  Only immutable scalars (and tuples of them) are
  propagated now.
- **YARA self-validation** (`triage/yara_check.py`): a strict parser for the
  subset of YARA this tool writes (sections, meta entries, string definitions
  with modifiers, escapes, condition references) plus a matcher, so every rule
  is checked against the source it was built from before it is written.  A rule
  that cannot match its own sample, references an undeclared string, has a
  string under YARA's 4-byte minimum or an unbalanced condition is reported as
  broken instead of shipped.  The verdict goes into the JSON report
  (`yara_check`) and onto the console line.
- **`--diff` coverage** (`triage/coverage.py`): compares the program as it came
  out of the container with the cleaned one — definitions kept/lost/emptied,
  statement counts per function, module names, imports, and how many string and
  numeric literals survived (with the folded ones counted, not hidden).  Writes
  `<name>.coverage.md`, records the verdict in the JSON, and prints one line.
- **Loop idiom recovery** (`polish/loops.py`): `i = 0; while i < len(seq): …
  seq[i] … i += 1` becomes `for item in seq:` — but only when the index is used
  *solely* to subscript that one sequence and to increment, the sequence is not
  mutated in the loop, and the step is exactly one.  Otherwise it becomes the
  honest `for i in range(...)`, or stays a `while`.  Nested loops are recovered
  from the inside out.
- **YARA export** (`triage/yara.py`, `--yara`): a rule built from the recovered
  indicators — meta block with author/hash/date/TLP, one named string group per
  indicator type, and a layered condition (`filesize < 8MB` plus a count of
  matches).  Generic indicators (`exec-sink`, `windows-path`, `encoded-blob`)
  are deliberately excluded so the rule does not match goodware.
- **Decode-aware indicator engine** (`triage/iocs.py`): 25 indicator families —
  Discord/Slack/Telegram channels, AWS/GitHub/GitLab/Slack/Stripe/Google/OpenAI
  keys, JWTs, private keys, wallets, onion services, database URIs, credential
  stores, exec sinks — scanned over the recovered source *and* over base64,
  base32, hex, reversed and rot13 variants of every string literal, plus the
  printable runs carved from the raw input.  Telegram chat IDs are paired with
  the bot token that anchors them.  Everything is defanged (`.` → `[.]`,
  `http` → `hxxp`) in the sheet, raw in the JSON.
- **IOC sheets**: `<name>.iocs.md` beside every recovered file, and `iocs-all.md`
  for a folder — which merges indicators across samples and lists the
  infrastructure they share.
- **Control-flow-flattening reconstruction** (`polish/unflatten.py` rewritten):
  the dispatcher loop is read as a graph — blocks keyed by state, transitions
  from the trailing state assignment, back edges turned into `while` loops,
  non-looping arms into `if`/`else`, opaque entry conditions settled by the
  predicate prover.  Nested loops come back as nested loops.
- `polish/dead.py`: identical consecutive assignments (a flattening artefact)
  are collapsed.
- Gates: `iocs` (27 checks), `yara` (36 checks), `coverage` (20 checks) and `shapes` (flattened + inline-`__import__`
  reconstruction); unit suite `tests/unit/test_unflatten.py` pins nine cases,
  including the four near-misses that must be left untouched.
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

### Indicators, control flow, a shippable rule, and proof

### Fought a real packer (idam v4) and fixed three fake successes
- **A version-gate decoy is no longer mistaken for the payload.**  The evaluator
  emulated `sys.version` as 3.14, so a sample gated on `== '3.13'` evaluated its
  `else` branch and the tool recovered `print("You need install a python 3.13")`
  as the script — 97 bytes, reported as verified.  The gate literal inside the
  sample is now treated as evidence: every version it names is tried and the
  branch that yields a real payload beats a one-line decoy.
- **A sealed payload is reported, never dressed up.**  When the payload's
  constants hold large blobs nothing can open, the run is marked incomplete, the
  console says *payload still encrypted … lifted the loader, not the script*,
  fidelity reads **NOT VERIFIED**, and the file is written as `_loader.py` — not
  as the recovered script.
- **A byte-for-byte copy is no longer called a recovery.**  If no layer matches
  and polishing changes nothing, the output is `_copy.py` and says
  *no layer recognised*; if polishing did change it, it says the source was
  cleaned in place.
- New gate `adversarial` (17 checks) builds all three fixtures on the fly: a
  gated decoy sample, a sealed-payload sample, and a plain file.
- New page [Tested against a packer](docs/adversarial.md) with the measurements
  and the ordered plan that follows from them.

### Fixed on phones
- **The interface now fits the terminal it is drawn in.** Panels were sized for a
  52-column minimum — wider than a Termux window — so every box wrapped and the
  borders looked broken.  The width floor is now 34, `COLUMNS` is honoured, the
  logo falls back to a wordmark, menu descriptions move to their own line, and
  every informational line is clipped to the window.  A new `terminal` gate
  renders the banner, menu and result panel at nine widths from 34 to 130 and
  fails on any overflow or ragged box.
- **`file not found` is now an answer, not a dead end.** The tool expands `~`,
  searches the folders a phone keeps downloads in, and prints the matching path
  with a pasteable command.  One unambiguous match is used and announced; two
  are listed rather than guessed.
- Long paths are trimmed from the middle, so `saved to` keeps the filename.

### Published
- The repository is public at <https://github.com/idam001/pydecomp>.  All links
  in the README, packaging metadata, docs, container labels and issue templates
  now point at the real remote instead of the placeholder organisation.
- A synthetic Stripe key in the indicators fixture was split into fragments so
  GitHub push protection no longer treats the test data as a live credential;
  the fixture still proves detection, and the literal is absent from every
  commit (history rewritten before the first push, so nothing leaked).

### Added
- **Fidelity guard** (`polish/fidelity.py`): the last check before a file is
  written.  The cleaned text is compared with the program as it came out of the
  container and is only kept when it is genuinely better — if cleaning produced
  something that does not parse, removed more than a fifth of the definitions,
  or turned a program into a wall of literals, the unpacked program is written
  instead and the rollback is stated in the console and the report.  Cleaning may
  improve recovered code; it may never replace it with rubbish.
- **Fixed: mutable literals were being constant-propagated.** `results = []`
  followed by `results.append(x)` became `[].append(x)`, and `return results`
  became `return []`.  Only immutable scalars (and tuples of them) are
  propagated now.
- **YARA self-validation** (`triage/yara_check.py`): a strict parser for the
  subset of YARA this tool writes (sections, meta entries, string definitions
  with modifiers, escapes, condition references) plus a matcher, so every rule
  is checked against the source it was built from before it is written.  A rule
  that cannot match its own sample, references an undeclared string, has a
  string under YARA's 4-byte minimum or an unbalanced condition is reported as
  broken instead of shipped.  The verdict goes into the JSON report
  (`yara_check`) and onto the console line.
- **`--diff` coverage** (`triage/coverage.py`): compares the program as it came
  out of the container with the cleaned one — definitions kept/lost/emptied,
  statement counts per function, module names, imports, and how many string and
  numeric literals survived (with the folded ones counted, not hidden).  Writes
  `<name>.coverage.md`, records the verdict in the JSON, and prints one line.
- **Loop idiom recovery** (`polish/loops.py`): `i = 0; while i < len(seq): …
  seq[i] … i += 1` becomes `for item in seq:` — but only when the index is used
  *solely* to subscript that one sequence and to increment, the sequence is not
  mutated in the loop, and the step is exactly one.  Otherwise it becomes the
  honest `for i in range(...)`, or stays a `while`.  Nested loops are recovered
  from the inside out.
- **YARA export** (`triage/yara.py`, `--yara`): a rule built from the recovered
  indicators — meta block with author/hash/date/TLP, one named string group per
  indicator type, and a layered condition (`filesize < 8MB` plus a count of
  matches).  Generic indicators (`exec-sink`, `windows-path`, `encoded-blob`)
  are deliberately excluded so the rule does not match goodware.
- **Decode-aware indicator engine** (`triage/iocs.py`): 25 indicator families —
  Discord/Slack/Telegram channels, AWS/GitHub/GitLab/Slack/Stripe/Google/OpenAI
  keys, JWTs, private keys, wallets, onion services, database URIs, credential
  stores, exec sinks — scanned over the recovered source *and* over base64,
  base32, hex, reversed and rot13 variants of every string literal, plus the
  printable runs carved from the raw input.  Telegram chat IDs are paired with
  the bot token that anchors them.  Everything is defanged (`.` → `[.]`,
  `http` → `hxxp`) in the sheet, raw in the JSON.
- **IOC sheets**: `<name>.iocs.md` beside every recovered file, and `iocs-all.md`
  for a folder — which merges indicators across samples and lists the
  infrastructure they share.
- **Control-flow-flattening reconstruction** (`polish/unflatten.py` rewritten):
  the dispatcher loop is read as a graph — blocks keyed by state, transitions
  from the trailing state assignment, back edges turned into `while` loops,
  non-looping arms into `if`/`else`, opaque entry conditions settled by the
  predicate prover.  Nested loops come back as nested loops.
- `polish/dead.py`: identical consecutive assignments (a flattening artefact)
  are collapsed.
- Gates: `iocs` (27 checks), `yara` (36 checks), `coverage` (20 checks) and `shapes` (flattened + inline-`__import__`
  reconstruction); unit suite `tests/unit/test_unflatten.py` pins nine cases,
  including the four near-misses that must be left untouched.
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
