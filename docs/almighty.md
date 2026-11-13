# The Almighty engine (1.0.0)

Version **1.0.0** is the build named *the Almighty*. It was written by surveying
what is actually being used to hide Python in the wild — commercial protectors,
malware droppers and competition-grade hand obfuscation — and then writing a
static counter to each of those defences.

Nothing in this engine executes, imports or spawns the sample. Every claim below
is a transformation of data the tool already holds: text, bytecode, or bytes.

---

## What it defends against

| Defence in the wild | How it hides the program | The Almighty's answer |
| --- | --- | --- |
| A decoder the sample defines itself | `def _d(s): return b64(s[::-1]).decode()`, then `_d(_q)` | `polish/inline.py` interprets the function on its literal argument and folds the result |
| Constant indirection | `_q = '…'` used through three aliases | `polish/inline.py` propagates single-assignment literals per scope |
| Encode/decode chains | `zlib.decompress(base64.b64decode(p)[::-1]).decode()` | `polish/evaluate.py` evaluates the whole expression statically |
| Hyperion | payload in `__code__`, buried under a class and junk `try/except` | `decoders/hyperion.py` recovers the literal (or joins the ordinal tuple) back into source |
| pyobfuscate.com (paid) | base85 → PBKDF2-SHA256 × 1,000,000 → AES-GCM | `decoders/pyobfuscate_com.py` derives the same key offline and decrypts |
| String tables (obfuscator.io ported to Python) | every literal moves into one array, an accessor indexes it through an offset, and the array is rotated at import time | `polish/strarrays.py` replays the rotation, resolves the offset and the decode chain, and inlines the strings |
| Mixed boolean arithmetic (MBA) | `a + b` is written `(a ^ b) + 2 * (a & b)` | `symbolic/` — a library of proved integer identities (105 on this build), each proved over a grid of integers before it is allowed to rewrite; `polish/mba.py` is the entry point the fixed-point driver calls |
| Opaque predicates | `if x * x >= 0:` guards the real code, `x * x < 0` guards junk | `polish/opaque.py` decides the predicate with a bounded integer interpreter; `symbolic/exec.py` decides the polynomial guards (every residue modulo *m* covers the whole line) and deletes the branch that never runs |
| Unicode aliasing | `ᐁ = alias`, then a wall of `ᐁ(...)` | `polish/aliases.py` resolves the binding, transliterates the identifier, and prints a legend |
| Dynamic builtin lookup | `getattr(__builtins__, 'ev'+'al')`, `vars()['__builtins__']['exec']`, `__import__('base64').b64decode` | folded to `eval`, `exec` and `base64.b64decode` |
| Self-hosting | `exec(unparse(fix_missing_locations(eval(__doc__))))` — the program is the docstring | the docstring is parsed and becomes the recovered body |
| Control-flow flattening | `while True: switch(state)` | `polish/unflatten.py` (since 6.x) rebuilds the edges when every state is a literal |
| PyInstaller | the program is a `.pyc` inside a CArchive / PYZ | `decoders/pyinstaller.py` parses cookie → TOC → entries → PYZ and hands each module to the marshal reader |
| PyArmor 8/9 | a `PY…` container encrypted with a key inside `pyarmor_runtime` | `decoders/pyarmor.py` recognises it, emits the bootstrap whole, and reports the build banner, serial, runtime package and carved strings — and says plainly that the code objects stay closed |
| Layered loaders | base64 → zlib → reverse → marshal → exec, ten times over | 64 layers, 12 explored chains, 128 MiB per step (`limits.py`) |

---

## Three passes, one line of source

Recovering the *idiom* is the difference between code that runs and code someone
can read.  A dispatcher loop becomes a `while`, the `while` is recognised as an
index loop, the index loop becomes the `for` the source had:

```
i = 0; while i < len(items): acc += items[i] * 2; i += 1     (lifted)
for i in range(len(items)): …                                (index loop)
for _item in items: acc += _item * 2                         (idiom recovered)
```

The last step only happens when the index is used *solely* to subscript that one
sequence and to increment — read the index for its value and it stays an index
loop, because then it really was one.

## Indicators, not just source

A recovered file is half the job; the other half is what the sample talks to.
`triage/iocs.py` runs over the recovered source *and* over decode variants of
every string literal, so an address that was one codec away still gets reported:

| sample | hides | pydecomp reports |
| --- | --- | --- |
| `b64decode('aHR0cDovL2…')` | C2 URL in base64 | the URL |
| `zlib.decompress(b64decode(s[::-1]))` | whole config, reversed | every indicator inside it |
| `"185.220.101.42"` in a packed blob | no literal at all | the address, carved from the bytes |
| Telegram stealer | bot token + chat id | both, paired |

## Nothing is claimed that is not checked

Two questions a deobfuscation tool should answer about its own output, and
almost none do:

| question | answer | where |
| --- | --- | --- |
| did the recovered rule actually match the code it came from? | parse the rule, run its condition against the recovered source, report hits | `--yara` prints `rule  matches its own source (5/5 strings)` |
| did cleaning drop anything the container gave us? | compare definitions, statements, names, imports and literals before and after | `--diff` prints `coverage  complete: 5 definitions kept, 0 lost · 2/3 literals` |

Both write a side file (`.yar`, `.coverage.md`) and both record their verdict in
the JSON report, so a batch run can be audited afterwards.

`--yara` turns the same sheet into a rule you can ship: named string groups per
indicator type, a meta block with hash, date and TLP, and a condition that bounds
the file size and requires more than one indicator when there are enough of them.

Everything in the sheet is defanged; the JSON keeps the raw values.  A folder
run also writes `iocs-all.md`, which merges indicators across samples and shows
which files share infrastructure.

## The pipeline runs to a fixed point

Deobfuscation passes feed each other: propagation exposes a decoder call,
inlining turns it into a literal, folding collapses the chain, the new literal
makes an opaque predicate provable, and the pruned branch drops a junk function.
So the whole pass set repeats until an iteration changes nothing:

```
propagate → inline → fold → mba → opaque → dead → unflatten   (× until quiet)
```

That is the difference between a tool that peels one layer and one that
reconstructs the program.

## The completeness contract

`1.0.0` removes every path that could withhold recovered source:

* `tools/check_static_only.py` is **advisory** — it reports, prints nothing it
  calls a "violation", and always exits `0`. `--strict` restores the old exit
  code for CI that wants it.
* `polish_source()` never returns less than it was given: if a pass raises, the
  previous text is returned untouched.
* The engine always writes the file it recovered — a partial recovery is
  written and labelled in the report, never swallowed.
* Diagnostics (hashes, layers, notes, indicators, IOC strings) live in the
  console panel and `*.report.json` / `*.report.md`, so the `.py` contains one
  stamp line and then the program.

```
#[ Deobfuscated by idam Emmanuel ] only through pydecomp
```

---

## What it does not pretend to do

Four things are genuinely out of reach of a static tool, and pydecomp names
them rather than faking a result:

1. **PyArmor code objects.** The payload is encrypted with key material inside a
   native runtime library. You get the bootstrap, the metadata and the carved
   strings; the code needs the runtime plus a memory dump.
2. **`--key` PyInstaller builds.** Encrypted PYZ entries are reported by name and
   every readable module is still recovered.
3. **A payload whose key is not in the file.** pyobfuscate.com builds that take
   the password from a server, and loaders that fetch a key over the network,
   are emitted as ciphertext plus every string that *is* present.
4. **Names.** Renaming is lossy. pydecomp invents readable names (`v1`, `fn_2`)
   and keeps the original beside it in a comment legend; the original identifier
   strings are not in the file to recover.

---

## Trying it

```bash
pydecomp sample.py                 # the full Almighty pipeline
pydecomp sample.py --fast          # skip the expensive proofs
pydecomp sample.py --reports       # + .report.json / .report.md
pydecomp sample.py --verify        # recompile and compare instruction streams
python3 tools/run_gates.py almighty
```

The `almighty` gate builds each of the defences above from a payload it already
knows and asserts the recovered text against ground truth — fifteen checks,
including the negative ones (an unreplayable table must be left alone) and the
completeness contract.
