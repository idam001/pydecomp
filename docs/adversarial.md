# Tested against a real packer

Reading about obfuscation is not evidence.  This page records what happened when
the tool was pointed at an aggressive third-party Python packer — the *idam v4*
obfuscator, which the operator supplied — and what had to change as a result.

Everything below was produced on Linux with CPython 3.13, running
`dist/pydecomp.py`.  The obfuscated samples were generated locally from a
1.5 KB script; nothing was uploaded anywhere and nothing was executed by the
analyser.

## The input

A small, ordinary program (1,550 bytes): a `class Item`, four functions, a loop
over CSV rows, a few string constants, one `%`-format call.

Two builds were made with the packer's own menu:

| build | options | output |
|---|---|---|
| light | every protection off | 1,213,672 B (783× the input) |
| full | more-obf, anti-debug, anti-trace, anti-hook, self-integrity, opcode remap, string pool, opaque predicates, anti-reconstruct | 1,592,387 B (1,027×) |

Both are a single 1.2 MB expression: a `%s%s%s…`-template chain that rebuilds
names like `__import__` and `marshal` from indexed junk strings, then one giant
decode (`base85 → bz2 → zlib → marshal`) handed to `exec`, guarded by

```python
... if str(sys.version[0:4]) == '3.13' else 'print("You need install a python 3.13")'
```

## What the tool used to do — and why it was wrong

Three of these are the exact failure this project must never ship: a confident
answer that is not the analyst's program.

### 1. It took the decoy branch

The expression engine emulated `sys.version` as a hard-coded `3.14`, so the
3.13 gate above evaluated **false**, the payload expression was skipped, and the
tool recovered the string

```
print("You need install a python 3.13")
```

as the deobfuscated script — 97 bytes, reported as *"fidelity: output verified"*.

**Fixed:** the version gate in a sample is *evidence*.  Every version literal the
file compares `sys.version` against is collected, each is tried, and the branch
that yields a real payload (code object > bytes > structured text) wins over a
one-line decoy.  The hard-coded 3.14 remains only as a fallback.

### 2. It called the packer's loader "the recovered program"

With the branch fixed, the payload resolves to a real code object — but it is
the packer's **loader**, whose own constants carry four sealed blobs (418 KB).
The tool lifted the loader (1.2 MB of library code plus decoys) and reported
*"output verified: still the recovered program"*.

**Fixed:** when the payload's constants contain large blobs that no decoder in
the toolchain can open, the run is marked incomplete:

```
   payload      still encrypted  4 blob(s), 418,159 B — lifted the loader, not the script
   fidelity     NOT VERIFIED — payload still encrypted — the output is the loader
   │ result    loader only — payload encrypted   4 stages
```

and the file is written as `<name>_loader.py`, never `<name>_deob.py`.  The
report carries `"recovered": {"complete": false, …}`.

### 3. It passed a byte-for-byte copy off as a recovery

The full-protection build is written entirely with junk constructs, so no layer
matches; the tool fell back to "it already looks like source", copied the input
and printed *"fidelity: output verified: still the recovered program"*.

**Fixed:** "nothing was unpacked" is now its own verdict.  If polishing changed
nothing, the output is `<name>_copy.py` and the console says *no layer
recognised — saving a copy, not a recovery*.  If polishing did change the
source, it says the source was cleaned in place.  Neither claims a recovery.

## What is actually recovered from these two builds

| | light build | full build |
|---|---|---|
| verdict | loader lifted, payload sealed | nothing unpacked |
| output file | `obf-target_a_loader.py` | `obf-full_copy.py` |
| fidelity | **NOT VERIFIED** | not unpacked |
| functions of the original script | 0 | 0 |
| sealed payload found | 4 blobs, 418,159 B | — |
| names the sealed payload still carries | 400, all from the packer's own loader (`StackSummary`, `tb_frame`, `marshal`, `settrace`) | — |
| names of the original script recovered | **0** | 0 |
| `_intel.txt` written | yes — capabilities, name table, 1,876 sealed blobs, 284 CJK filler strings dropped | — |

So the honest answer for this packer today is: **the payload is not recovered**,
but the analyst gets the packer's identity, the size and count of the sealed
blobs, the fact that the payload is a marshalled module, and what the sealed
payload still says about itself.  That is intelligence; it is not the script, and
the tool says so.

### Why "the name set the script defines" was wrong

An earlier revision of this page listed the original script's identifiers
(`Item`, `parse_rows`, `summarise`, …) as leaked.  They are not.  Each of those
strings occurs exactly **once** in the lifted loader, inside a disabled comment
line, so they come from pydecomp's own comment text rather than from the
payload.  Harvesting the payload's real name table gives 400 identifiers and
**none of them belong to the original script**: they are the packaging loader's
own symbols (`sys`, `marshal`, `StackSummary`, `settrace`, `format`, `getattr`).
The lesson is the one this campaign keeps teaching: a plausible-looking list is
not evidence.

### What the sealed payload does still give up

`<stem>_intel.txt`, written next to a `_loader` output, reports what survived
packaging.  On the light build (0.35 s, one code object, 168,806 B of bytecode):

| section | content |
|---|---|
| reaches for | `anti-analysis` (`_getframe`, `settrace`, `inspect`), `dynamic-code` (`marshal`, `compile`, `eval`, `setattr`), `decode-layers` (`fromhex`), `filesystem` (`open`, `read`), `subprocess` (`system`) |
| name table | 400 identifiers, deduplicated, filler removed |
| sealed blobs | 1,876 byte constants; the 4 that are ≥ 8,192 B are classified, not just counted |
| blob classification | 88,870 B e=4.59 p=4 · 89,012 B e=2.67 p=8 · 134,532 B e=5.88 p=9 · 105,745 B e=5.83 p=7 — all four repeat at a fixed stride |
| CJK filler strings | 284, counted and dropped |

Capability claims match **whole identifier words only**.  Substring matching
turned `_walk_tb_with_full_positions` into an `os.walk` claim during
development, which is exactly the kind of false precision this tool must not
ship.

Each sealed blob is measured, not guessed: entropy, dominant byte share, and
self-coincidence at strides 1–64.  The verdict never says a blob was opened —
it says what the numbers show.  Random data measures 1.0× the coincidence of
uniform noise; these four measure 41× to 178×, so the file says *"data repeats
at a stride of 4 / 8 / 9 / 7 bytes — a repeating-key XOR or a fixed-size record
table; not opened"*.

### The `__nxor2__` sites do not hide strings

The obfuscator's emitter explains them, and it settles a wrong hypothesis of
ours.  In `idam_obf_v4_fixed.py` the `__nb__` helper wraps **bytecode tables**:

```python
def __nb__(bb):
    __nk__ = secrets.randbelow(255) + 1
    return f"__nxor2__({bytes(b ^ __nk__ for b in bb)!r}, {__nk__})"
```

It is applied to `co_code`, `co_linetable` and `co_exceptiontable`, never to
string constants (those go through the string pool).  Decoding all 11 sites in
the lifted loader confirms it: seven decodes are under 50 bytes, two are
134,532 B and 105,745 B of table data, and the only compressed one is a 40-byte
zlib stream that inflates to 32 bytes of `d5,fc5hf;64dy6c16699c6}ej5[f=5Yf`.
There is no readable loader string behind the XOR, so "fold the decoder to
expose the loader's strings" was never going to work.

### The four "sealed" constants are the loader's own code tables

The engine reports four constants that no decoder opens, and calls the payload
sealed.  The verdict (this is the loader, not the script) is right; the reason
needed checking, and here is what the check found.  Two of the four match a
`__nxor2__` site in the lifted loader **byte for byte after a single XOR**:

| payload constant | loader site data | XOR delta |
|---|---|---|
| 134,532 B | 134,532 B | exactly `0xC1` (the site's own key) |
| 105,745 B | 105,745 B | exactly `0x86` (the site's own key) |

One distinct delta across half a megabyte is not a coincidence: those constants
are the loader's own `co_code`/`co_linetable`/`co_exceptiontable`, emitted XOR'd
by the packer's `__nb__` helper and XOR'd again by the sealer.  So the light
build does **not** hide the target script behind these blobs - the script's code
objects are not in this layer at all.  That is why `_loader` and *NOT VERIFIED*
are the honest labels here, and why the next step below is about the emitted
code objects rather than about breaking this cipher.

### What was tried on the big blobs, and failed

Recorded so it is not retried:

| attempt | result |
|---|---|
| single-byte XOR + `marshal` under all 256 keys, exact re-serialisation required | no key round-trips |
| single-byte XOR + zlib/bz2/lzma at every offset 0–63 | no stream opens |
| base85/base64 after single-byte XOR | nothing decodes |
| key recovery assuming the dominant plaintext byte is space | best printable ratio 0.90, and the text is nonsense |

Single-byte XOR over the payload's small byte constants is implemented but **off
by default**: every filter we tried (printable ratio, word shape, vowel
structure, alphabet-run rejection) still let 60 noise literals through on this
sample.  Shipping it would be a false-positive factory, so the report says it
was not applied.

## What has to be built next

Ordered by what this campaign proved is missing.

1. **Rebuild the code objects the loader constructs (P0, full build first).**  The emitter shows
   the shape: `__emmanuelencoder_runner_(argcount, nlocals, stacksize, flags,
   code, consts, names, …, linetable, exceptiontable, …)` with the XOR'd
   bytecode as an argument.  A static pass that evaluates those arguments,
   undoes the XOR and hands the result to `types.CodeType` would rebuild each
   code object **without executing anything**, and `lift_module` would then
   produce the source.  This is the one path that leads to real recovery on this
   family, and it needs no cipher break: the key is the literal second argument.  The expression evaluator already interprets function bodies; it
   needs to be pointed at call sites inside the lifted module.
2. **Follow the loader's own decryptor into the sealed blobs (P0).**  Once (1)
   works, the keys and the order of operations (`base85 → bz2 → zlib →
   marshal`) are readable, and the 418 KB of sealed payload becomes decodable
   statically.
3. **Suppress opaque junk (P1).**  24% of the lifted loader is decoy: `# jump to`
   markers, `if not 1521 == 1521:` blocks, `all([True, 1, 'a'])` guards.  They
   are constant-foldable and should be folded away instead of reproduced.
4. **Detect virtualisation (P1).**  Nothing in this family yet, but the
   compressed-VM packs now common (per-function blobs with a stub that swaps
   `__code__`) need a recogniser that says *virtualised* rather than lifting a
   stub and calling it code.
5. **Report recovered identifiers when the payload is sealed (P2).**  The name
   set above arrived as a comment inside a disabled construct.  It belongs in the
   report, as a plain list of what the script defines.

## Reproducing this

```bash
# obfuscate (the packer's own menu, every answer is y/n)
python idam_obf_v4_fixed.py          # Enter File: target.py, then the options

# analyse — never executes the sample
python dist/pydecomp.py obf-target.py -o out --reports --diff
```

The regression gate for these three failures is `tools/run_gates.py adversarial`;
it builds its fixtures on the fly, so it needs no obfuscator and no binary
fixture in the repository.
