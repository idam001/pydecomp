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
| original identifiers leaked as readable text | `Item`, `parse_rows`, `summarise`, `report`, `main`, `REPORT_TITLE`, `ALERT_LIMIT`, `CONTACT` | — |

So the honest answer for this packer today is: **the payload is not recovered**,
but the analyst gets the packer's identity, the size and count of the sealed
blobs, the fact that the payload is a marshalled module, and the name set the
script defines.  That is intelligence; it is not the script, and the tool says so.

## What has to be built next

Ordered by what this campaign proved is missing.

1. **Fold the packer's own string decoder (P0).**  The loader defines its decoder
   in plain sight:
   `__nxor2__ = lambda data, key: bytes(b ^ key for b in data)` and calls it as
   `__nxor2__(b'…', 229)`.  A static pass that binds lambdas, evaluates their
   bodies with the call-site arguments and replaces the call with the resulting
   literal would expose the loader's strings — the first real crack in this
   family.  The expression evaluator already interprets function bodies; it
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
