# What pydecomp recovers

pydecomp statically analyzes source, bytecode, containers, and encoded layers.
It reconstructs the subset supported by the selected parser and lifter; comments
and original whitespace are generally absent, and protected or native payloads
may remain opaque. Output includes the tier actually earned. A recognized
format or extracted string table is not the same as recovered source, and a
compile check is not a proof of runtime equivalence.

## The path each input takes

| input | what comes back |
|---|---|
| base64 / base32 / base85 / a85 / hex / z85 / base45 / base58 / base62 / uu / rot13 / reverse / escapes | decoded through the full chain, layer by layer, with the chain reported |
| zlib / gzip / bz2 / lzma, nested and mixed with text codecs | decompressed and decoded to the innermost source |
| `exec`/`eval`/`compile` loaders, lambda decoders, alias chains, `getattr`-hidden sinks | statically evaluated: the argument is computed, never run |
| marshal, `.pyc` headers, zip bundles, string tables, `types.CodeType` reconstruction | parsed with version-specific tables; source lifting coverage depends on opcode/construct support |
| XOR and other candidate keys | bounded candidates may be tried; keep a result only when format-specific validation succeeds, and report the validation strength |
| MBA, opaque predicates, control-flow flattening, dead code | simplified only by implemented passes; each rewrite is subject to the project's checks and limits |
| PyArmor-shaped blobs | experimental, key-dependent path; current end-to-end fixture is synthetic and is not evidence of universal vendor compatibility |
| PyInstaller/freezer containers and native images | extract recognized members or metadata; embedded Python bytecode may be lifted, while native machine code is not generally converted back to Python source |
| Nuitka binaries | best-effort constants, strings, module names, and embedded code-object extraction; this is not a full decompilation of Nuitka machine code |

## Key derivation and encrypted payloads

Static key analysis is limited to bounded, explicit candidate sources and
whitelisted expressions. A candidate is not accepted merely because it looks
plausible; the format-specific parser must validate its output. A parseable
marshal stream is structural evidence, not cryptographic authentication.

If a key is supplied at runtime by a license service, is absent from the
provided files, or is protected by an unsupported native routine, pydecomp
cannot infer it from ciphertext alone. It reports the missing input and preserves
recoverable metadata rather than inventing source. Any timing or key-recovery
claim must name the fixture and candidate-space limits used to measure it.

## Compiled and custom targets

- **Nuitka and Cython.** The native front end can inspect supported ELF/PE
  structures, extract strings/constants and recover embedded Python bytecode
  when present. Compiled machine code itself is not lifted back into equivalent
  Python; results must say whether they are source, embedded bytecode, or
  metadata-only.
- **A packer with its own VM.** Static inspection may expose a dispatcher or
  payload, but translating an undocumented VM back to Python is a separate
  feature and is not assumed to succeed automatically.

## Coverage, measured not universal

The generated recovery corpus currently has 74 families × 4 cases (296 total);
the latest recorded run recovered 296/296 at the corpus's token-retention
threshold. A separate gate drives 200 generated stacks up to 24 layers through
13 loader shapes. These are useful regression suites, not proof of coverage for
every real-world protector, Python release, or native build.

## The rule that outranks everything above

A cleaning pass is kept only when the output is still the recovered program. If
control flow disappears without a pass recording a proof for it, the unpacked
text is written instead and the rollback is reported. A wrong simplification is
worse than a missed one.
