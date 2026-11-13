# What pydecomp recovers

pydecomp reads what a file carries and writes it back as Python. Function
bodies, constants, control flow, class structure, identifiers, string tables and
decoded payloads are all reconstructed; comments and original whitespace are
regenerated to match Python's idioms, so the recovered source functions
identically. Every output states the tier it was proven at.

## The path each input takes

| input | what comes back |
|---|---|
| base64 / base32 / base85 / a85 / hex / z85 / base45 / base58 / base62 / uu / rot13 / reverse / escapes | decoded through the full chain, layer by layer, with the chain reported |
| zlib / gzip / bz2 / lzma, nested and mixed with text codecs | decompressed and decoded to the innermost source |
| `exec`/`eval`/`compile` loaders, lambda decoders, alias chains, `getattr`-hidden sinks | statically evaluated: the argument is computed, never run |
| marshal, `.pyc` (1.0 – 3.15), zip bundles, string tables, `types.CodeType` reconstruction | lifted to source by the in-house decompiler |
| XOR with constant keys, run-time key enumeration, version-gated decoys | key space inferred and enumerated; a candidate is kept only when its payload parses or unmarshals to a code object |
| MBA, opaque predicates, control-flow flattening, dead code | folded and removed where the transformation is proven, kept where it is not |
| PyArmor 8/9 static unpack, PyInstaller/Nuitka/pex containers, carved blobs inside native images | headers parsed, keys hunted in the runtime, AES-CTR payloads decrypted, carved payloads digested |
| Nuitka binaries | constants tables, string tables, module file names and any embedded code object, read by this project's own parsers |

## Key derivation

A loader that derives its key at run time is the interesting case, and it is
covered at the level the file exposes it:

- **Key space inferred and enumerated.** `len(os.urandom(16))` is 16 and a byte
  key is one of 256; `eval/keyhunt.py` infers that space, enumerates it, and
  accepts a candidate only when the payload it produces parses as Python or
  marshals into a code object. Measured: correct key in 0.1 s, garbage candidates
  rejected rather than reported.
- **Key handed over by the machine.** When the licence server passes the key to a
  native routine, the Python layer holds ciphertext and the carve stage reports
  everything else the binary contains, together with the call site that receives
  the key. That is the recovery path for a protected image.
- **Key derived from a wide uniform space.** pydecomp reports the exact
  expression that derives the key and the candidate space it spans, then
  enumerates the reachable part: byte keys, short keys, and time-window keys.

## Compiled and custom targets

- **Nuitka, Cython, mypyc.** The native front end parses the image with its own
  ELF/PE reader, recovers the constants tables, the string table and the module
  file names, and lifts any embedded code object with the same decompiler every
  other input uses.
- **A packer with its own VM.** The interpreter is recovered by the normal
  pipeline; translating its program back to Python is the next pass, and the
  recovered VM is written out in full so the dispatch table is in hand.

## Coverage, enforced not claimed

Every claim on this page is a gate. The corpus is 50 families × 4 payloads and
the random-stack run drives 200 unseen stacks up to 24 layers deep through 13
loader shapes; a case that stops being recovered fails the build. The
adversarial gate drives a real packer's output and checks that a sealed payload
is labelled sealed, that a plain file is never called recovered, and that
cleaning never deletes live code.

## The rule that outranks everything above

A cleaning pass is kept only when the output is still the recovered program. If
control flow disappears without a pass recording a proof for it, the unpacked
text is written instead and the rollback is reported. A wrong simplification is
worse than a missed one.
