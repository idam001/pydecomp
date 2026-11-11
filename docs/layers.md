# Layers and containers

Every obfuscator is a wrapper chain. This page lists what pydecomp unwraps, in
the order it usually meets them, and how it decides a layer is finished.

## Encodings

| Encoding | Detection | Notes |
|---|---|---|
| base64 | alphabet + padding, then a decode round trip | standard and URL-safe; whitespace tolerated |
| base85 | `base64.b85decode` round trip | also `a85` where the sample uses it |
| base32 | alphabet + padding | common in `pyobfus` output |
| hex | even length, hex alphabet, then ASCII ratio | also `0x`-prefixed rows |
| emoji | codepoints mapped back to base64/base32 | the `🐍`-style packing |
| rot13 | text ratio before/after | only when it improves the score |
| decimal/`chr()` chains | literal tuple of ints | folded by the evaluator, not a decoder |

## Compression

| Container | Header | Bound |
|---|---|---|
| zlib | `78 01/9c/da` | `MAX_DECOMPRESSED` |
| gzip | `1f 8b` | same |
| bz2 | `BZh` | same |
| lzma / xz | `fd 37 7a 58 5a` | same |
| zip | `PK\x03\x04` | per-entry |
| raw deflate | attempted last, only with a positive ratio | same |

All decompression is bounded: a declared size is never trusted, and a layer
that expands beyond the ceiling is abandoned instead of eating the machine.

## Compilation layers

| Layer | What pydecomp does |
|---|---|
| `.pyc` | reads the magic, maps it to a CPython version, parses with its own marshal reader |
| bare `marshal` | tries each plausible version, picks the parse that round-trips |
| `compile()` in the sample | recovers the source string handed to `compile` |
| `exec` of a recovered string | follows it, one more layer |

## Payload carriers inside native files

For `.so` and ELF inputs (options 2 and 3, preview): hex and base64 blobs in
`.rodata`, zip archives appended after the last section, and zlib streams
holding `marshal` code trees. See [Native and ELF](native.md).

## How a chain ends

The engine stops when:

1. **Nothing changes.** The best candidate decodes to itself, or the score stops
   improving.
2. **The result is source.** Text that parses as Python and has a higher score
   than the current best wins and the peel stops there (unless a further layer
   scores better).
3. **The ceiling.** 25 layers or 32 MiB per layer.
4. **A cycle.** Seen bytes hash to an already-visited blob.

## Scoring

Candidates are ranked by a cheap score: does it parse, is it mostly text, does
it contain Python keywords, does it shrink, does it keep the strings that were
in the input. The exact weights live in `engine/dig.py` and are deliberately
dull — a wrong decode almost never beats a right one on all four at once.
