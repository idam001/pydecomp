# Examples

Small, self-contained samples and the recovery pydecomp produces for them. Every
sample here is **synthetic**: it is obfuscated on purpose so the shapes are
visible, and none of it is malicious.

```bash
# run every example and compare with the expected output
python3 examples/run_examples.py

# or one at a time
pydecomp examples/01_base64_zlib.py -o /tmp/ex
cat /tmp/ex/01_base64_zlib_deob.py
```

| Example | Shape | What it shows |
|---|---|---|
| `01_base64_zlib.py` | `exec(zlib.decompress(base64.b64decode(...)))` | the classic dropper; two layers, one output file |
| `02_chr_join.py` | `''.join(chr(n) for n in (...))` | the evaluator resolving a character array |
| `03_reversed_layers.py` | base64 inside gzip inside hex | order does not matter; the engine finds it |
| `04_marshal_b64.py` | marshalled code object, base64 wrapped | the bytecode path and the `# rebuilt by pydecomp` preamble |
| `05_mangled_names.py` | `lIIllIlI`-style identifiers | demangling, and the report of every rename |
| `06_zip_bundle.py` | a zip holding a `.pyc` | container + bytecode in one chain |

Expected outputs live in `examples/expected/`. They are compared on structure
(does it compile, does it contain the key strings) rather than byte for byte,
because comments and formatting are free to improve between releases.
