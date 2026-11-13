# The expression evaluator

Obfuscated Python is mostly arithmetic. A payload built by joining
`chr()` calls, slicing a reversed string, or XORing a literal does not need a
Python interpreter to recover — it needs a small, safe evaluator that knows
exactly what it is allowed to compute.

## What it is

`pydecomp/eval/` implements a whitelisted interpreter for *pure* expressions:

```python
''.join(chr(c) for c in (104, 101, 108, 108, 111))       # ok
bytes([c ^ 0x5a for c in b'\x32\x37\x36\x37'])           # ok
__import__('os').system('...')                            # refused
open('/etc/passwd').read()                                # refused
socket.socket()                                           # refused
```

## The whitelist

| Layer | Allows |
|---|---|
| names | literals, the builtins in `BUILTINS`, names bound earlier in the same expression |
| imports | modules named in `MODULE_NAMES` (base64, codecs, zlib, binascii, …) |
| calls | methods on `str`, `bytes`, `bytearray`, `list`, `dict`, `set`, `int`, plus `METHOD_NAMES_EXTRA` |
| attributes | only on values the evaluator produced itself |
| statements | none — this evaluates expressions, not programs |

Anything else becomes `_PydecompUnknown`, which is callable, subscriptable,
iterable and falsy. That sentinel is why a half-known expression still produces
readable source instead of `None(...)`.

## Where it runs

| Caller | Use |
|---|---|
| `engine/dig.py` | resolving decoder chains found in the sample text |
| `polish/fold.py` | folding constants the lifter left as expressions |
| `lift/module.py` | resolving import aliases and module-level constants |

Used directly, an `Evaluator` is a stateful namespace: `eval` takes an AST node
and returns a `Val`, `run_body` executes a small body of constant assignments so
later expressions can refer to them.

```python
import ast, pydecomp
engine = pydecomp.Evaluator()
value = engine.eval(ast.parse("'abc'.upper()", mode="eval").body)
value.value      # 'ABC'
value.recipe     # ['upper'] — how it was computed
engine.run_body("KEY = 'abc' + 'def'")      # binds constants for later bodies
```

Methods are only allowed on values the evaluator produced itself, and on names
it resolved from the whitelist — a method call on an unknown name raises
`EvalUnsafe`, which is the point.

## Cost control

- Every evaluation has a step budget; a pathological expression is abandoned,
  not spun on.
- Strings have a length ceiling, so `'a' * 10**9` stops at the ceiling instead of being built.
- Recursion into the evaluator is depth-limited.

## Why not `eval`?

Because the input is hostile. `eval` on sample text — even inside a "safe"
namespace — is one missing dunder away from arbitrary code execution. The
evaluator is an AST walker: there is no bytecode, no frame, and no way for the
sample's text to become executable. `tools/check_static_only.py` enforces this
in CI.

## Testing it

```bash
PYTHONPATH=src python3 tests/integration/test_probes.py     # 37 obfuscator shapes
PYTHONPATH=src python3 -c "
import ast, pydecomp
print(pydecomp.Evaluator().eval(ast.parse(chr(39)*2 + '.join(chr(c) for c in (104,105))' + chr(39)*2, mode='eval').body))"
```

The `probes` gate is the real specification: each shape is a known obfuscator
idiom, and the gate asserts the recovered text contains the plain value.
