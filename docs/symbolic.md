# The symbolic domain

Three of the Almighty's passes need the same thing: a way to ask *what value does
this expression have, for any input*.  The mixed-arithmetic pass needs it to see
through `(a ^ b) + 2 * (a & b)`; the opaque-predicate pass needs it to know that
`x * x >= 0` can only be true; a constant folder needs it to know that a
subexpression does not depend on anything that changes.

`pydecomp.symbolic` is that one place.  It has three parts:

| Module | What it holds |
| --- | --- |
| `symbolic/domain.py` | The values: `SymConst` (an integer), `SymUnknown` (a name), `SymExpr` (an operator over other values), plus `from_ast`, `evaluate`, `to_ast`, `bind_tree`, `unknowns` |
| `symbolic/simplify.py` | The identity library, the prover that guards it, and the rewriter that applies it |
| `symbolic/exec.py` | The executor: walks a recovered module, collapses mixed arithmetic, decides branch predicates, drops the arm that never runs |

Nothing in the domain runs the sample.  A value is built from the source text the
tool already holds, and every transformation is a substitution on that tree.

## The rules are proved, not asserted

A hand-written rule table is a liability: one wrong entry silently changes what
the program computes.  So the library is not installed, it is *proved* - at
import, over a grid of integers, on both halves of every candidate rule:

```
python3 -c "from pydecomp.symbolic.simplify import IDENTITIES, REJECTED; \
            print(len(IDENTITIES), len(REJECTED))"
```

On this build that prints `105 10`.  Both numbers are measured facts about the
checkout, re-measured by `tests/unit/test_symbolic.py`, which re-proves every
installed rule independently of the prover that installed it.

The grid is `-8, -3, -2, -1, 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 255`: negatives
exercise the two's-complement identities, powers of two exercise the shift and
mask ones, and `255` exercises the byte-wide masks that string and CRC code uses.
Three-variable rules get a narrower grid, because fifteen cubed samples per rule
at import is time the user spends waiting for a CLI to start.

What ends up in `REJECTED` is not noise.  It is the list of rules that *looked*
right and are not - `x & (x + y) == x & y`, `(x & y) <= x` (false for negative
`x`), `0 ** x == 1` (false for negative `x`).  A rule that fails one sample is
dropped, and it is never hand-promoted back in.

## Rewriting reduces, always

The library deliberately holds some relations in **both** directions - `x * 2`
and `x << 1` are the same value, and so are `~x ^ y` and `~(x ^ y)`.  That is not
a bug; both halves are true statements.  The rewriter is what has to terminate,
so it accepts a rewrite only when it makes the tree *strictly smaller*, or the
same size and earlier in a fixed ordering.  That gives one normal form per
value, and a finite loop, without any of the rules having to be declared
"the forward one".

The rewriter also declines to restyle code that was never hidden.  An expression
is eligible only when it uses a bitwise or shift operator **and** its leaves are
plain names and integers - the shape mixed boolean arithmetic has and ordinary
source almost never does.  `x * 2` is not rewritten to `x << 1`: both spellings
are the same size, so a rule for it would restyle working code to no purpose.

## Two kinds of decision

**By identity.**  A predicate is rewritten until it is a constant:

```python
from pydecomp.symbolic import prove_true, from_ast
import ast

prove_true(from_ast(ast.parse("(a ^ b) + 2 * (a & b) == a + b", mode="eval").body))
# True
```

**By residue.**  A guard that is a polynomial in its unknown is decided without
any identity at all.  A polynomial with integer coefficients takes the same value
modulo *m* for every integer in a residue class, so *m* samples per unknown cover
the whole line - a proof, not a poll:

```
(x * x + x) % 2 == 0      -> True    every square-plus-self is even
(x ** 3 - x) % 3 == 0     -> True    every cube-minus-self is a multiple of 3
(x * x) % 3 == 2          -> False   a quadratic residue mod 3 is 0 or 1
(x * x) % 3 == 1          -> None    varies, so the branch stays
```

`None` is the answer that keeps code intact, and it is the common answer:
`x * x == 4` depends on `x`, so the branch survives untouched.

## What it looks like on a file

```python
def check(code, key):
    hidden = (code ^ key) + 2 * (code & key)
    masked = (code | key) - (code & key)
    if (hidden * hidden + hidden) % 2 == 0:
        return hidden + masked
    return 0

def guard(x):
    if (x ** 3 - x) % 3 != 0:
        return -1
    return x
```

after the polish pass:

```python
def check(code, key):
    hidden = code + key
    masked = code ^ key
    return hidden + masked

def guard(x):
    return x
```

Both rewrites come from the same three pieces: the two `hidden`/`masked` lines
from the identity library, and both dead arms - the even guard's `else` and the
`return -1` - from the residue prover.  Nothing about this sample is special:
there is no per-obfuscator code here, which is the point.

## Checking it

```
PYTHONPATH=src python3 -m pytest tests/unit/test_symbolic.py   # the domain in isolation
python3 tools/run_gates.py almighty                            # the pass in the pipeline
python3 -c "from pydecomp.symbolic import describe; print(describe())"
```
