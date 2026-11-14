"""Identity gate: rebuild each source, recompile, diff the instruction streams.

A case passes only when every opcode, canonical operand and argument rendering
matches the original, including branch targets.  Run with
``python3 tests/test_identity.py``.
"""
import os
import py_compile
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pydecomp as P                                     # noqa: E402


CASES = {
 "assign": "x = 1\nname = 'pydecomp'\nprint(name, x)\n",
 "func": "def greet(name):\n    return 'hello ' + name\n\ngreet('a')\n",
 "default": "_K = 90\n\ndef sign(payload, key=_K):\n    return payload + key\n",
 "if_else": "def f(x):\n    if x > 3:\n        return 'big'\n    else:\n        return 'small'\n",
 "ternary": "y = 5 if True else 6\n",
 "for": "out = []\nfor i in range(4):\n    out.append(i * 2)\n",
 "for_filter": "odds = [n for n in range(9) if n % 2]\n",
 "comp": "NUM = [i * 2 for i in range(5)]\n",
 "while": "n = 0\nwhile n < 3:\n    n += 1\n",
 "try": "def g(v):\n    try:\n        return int(v)\n    except ValueError:\n        return 0\n",
 "try2": "def g(v):\n    try:\n        return int(v)\n    except ValueError:\n        return 0\n    except TypeError:\n        return -1\n",
 "with": "def r(p):\n    with open(p) as fh:\n        return fh.read()\n",
 "cls": "class Box:\n    def __init__(self, n):\n        self.n = n\n\n    def tag(self):\n        return self.n\n",
 "deco": "def deco(fn):\n    return fn\n\n@deco\ndef h():\n    return 1\n",
 "kwargs": "def k(a, b=2, *rest, c=3, **kw):\n    return a + b\n\nk(1, 2, 3, c=4)\n",
 "fstring": "def s(n):\n    return f'{n!r:>4}'\n",
 "lambda": "fn = lambda a, b=2: a * b\n",
 "global_": "count = 0\n\ndef bump():\n    global count\n    count += 1\n",
 "slice_": "def cut(xs):\n    return xs[1:-1:2]\n",
 "dictset": "d = {'a': 1, 2: 'b'}\ns = {1, 2, 3}\nt = (1, 2)\nl = [1, 2]\n",
 "aug": "def add(xs):\n    xs += [1]\n    return xs\n",
 "chained": "def c(x):\n    return 0 < x < 10\n",
 "del_": "def d(x):\n    del x\n    return None\n",
 "imports": "import base64, zlib\nfrom json import dumps\n\nX = base64.b64decode('Z2hw').decode()\n",
 "nested_def": "def outer(a):\n    def inner(b):\n        return b + 1\n    return inner(a)\n",
 "raise_": "def r(x):\n    if not x:\n        raise ValueError('no')\n    return x\n",
 "raise_simple": "def fail():\n    raise ValueError('no')\n",
 "set_literal": "values = {1, 2, 3}\n",
 "kwonly_sig": "def only(a, /, b=2, *, c=3):\n    return a + b + c\n",
 "assert_": "def a(x):\n    assert x, 'bad'\n    return x\n",
 "async_": "async def run(x):\n    return x\n",
 "yield_": "def gen(n):\n    for i in range(n):\n        yield i\n",
 "cls_deco": "class A:\n    @staticmethod\n    def f(x):\n        return x\n",
 "nested_loop": "def f(n):\n    t = 0\n    for i in range(n):\n        for j in range(i):\n            t += j\n    return t\n",
 "loop_break": "def f(xs):\n    for x in xs:\n        if x < 0:\n            continue\n        if x > 9:\n            break\n    return x\n",
 "try_finally": "def f(p):\n    try:\n        return open(p).read()\n    finally:\n        print('done')\n",
 "dictcomp": "d = {k: v for k, v in [('a', 1)]}\n",
 "star_args": "def f(*a, **k):\n    return len(a) + len(k)\n\nf(*[1, 2], **{'x': 1})\n",
 "if_elif": "def f(x):\n    if x == 1:\n        return 'a'\n    elif x == 2:\n        return 'b'\n    return 'c'\n",
 "import_fn": "def f():\n    import os\n    return os.sep\n",
 "set_meth": "def f(xs):\n    return sorted(set(xs))\n",
 "nested_call": "def f(a):\n    return len(str(a).strip())\n",
 "genexp": "g = (x * 2 for x in range(3))\n",
 "walrus": "def f(xs):\n    if (n := len(xs)) > 0:\n        return n\n    return 0\n",
 "for_else": "def f(xs):\n    for x in xs:\n        if x:\n            break\n    else:\n        return 1\n",
 "cls_super": "class A:\n    pass\n\n\nclass B(A):\n    def __init__(self):\n        super().__init__()\n",
 "fstr_expr": "def f(a, b):\n    return f'{a + b} items'\n",
 "try_else": "def f(x):\n    try:\n        y = int(x)\n    except ValueError:\n        return -1\n    else:\n        return y\n",
 "multi_assign": "a, b = 1, 2\na, b = b, a\n",
 "comment_str": "def f():\n    \"\"\"doc\"\"\"\n    return 1\n",
}


def main() -> int:
    rows = []
    for label, source in CASES.items():
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "m.py")
        open(path, "w").write(source)
        pyc = py_compile.compile(path, cfile=path + "c", doraise=True)
        version, module = P.parse_pyc(open(pyc, "rb").read())
        text, _score = P.decompile_object(module, version, None)
        if text is None:
            rows.append((label, "FAILED", 0.0, "no source produced"))
            continue
        matched, total, first = P.exact_match(module, text, version)
        rows.append((label, f"{matched}/{total}", matched / max(total, 1), first or ""))
    for label, frac, share, first in rows:
        flag = "ok  " if share == 1.0 else "FAIL"
        print(f"{flag}  {label:12s} {frac:9s} {share:5.2f}  {first[:80]}")
    ok = sum(1 for row in rows if row[2] == 1.0)
    print(f"\ninstruction-identical: {ok}/{len(rows)}")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
