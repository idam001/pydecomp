"""pydecomp - evaluate.

The single biggest reconstruction lever, and the one every serious deobfuscator
converges on: *evaluate only the decode expression*.

A packer does not need a whole program to hide a payload.  It needs one pure
expression whose leaves are literals:

    exec(zlib.decompress(base64.b64decode(_p)[::-1].decode()))

Nothing about that expression needs the program to run.  ``evaluate`` is a
bounded, side-effect-free interpreter for exactly this shape of expression.  It
understands literals, tuples/lists/dicts, arithmetic and slicing, comparisons and
conditionals, comprehensions over literal iterables, f-strings, lambdas, and a
fixed allowlist of pure methods (``.decode``, ``.encode``, ``.replace``,
``.join``, …) and modules (``base64``, ``binascii``, ``zlib``, ``gzip``, ``bz2``,
``lzma``, ``codecs``, ``binascii``) plus a handful of builtins (``chr``, ``ord``,
``bytes``, ``str``, ``map``, ``filter``, ``reversed``, ``sum``, …).

It refuses - loudly, by raising - anything else: attribute access on unknown
objects, imports, name lookups it has not been given, and any result that grows
past the size caps.  pydecomp never imports or executes the sample; this module
evaluates its own whitelist over the sample's *data*.

Two consumers:

* ``fold_expressions`` - a pass that replaces every fully-evaluable expression
  with its value, so a forty-layer decode chain collapses to the payload;
* ``polish/inline.py`` - which uses the same machinery to run a *decoder the
  sample itself defines* (``def d(s): return b64(s[::-1])``) on a literal
  argument.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import lzma
import zlib

from ..polish.demangle import _ast

MAX_STRING = 8 * 1024 * 1024
MAX_SEQUENCE = 200_000
MAX_INT_BITS = 4096
MAX_STEPS = 100_000


class Unevaluable(Exception):
    """The expression is not pure, not understood, or too big to be worth it."""


class _Budget:
    __slots__ = ("steps",)

    def __init__(self, steps: int = MAX_STEPS):
        self.steps = steps

    def tick(self):
        self.steps -= 1
        if self.steps <= 0:
            raise Unevaluable("budget")


def _guard(value):
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise Unevaluable("string too large")
        return value
    if isinstance(value, (bytes, bytearray)):
        if len(value) > MAX_STRING:
            raise Unevaluable("bytes too large")
        return value
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        if len(value) > MAX_SEQUENCE:
            raise Unevaluable("sequence too large")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if value.bit_length() > MAX_INT_BITS:
            raise Unevaluable("integer too large")
        return value
    return value


# ---------------------------------------------------------------------------
# allowlisted modules and methods
# ---------------------------------------------------------------------------

def _b64(blob, validate=False):
    data = blob.encode("latin-1", "ignore") if isinstance(blob, str) else bytes(blob)
    data = bytes(c for c in data if c not in b" \t\r\n")
    return base64.b64decode(data + b"=" * (-len(data) % 4), validate=False)


def _b64url(blob):
    data = blob.encode("latin-1", "ignore") if isinstance(blob, str) else bytes(blob)
    data = bytes(c for c in data if c not in b" \t\r\n")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def _b32(blob):
    data = blob.encode("latin-1", "ignore") if isinstance(blob, str) else bytes(blob)
    data = bytes(c for c in data if c not in b" \t\r\n")
    return base64.b32decode(data + b"=" * (-len(data) % 8))


def _unhex(blob):
    data = blob.encode("latin-1", "ignore") if isinstance(blob, str) else bytes(blob)
    data = bytes(c for c in data if c not in b" \t\r\n:-_")
    return binascii.unhexlify(data)


_MODULES = {
    "base64": {
        "b64decode": _b64,
        "standard_b64decode": _b64,
        "urlsafe_b64decode": _b64url,
        "b32decode": _b32,
        "b16decode": _unhex,
        "unhexlify": _unhex,
        "hexlify": binascii.hexlify,
        "a85decode": base64.a85decode,
        "b85decode": base64.b85decode,
        "b32encode": base64.b32encode,
        "b64encode": base64.b64encode,
    },
    "binascii": {
        "unhexlify": _unhex,
        "a2b_hex": _unhex,
        "a2b_base64": lambda blob: base64.b64decode(
            blob.encode("latin-1") if isinstance(blob, str) else bytes(blob)),
        "hexlify": binascii.hexlify,
        "b2a_base64": binascii.b2a_base64,
    },
    "zlib": {"decompress": zlib.decompress, "compress": zlib.compress},
    "gzip": {"decompress": gzip.decompress},
    "bz2": {"decompress": bz2.decompress},
    "lzma": {"decompress": lzma.decompress},
    "codecs": {"decode": codecs.decode, "encode": codecs.encode},
    "hashlib": {"sha256": lambda blob: hashlib.sha256(
        blob.encode() if isinstance(blob, str) else bytes(blob)).hexdigest(),
        "md5": lambda blob: hashlib.md5(
            blob.encode() if isinstance(blob, str) else bytes(blob)).hexdigest()},
    "bytes": {"fromhex": bytes.fromhex},
    "str": {"join": lambda sep, items: sep.join(items)},
}

_BUILTINS = {
    "chr": chr, "ord": ord, "len": len, "int": int, "str": str, "bytes": bytes,
    "bytearray": bytearray, "list": list, "tuple": tuple, "set": set,
    "frozenset": frozenset, "dict": dict, "sorted": sorted, "reversed": reversed,
    "sum": sum, "min": min, "max": max, "abs": abs, "round": round,
    "hex": hex, "oct": oct, "bin": bin, "bool": bool, "float": float,
    "repr": repr, "ascii": ascii, "enumerate": enumerate, "range": range,
    "map": lambda fn, *seqs: _map(fn, seqs), "filter": None, "zip": zip,
    "pow": pow, "divmod": divmod, "isinstance": None, "join": None,
}

# pure methods on str/bytes/list values
_METHODS = {
    "decode", "encode", "replace", "strip", "lstrip", "rstrip", "split",
    "rsplit", "join", "upper", "lower", "title", "capitalize", "swapcase",
    "zfill", "startswith", "endswith", "find", "rfind", "index", "count",
    "isdigit", "isalpha", "isalnum", "isspace", "islower", "isupper", "format",
    "removeprefix", "removesuffix", "center", "ljust", "rjust", "partition",
    "rpartition", "splitlines", "casefold", "expandtabs", "translate",
    "maketrans", "fromhex", "hex", "insert", "append",
}


def _map(fn, seqs):
    return list(map(fn, *seqs))


class _Module:
    """A module proxy that only exposes the allowlisted functions."""

    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


class _Builtin:
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


class _BoundMethod:
    """A whitelisted method (``.decode``, ``.join``, ``.replace``…) on a value."""

    __slots__ = ("value", "name")

    def __init__(self, value, name):
        self.value = value
        self.name = name


class _NamedFunction:
    """A sample-defined function we are allowed to interpret (see inline.py)."""

    __slots__ = ("params", "defaults", "body", "name", "globals")

    def __init__(self, params, defaults, body, name="", globals=None):
        self.params = params
        self.defaults = defaults
        self.body = body
        self.name = name
        self.globals = globals or {}


class _LambdaFunction(_NamedFunction):
    pass


def module_proxy(name: str):
    return _Module(name) if name in _MODULES else None


# ---------------------------------------------------------------------------
# the interpreter
# ---------------------------------------------------------------------------

def evaluate(node, env=None, budget=None):
    """Evaluate one expression node.  Raises ``Unevaluable`` when it cannot."""
    env = {} if env is None else env
    budget = budget or _Budget()
    budget.tick()
    if isinstance(node, _ast.Constant):
        return node.value
    if isinstance(node, _ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in _BUILTINS and _BUILTINS[node.id] is not None:
            return _Builtin(node.id)
        if node.id in _MODULES:
            return _Module(node.id)
        raise Unevaluable(f"name {node.id}")
    if isinstance(node, _ast.Tuple):
        return tuple(_guard(evaluate(e, env, budget)) for e in node.elts)
    if isinstance(node, _ast.List):
        return list(_guard(evaluate(e, env, budget)) for e in node.elts)
    if isinstance(node, _ast.Set):
        return set(_guard(evaluate(e, env, budget)) for e in node.elts)
    if isinstance(node, _ast.Dict):
        out = {}
        for key, value in zip(node.keys, node.values):
            if key is None:
                raise Unevaluable("dict unpack")
            out[_guard(evaluate(key, env, budget))] = _guard(evaluate(value, env, budget))
        return out
    if isinstance(node, _ast.BinOp):
        return _guard(_binop(node.op, evaluate(node.left, env, budget),
                            evaluate(node.right, env, budget)))
    if isinstance(node, _ast.UnaryOp):
        value = evaluate(node.operand, env, budget)
        try:
            if isinstance(node.op, _ast.USub):
                return -value
            if isinstance(node.op, _ast.UAdd):
                return +value
            if isinstance(node.op, _ast.Invert):
                return ~value
            if isinstance(node.op, _ast.Not):
                return not value
        except Exception as exc:                       # noqa: BLE001
            raise Unevaluable(str(exc)) from None
        raise Unevaluable("unary")
    if isinstance(node, _ast.BoolOp):
        values = [evaluate(v, env, budget) for v in node.values]
        if isinstance(node.op, _ast.And):
            result = values[0]
            for value in values[1:]:
                result = value if not result else value
            return result
        result = values[0]
        for value in values[1:]:
            result = result if result else value
        return result
    if isinstance(node, _ast.Compare):
        left = evaluate(node.left, env, budget)
        for op, comparator in zip(node.ops, node.comparators):
            right = evaluate(comparator, env, budget)
            if not _compare(op, left, right):
                return False
            left = right
        return True
    if isinstance(node, _ast.IfExp):
        return (evaluate(node.body, env, budget) if evaluate(node.test, env, budget)
                else evaluate(node.orelse, env, budget))
    if isinstance(node, _ast.Subscript):
        value = evaluate(node.value, env, budget)
        index = evaluate(node.slice, env, budget) \
            if not isinstance(node.slice, _ast.Slice) else _slice(node.slice, env, budget)
        try:
            return _guard(value[index])
        except Exception as exc:                       # noqa: BLE001
            raise Unevaluable(str(exc)) from None
    if isinstance(node, _ast.Slice):
        return _slice(node, env, budget)
    if isinstance(node, _ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, _ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, _ast.FormattedValue):
                inner = evaluate(value.value, env, budget)
                conversion = value.conversion
                if conversion == ord("r"):
                    inner = repr(inner)
                elif conversion == ord("s"):
                    inner = str(inner)
                spec = ""
                if value.format_spec is not None:
                    spec = str(evaluate(value.format_spec, env, budget))
                parts.append(format(inner, spec))
            else:
                raise Unevaluable("f-string")
        return "".join(parts)
    if isinstance(node, _ast.Attribute):
        if _is_module_name(node.value):
            module = node.value.id
            if module in _MODULES and node.attr in _MODULES[module]:
                return _MODULES[module][node.attr]
            raise Unevaluable(f"{module}.{node.attr}")
        base = evaluate(node.value, env, budget)
        if node.attr in _METHODS and hasattr(base, node.attr):
            return _BoundMethod(base, node.attr)
        raise Unevaluable("attribute")
    if isinstance(node, _ast.Lambda):
        return _make_lambda(node, env)
    if isinstance(node, (_ast.ListComp, _ast.SetComp, _ast.GeneratorExp, _ast.DictComp)):
        return _comprehension(node, env, budget)
    if isinstance(node, _ast.Call):
        return _call(node, env, budget)
    raise Unevaluable(type(node).__name__)


def _is_module_name(node) -> bool:
    return isinstance(node, _ast.Name) and node.id in _MODULES


def _make_lambda(node, env):
    params = [arg.arg for arg in node.args.args]
    defaults = [evaluate(d, env) for d in node.args.defaults]
    return _LambdaFunction(params, defaults, node.body, "<lambda>", env)


def _call(node, env, budget):
    func = evaluate(node.func, env, budget)
    args = []
    for argument in node.args:
        if isinstance(argument, _ast.Starred):
            value = evaluate(argument.value, env, budget)
            try:
                args.extend(value)
            except TypeError:
                raise Unevaluable("starred") from None
        else:
            args.append(evaluate(argument, env, budget))
    kwargs = {}
    for keyword in node.keywords:
        if keyword.arg is None:
            raise Unevaluable("**kwargs")
        kwargs[keyword.arg] = evaluate(keyword.value, env, budget)

    if isinstance(func, _Builtin):
        fn = _BUILTINS.get(func.name)
        if fn is None:
            raise Unevaluable(f"builtin {func.name}")
        try:
            return _guard(fn(*args, **kwargs))
        except Exception as exc:                       # noqa: BLE001
            raise Unevaluable(str(exc)) from None
    if callable(func) and not isinstance(func, (_NamedFunction, _Module)):
        try:
            return _guard(func(*args, **kwargs))
        except Exception as exc:                       # noqa: BLE001
            raise Unevaluable(str(exc)) from None
    if isinstance(func, _NamedFunction):
        return _invoke(func, args, kwargs, budget)
    if isinstance(func, _BoundMethod):
        method = getattr(func.value, func.name, None)
        if method is None or not callable(method):
            raise Unevaluable(f"method {func.name}")
        try:
            return _guard(method(*args, **kwargs))
        except Exception as exc:                       # noqa: BLE001
            raise Unevaluable(str(exc)) from None
    raise Unevaluable("call target")


def _invoke(function, args, kwargs, budget):
    if len(args) > len(function.params):
        raise Unevaluable("arity")
    local = dict(function.globals)
    for index, name in enumerate(function.params):
        if index < len(args):
            local[name] = args[index]
        elif name in kwargs:
            local[name] = kwargs[name]
        else:
            offset = index - (len(function.params) - len(function.defaults))
            if 0 <= offset < len(function.defaults):
                local[name] = function.defaults[offset]
            else:
                raise Unevaluable("missing argument")
    return evaluate(function.body, local, budget)


def _slice(node, env, budget):
    lower = evaluate(node.lower, env, budget) if node.lower is not None else None
    upper = evaluate(node.upper, env, budget) if node.upper is not None else None
    step = evaluate(node.step, env, budget) if node.step is not None else None
    return slice(lower, upper, step)


def _binop(op, left, right):
    try:
        if isinstance(op, _ast.Add):
            return left + right
        if isinstance(op, _ast.Sub):
            return left - right
        if isinstance(op, _ast.Mult):
            if isinstance(left, (str, bytes, list)) and isinstance(right, int) \
                    and len(left) * max(right, 0) > MAX_STRING:
                raise Unevaluable("repeat too large")
            if isinstance(right, (str, bytes, list)) and isinstance(left, int) \
                    and len(right) * max(left, 0) > MAX_STRING:
                raise Unevaluable("repeat too large")
            return left * right
        if isinstance(op, _ast.Div):
            return left / right
        if isinstance(op, _ast.FloorDiv):
            return left // right
        if isinstance(op, _ast.Mod):
            return left % right
        if isinstance(op, _ast.Pow):
            if isinstance(right, int) and isinstance(left, int) and right > 4096:
                raise Unevaluable("power too large")
            return left ** right
        if isinstance(op, _ast.LShift):
            if isinstance(right, int) and right > 64:
                raise Unevaluable("shift")
            return left << right
        if isinstance(op, _ast.RShift):
            return left >> right
        if isinstance(op, _ast.BitAnd):
            return left & right
        if isinstance(op, _ast.BitOr):
            return left | right
        if isinstance(op, _ast.BitXor):
            return left ^ right
    except Unevaluable:
        raise
    except Exception as exc:                           # noqa: BLE001
        raise Unevaluable(str(exc)) from None
    raise Unevaluable("binop")


def _compare(op, left, right) -> bool:
    try:
        if isinstance(op, _ast.Eq):
            return left == right
        if isinstance(op, _ast.NotEq):
            return left != right
        if isinstance(op, _ast.Lt):
            return left < right
        if isinstance(op, _ast.LtE):
            return left <= right
        if isinstance(op, _ast.Gt):
            return left > right
        if isinstance(op, _ast.GtE):
            return left >= right
        if isinstance(op, _ast.Is):
            return left is right
        if isinstance(op, _ast.IsNot):
            return left is not right
        if isinstance(op, _ast.In):
            return left in right
        if isinstance(op, _ast.NotIn):
            return left not in right
    except Exception as exc:                           # noqa: BLE001
        raise Unevaluable(str(exc)) from None
    raise Unevaluable("compare")


def _comprehension(node, env, budget):
    local = dict(env)
    results = []

    def run(generators, depth=0):
        if depth >= len(generators):
            if isinstance(node, _ast.DictComp):
                results.append((evaluate(node.key, local, budget),
                                evaluate(node.value, local, budget)))
            else:
                results.append(evaluate(node.elt, local, budget))
            return
        generator = generators[depth]
        if getattr(generator, "is_async", 0):
            raise Unevaluable("async comprehension")
        iterable = evaluate(generator.iter, local, budget)
        try:
            items = list(iterable)
        except TypeError:
            raise Unevaluable("iterable") from None
        if len(items) > MAX_SEQUENCE:
            raise Unevaluable("iterable too large")
        for item in items:
            if not isinstance(generator.target, _ast.Name):
                raise Unevaluable("complex target")
            local[generator.target.id] = item
            keep = True
            for condition in generator.ifs:
                if not evaluate(condition, local, budget):
                    keep = False
                    break
            if keep:
                run(generators, depth + 1)

    run(node.generators)
    if isinstance(node, _ast.DictComp):
        return dict(results)
    if isinstance(node, _ast.SetComp):
        return set(results)
    return list(results)


# ---------------------------------------------------------------------------
# the pass
# ---------------------------------------------------------------------------

_SKIP = (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef, _ast.Module,
         _ast.Lambda)


def _literal_node(value):
    try:
        node = _ast.parse(repr(value), mode="eval").body
    except Exception:                                  # noqa: BLE001
        return None
    return node


def _interesting(node) -> bool:
    """Only expressions with something to fold are worth the interpreter."""
    for sub in _ast.walk(node):
        if isinstance(sub, (_ast.Call, _ast.Subscript, _ast.BinOp, _ast.JoinedStr)):
            return True
    return False


class _Folder(_ast.NodeTransformer):
    #: calls whose argument stays exactly as written
    SINKS = {"exec", "eval", "compile"}

    def __init__(self, env, budget):
        self.env = env
        self.budget = budget
        self.folded = 0

    def visit_Call(self, node):                        # noqa: N802
        func = node.func
        name = func.id if isinstance(func, _ast.Name) else getattr(func, "attr", "")
        if name not in self.SINKS:
            return self.generic_visit(node)
        # Inside an exec/eval sink, a folded *string* is how obfuscators spell
        # names (`'ex'+'ec'`) and folding it is the point.  A folded *bytes*
        # value is different: it replaces the loader with the plaintext it would
        # have run, and when that plaintext is not Python the operator is handed
        # `exec(b'not a program')` - a file that never existed.  The peeler
        # recovers real payloads properly, so leave bytes alone here.
        self._in_sink = getattr(self, "_in_sink", 0) + 1
        try:
            return self.generic_visit(node)
        finally:
            self._in_sink -= 1

    def visit_FunctionDef(self, node):
        """Fold inside the body, with every name the function binds removed from
        the environment so a parameter can never be read as a module constant."""
        shadow = {a.arg for a in node.args.args + node.args.kwonlyargs
                  + node.args.posonlyargs}
        for extra in (node.args.vararg, node.args.kwarg):
            if extra is not None:
                shadow.add(extra.arg)
        for sub in _ast.walk(node):
            if isinstance(sub, _ast.Name) and isinstance(sub.ctx, _ast.Store):
                shadow.add(sub.id)
        saved = self.env
        self.env = {name: value for name, value in saved.items() if name not in shadow}
        try:
            node.body = [self.visit(stmt) for stmt in node.body]
        finally:
            self.env = saved
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit(self, node):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            return self.visit_FunctionDef(node)
        if isinstance(node, _SKIP):
            return node
        node = super().visit(node)
        if node is None or not _interesting(node):
            return node
        try:
            value = evaluate(node, self.env, self.budget)
        except (Unevaluable, RecursionError):
            return node
        if getattr(self, "_in_sink", 0) and isinstance(value, (bytes, bytearray)):
            from ..decoders.emoji import parses_as_python
            try:
                text = bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is None or not parses_as_python(text):
                return node
        replacement = _literal_node(value)
        if replacement is None:
            return node
        self.folded += 1
        return _ast.copy_location(replacement, node)


def fold_expressions(tree, env=None) -> int:
    """Collapse every fully-evaluable expression to its value."""
    try:
        folder = _Folder(dict(env or {}), _Budget())
        tree.body = [folder.visit(stmt) for stmt in tree.body]
        return folder.folded
    except RecursionError:
        return 0
    except Exception:                                  # noqa: BLE001 - cosmetic pass
        return 0


def evaluate_text(text: str, env=None):
    """Evaluate a snippet the tool is holding as data (never sample code)."""
    try:
        return evaluate(_ast.parse(text, mode="eval").body, dict(env or {}))
    except (Unevaluable, SyntaxError, RecursionError, ValueError):
        return None
