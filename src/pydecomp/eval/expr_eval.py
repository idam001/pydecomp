"""pydecomp - expr_eval."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import bz2
import codecs
import collections
import copy
import functools
import hashlib
import itertools
import json
import lzma
import marshal
import math
import operator
import re
import string
import struct
import types
import zlib

from ..bytecode.codeobj import CodeObj
from ..bytecode.marshal_reader import _MarshalProxy, parse_marshal_blob
from ..eval.builtins import _safe_builtin, _safe_compile
from ..eval.namespace import (
    _BuiltinsModule, _CryptoModule, _FakeSys, _ImportlibModule, _NameSpace,
)
from ..eval.sentinel import _EXEC_SENTINELS, _ExecSentinel
from ..exceptions import _ExprCaptured, _ExprRefuse

class _LocalReturn(Exception):
    """A ``return`` inside a function the analysis is only partly following."""

    def __init__(self, value=None):
        self.value = value

_EXPR_STEP_BUDGET = 400_000

def _coerce_payload(value):
    """Turn anything the sample produced into ``(version, CodeObj)``.

    A live ``types.CodeType`` has to be re-serialised and re-parsed into this
    module's own ``CodeObj`` - the lifter reads the raw marshalled layout, not
    the runtime object, so handing it a real code object just crashes it.
    """
    if isinstance(value, CodeObj):
        return (3, 14), value
    if isinstance(value, types.CodeType):
        try:
            version, obj, _consumed = parse_marshal_blob(marshal.dumps(value))
        except Exception:                            # noqa: BLE001 - exotic object
            return None
        if isinstance(obj, CodeObj):
            return version or (3, 14), obj
    return None

EXPR_MODULES = {"sys", "base64", "zlib", "marshal", "codecs", "binascii", "lzma",
                "builtins", "importlib", "imp", "Crypto", "Cryptodome", "cryptography",
                "bz2", "hashlib", "json", "struct", "string", "math", "itertools",
                "collections", "re", "operator", "functools", "types", "copy"}

EXPR_BUILTINS = {name: getattr(builtins, name) for name in (
    "getattr", "setattr", "vars", "str", "bytes", "bytearray", "int", "float", "bool",
    "chr", "ord", "len", "list", "tuple", "dict", "set", "frozenset", "range", "slice",
    "min", "max", "sum", "sorted", "zip", "map", "filter", "enumerate", "repr", "hex",
    "oct", "bin", "abs", "divmod", "round", "type", "isinstance", "iter", "next",
    "reversed", "format", "ascii", "hash", "object", "complex", "pow", "callable",
) if hasattr(builtins, name)}

class ExprEval:
    """Evaluate the *expression* an obfuscator builds its payload with.

    Nothing from the sample is compiled or run: the analyser walks the ``ast``
    tree itself, with a whitelist of pure builtins, pure module functions and
    methods on plain values, and it intercepts ``exec``/``eval`` to capture the
    payload those calls would have received.
    """

    def __init__(self, libraries=True, target_version: str | None = None):
        self.libraries = libraries
        self.target_version = target_version
        self.ns = dict(EXPR_BUILTINS)
        self._globals = _NameSpace(self, "globals")
        self._builtins_view = _NameSpace(self, "builtins")
        self.ns.update({"__builtins__": self._builtins_view, "__name__": "__main__",
                        "exec": _EXEC_SENTINELS["exec"], "eval": _EXEC_SENTINELS["eval"],
                        "__import__": self.import_module,
                        "globals": self.module_namespace, "locals": self.module_namespace,
                        "vars": self.vars_of, "dir": self.dir_of,
                        "compile": _safe_compile, "__doc__": None,
                        "__file__": "<obfuscated>", "__spec__": None})
        self.marshal = _MarshalProxy()
        self.calls = 0
        self.steps = 0
        self.captured = []

    # ------------------------------------------------------------- evaluation
    @staticmethod
    def _flatten(body) -> list:
        """Every statement reachable without entering a function or class."""
        out = []
        for stmt in body:
            out.append(stmt)
            if isinstance(stmt, ast.Try):
                out.extend(ExprEval._flatten(stmt.body))
                for handler in stmt.handlers:
                    out.extend(ExprEval._flatten(handler.body))
                out.extend(ExprEval._flatten(stmt.orelse))
                out.extend(ExprEval._flatten(stmt.finalbody))
            elif isinstance(stmt, (ast.If, ast.For, ast.While)):
                out.extend(ExprEval._flatten(stmt.body))
                out.extend(ExprEval._flatten(stmt.orelse))
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                out.extend(ExprEval._flatten(stmt.body))
        return out

    # ------------------------------------------------------------- statement VM
    def run_module(self, tree: ast.Module):
        """Walk the module body with a real (bounded) statement machine.

        The earlier version only re-evaluated assignments and plain expression
        statements, so a sample that did ``import zlib`` first, or wrapped its
        loader in ``if __name__ == '__main__':``, or defined a helper function,
        was simply never reached.  Everything below is still pure evaluation:
        no sample code is compiled or handed to the interpreter.
        """
        try:
            self.exec_block(tree.body, self.ns)
        except _ExprCaptured as capture:
            return capture.payload
        except (_ExprRefuse, Exception):             # noqa: BLE001 - best effort
            pass
        self.exec_block(tree.body, self.ns, tolerant=True)
        return None

    def exec_block(self, body, scope, tolerant=False):
        """Execute a block of statements.  ``tolerant`` swallows refusals."""
        for stmt in body:
            if self.steps > _EXPR_STEP_BUDGET:
                raise _ExprRefuse("statement budget")
            self.steps += 1
            try:
                self.exec_stmt(stmt, scope)
            except _ExprCaptured:
                raise
            except _LocalReturn as ret:
                if not tolerant:
                    raise
                return ret.value
            except (_ExprRefuse, Exception):         # noqa: BLE001
                if not tolerant:
                    raise _ExprRefuse("statement")
        return None

    def exec_stmt(self, stmt, scope):
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                module = self.import_module(alias.name)
                scope[alias.asname or alias.name.split(".")[0]] = module
            return
        if isinstance(stmt, ast.ImportFrom):
            if stmt.module is None:
                raise _ExprRefuse("relative import")
            module = self._module(stmt.module.split(".")[0])
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                try:
                    scope[alias.asname or alias.name] = getattr(module, alias.name)
                except AttributeError:
                    pass
            return
        if isinstance(stmt, ast.Assign):
            value = self.eval(stmt.value, scope)
            for target in stmt.targets:
                self.bind(target, value, scope)
            return
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.bind(stmt.target, self.eval(stmt.value, scope), scope)
            return
        if isinstance(stmt, ast.AugAssign):
            current = self.eval(stmt.target, scope)
            value = self.eval(stmt.value, scope)
            table = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
                     ast.BitOr: lambda a, b: a | b, ast.BitXor: lambda a, b: a ^ b,
                     ast.BitAnd: lambda a, b: a & b, ast.Mult: lambda a, b: a * b}
            for klass, fn in table.items():
                if isinstance(stmt.op, klass):
                    self.bind(stmt.target, fn(current, value), scope)
                    return
            raise _ExprRefuse("augassign")
        if isinstance(stmt, ast.Expr):
            return self.eval(stmt.value, scope)
        if isinstance(stmt, ast.If):
            branch = stmt.body if self.eval(stmt.test, scope) else stmt.orelse
            return self.exec_block(branch, scope, tolerant=True)
        if isinstance(stmt, ast.For):
            iterable = self.eval(stmt.iter, scope)
            if isinstance(iterable, (str, bytes)):
                items = list(iterable[:4096])
            else:
                items = list(iterable)[:4096]
            for item in items:
                self.bind(stmt.target, item, scope)
                self.exec_block(stmt.body, scope, tolerant=True)
            return self.exec_block(stmt.orelse, scope, tolerant=True)
        if isinstance(stmt, ast.While):
            guard = 0
            while self.eval(stmt.test, scope):
                guard += 1
                if guard > 64:
                    raise _ExprRefuse("while budget")
                self.exec_block(stmt.body, scope, tolerant=True)
            return self.exec_block(stmt.orelse, scope, tolerant=True)
        if isinstance(stmt, ast.Try):
            try:
                self.exec_block(stmt.body, scope, tolerant=False)
            except _ExprCaptured:
                raise
            except (_ExprRefuse, Exception) as exc:  # noqa: BLE001
                for handler in stmt.handlers:
                    if handler.type is not None:
                        try:
                            wanted = self.eval(handler.type, scope)
                        except Exception:            # noqa: BLE001
                            wanted = BaseException
                        names = wanted if isinstance(wanted, tuple) else (wanted,)
                        if isinstance(exc, _ExprRefuse) and wanted is not BaseException:
                            continue
                        if not isinstance(exc, tuple(t for t in names
                                                     if isinstance(t, type))):
                            continue
                    if handler.name:
                        scope[handler.name] = exc
                    self.exec_block(handler.body, scope, tolerant=True)
                    break
                else:
                    raise
            finally:
                if stmt.finalbody:
                    self.exec_block(stmt.finalbody, scope, tolerant=True)
            return self.exec_block(stmt.orelse, scope, tolerant=True)
        if isinstance(stmt, ast.FunctionDef):
            scope[stmt.name] = self.make_function(stmt, scope)
            return
        if isinstance(stmt, ast.ClassDef):
            return
        if isinstance(stmt, ast.Pass):
            return
        if isinstance(stmt, ast.Return):
            raise _LocalReturn(self.eval(stmt.value, scope) if stmt.value else None)
        if isinstance(stmt, (ast.Global, ast.Nonlocal, ast.Assert, ast.With,
                             ast.AsyncWith, ast.AsyncFor, ast.AsyncFunctionDef)):
            return
        if isinstance(stmt, ast.Raise):
            raise _ExprRefuse("raise")
        if isinstance(stmt, ast.Delete):
            return
        raise _ExprRefuse(type(stmt).__name__)

    def make_function(self, node, scope):
        """A module-level ``def`` in the sample, callable during analysis."""
        spec = node.args
        named = [a.arg for a in spec.posonlyargs + spec.args]
        defaults = [self.eval(d, scope) for d in spec.defaults]
        vararg = spec.vararg.arg if spec.vararg else None
        kwarg = spec.kwarg.arg if spec.kwarg else None

        def call(*args, **kwargs):
            local = dict(scope)
            for index, name in enumerate(named):
                if index < len(args):
                    local[name] = args[index]
                elif name in kwargs:
                    local[name] = kwargs[name]
                elif defaults and index >= len(named) - len(defaults):
                    local[name] = defaults[index - (len(named) - len(defaults))]
            if vararg:
                local[vararg] = tuple(args[len(named):])
            if kwarg:
                local[kwarg] = dict(kwargs)
            try:
                self.exec_block(node.body, local, tolerant=False)
            except _LocalReturn as ret:
                return ret.value
            return None

        call.__name__ = getattr(node, "name", "f")
        return call

    def bind(self, target, value, scope):
        if isinstance(target, ast.Name):
            scope[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            values = list(value) if isinstance(value, (list, tuple, str, bytes)) else []
            for index, element in enumerate(target.elts):
                self.bind(element, values[index] if index < len(values) else None, scope)
            return
        if isinstance(target, ast.Subscript):
            container = self.eval(target.value, scope)
            container[self.eval(target.slice, scope)] = value
            return
        if isinstance(target, ast.Attribute):
            setattr(self.eval(target.value, scope), target.attr, value)
            return
        raise _ExprRefuse("target")

    def eval(self, node, env=None):
        env = self.ns if env is None else env
        if isinstance(node, ast.Expression):
            return self.eval(node.body, env)
        if isinstance(node, ast.Expr):
            return self.eval(node.value, env)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            return _safe_builtin(node.id, self)        # item 1: builtins by name
        if isinstance(node, ast.Lambda):
            spec = node.args
            named = [a.arg for a in spec.posonlyargs + spec.args]
            defaults = [self.eval(d, env) for d in spec.defaults]
            kwonly = [a.arg for a in spec.kwonlyargs]
            kwdefaults = [self.eval(d, env) if d is not None else None
                          for d in spec.kw_defaults]
            vararg = spec.vararg.arg if spec.vararg else None
            kwarg = spec.kwarg.arg if spec.kwarg else None

            def closure(*args, __node=node, __env=env, **kwargs):
                scope = dict(__env)
                filled = list(named[len(named) - len(defaults):]) if defaults else []
                for index, name in enumerate(named):
                    if index < len(args):
                        scope[name] = args[index]
                    elif name in kwargs:
                        scope[name] = kwargs[name]
                    elif defaults and name in filled:
                        scope[name] = defaults[len(named) - len(defaults)
                                               + filled.index(name)]
                if vararg:
                    scope[vararg] = tuple(args[len(named):])
                if kwarg:
                    extra = {k: v for k, v in kwargs.items()
                             if k not in named and k not in kwonly}
                    scope[kwarg] = extra
                for index, name in enumerate(kwonly):
                    if name in kwargs:
                        scope[name] = kwargs[name]
                    elif kwdefaults[index] is not None:
                        scope[name] = kwdefaults[index]
                return self.eval(__node.body, scope)

            return closure
        if isinstance(node, ast.Attribute):
            return getattr(self.eval(node.value, env), node.attr)
        if isinstance(node, ast.Subscript):
            return self.eval(node.value, env)[self.eval(node.slice, env)]
        if isinstance(node, ast.Slice):
            return slice(*(self.eval(part, env) if part is not None else None
                           for part in (node.lower, node.upper, node.step)))
        if isinstance(node, ast.Tuple):
            return tuple(self.eval(item, env) for item in node.elts)
        if isinstance(node, ast.List):
            return [self.eval(item, env) for item in node.elts]
        if isinstance(node, ast.Set):
            return {self.eval(item, env) for item in node.elts}
        if isinstance(node, ast.Dict):
            return {self.eval(k, env): self.eval(v, env)
                    for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.UnaryOp):
            value = self.eval(node.operand, env)
            return {ast.USub: lambda v: -v, ast.UAdd: lambda v: +v,
                    ast.Not: lambda v: not v, ast.Invert: lambda v: ~v}[
                        type(node.op)](value)
        if isinstance(node, ast.BinOp):
            left, right = self.eval(node.left, env), self.eval(node.right, env)
            table = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
                     ast.Mult: lambda a, b: a * b, ast.Div: lambda a, b: a / b,
                     ast.FloorDiv: lambda a, b: a // b, ast.Mod: lambda a, b: a % b,
                     ast.Pow: lambda a, b: a ** b, ast.BitOr: lambda a, b: a | b,
                     ast.BitXor: lambda a, b: a ^ b, ast.BitAnd: lambda a, b: a & b,
                     ast.LShift: lambda a, b: a << b, ast.RShift: lambda a, b: a >> b}
            for klass, fn in table.items():
                if isinstance(node.op, klass):
                    if isinstance(node.op, ast.Mult) and isinstance(left, (str, bytes)) \
                            and len(left) * max(int(right), 0) > 40_000_000:
                        raise _ExprRefuse("huge repeat")
                    return fn(left, right)
            raise _ExprRefuse("binop")
        if isinstance(node, ast.BoolOp):
            values = [self.eval(item, env) for item in node.values]
            result = values[0]
            if isinstance(node.op, ast.And):
                for value in values[1:]:
                    result = value if result else result
            else:
                for value in values[1:]:
                    result = result if result else value
            return result
        if isinstance(node, ast.Compare):
            left = self.eval(node.left, env)
            for op, comparator in zip(node.ops, node.comparators):
                right = self.eval(comparator, env)
                for klass, fn in ((ast.Eq, lambda a, b: a == b),
                                  (ast.NotEq, lambda a, b: a != b),
                                  (ast.Lt, lambda a, b: a < b),
                                  (ast.LtE, lambda a, b: a <= b),
                                  (ast.Gt, lambda a, b: a > b),
                                  (ast.GtE, lambda a, b: a >= b),
                                  (ast.Is, lambda a, b: a is b),
                                  (ast.IsNot, lambda a, b: a is not b),
                                  (ast.In, lambda a, b: a in b),
                                  (ast.NotIn, lambda a, b: a not in b)):
                    if isinstance(op, klass):
                        if not fn(left, right):
                            return False
                        break
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return (self.eval(node.body, env) if self.eval(node.test, env)
                    else self.eval(node.orelse, env))
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    parts.append(str(self.eval(value.value, env)))
                else:
                    raise _ExprRefuse("fstring")
            return "".join(parts)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension(node, env)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        raise _ExprRefuse(type(node).__name__)

    def _comprehension(self, node, env):
        results = []
        generators = node.generators

        def walk(index, scope):
            if index >= len(generators):
                if isinstance(node, ast.DictComp):
                    results.append((self.eval(node.key, scope),
                                    self.eval(node.value, scope)))
                else:
                    results.append(self.eval(node.elt, scope))
                return
            generator = generators[index]
            sequence = self.eval(generator.iter, scope)
            items = sequence if isinstance(sequence, (str, bytes)) else list(sequence)
            for item in items[:200000]:
                inner = dict(scope)
                targets = generator.target.elts \
                    if isinstance(generator.target, ast.Tuple) else [generator.target]
                values = item if isinstance(generator.target, ast.Tuple) else (item,)
                for target, value in zip(targets, values):
                    if not isinstance(target, ast.Name):
                        raise _ExprRefuse("target")
                    inner[target.id] = value
                if all(self.eval(cond, inner) for cond in generator.ifs):
                    walk(index + 1, inner)

        walk(0, dict(env))
        if isinstance(node, ast.SetComp):
            return set(results)
        if isinstance(node, ast.DictComp):
            return dict(results)
        return results

    def module_namespace(self, *args, **kwargs):
        """``globals()`` / ``locals()`` — a live view that resolves builtins."""
        return self._globals

    def vars_of(self, obj=None):
        if obj is None:
            return self._globals
        if isinstance(obj, _NameSpace):
            return obj
        if isinstance(obj, dict):
            return obj
        try:
            return dict(obj.__dict__)
        except AttributeError as exc:
            raise _ExprRefuse("vars") from exc

    def dir_of(self, obj=None):
        if obj is None:
            return sorted(iter(self._globals))
        if isinstance(obj, _NameSpace):
            return sorted(obj.keys())
        try:
            return list(dir(obj))
        except Exception:                            # noqa: BLE001
            return []

    def import_module(self, name, *args, **kwargs):
        """``__import__`` as a first-class object (item 5)."""
        if not isinstance(name, str):
            raise _ExprRefuse("import")
        module = self._module(name.split(".")[0])
        if module is None:
            raise _ExprRefuse(f"import {name}")
        if "." in name:
            try:
                for part in name.split(".")[1:]:
                    module = getattr(module, part)
            except AttributeError as exc:
                raise _ExprRefuse(f"import {name}") from exc
        return module

    def _module(self, name):
        if not self.libraries or name not in EXPR_MODULES:
            raise _ExprRefuse(f"import {name}")
        if name == "builtins":
            return _BuiltinsModule(self)             # defused: exec/eval capture
        if name in ("importlib", "imp"):
            return _ImportlibModule(self)
        if name in ("Crypto", "Cryptodome", "cryptography"):
            return _CryptoModule(self, name)
        return {"sys": _FakeSys(self.target_version), "base64": base64, "zlib": zlib, "codecs": codecs,
                "binascii": binascii, "lzma": lzma, "bz2": bz2, "hashlib": hashlib,
                "json": json, "struct": struct, "string": string, "math": math,
                "itertools": itertools, "collections": collections, "re": re,
                "operator": operator, "functools": functools, "types": types,
                "copy": copy, "marshal": self.marshal}.get(name)

    def _call(self, node, env):
        self.calls += 1
        if self.calls > 2_000_000:
            raise _ExprRefuse("call budget")
        func = self.eval(node.func, env)
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Starred):        # item 4: exec(*args)
                value = self.eval(arg.value, env)
                args.extend(list(value) if isinstance(value, (list, tuple)) else [value])
            else:
                args.append(self.eval(arg, env))
        kwargs = {}
        for kw in node.keywords:
            value = self.eval(kw.value, env)
            if kw.arg is None:
                if isinstance(value, dict):
                    kwargs.update(value)
            else:
                kwargs[kw.arg] = value
        if func is builtins.exec or func is builtins.eval \
                or isinstance(func, _ExecSentinel):
            self.captured.append(args[0] if args else None)
            raise _ExprCaptured(args[0] if args else None)
        if func is builtins.map and args and (isinstance(args[0], _ExecSentinel)
                                             or args[0] in (builtins.exec, builtins.eval)):
            raise _ExprCaptured(list(args[1])[0] if len(args) > 1 and args[1] else None)
        if func is builtins.__import__:
            return self._module(args[0] if args else "")
        if func is builtins.compile:
            return args[0] if args and isinstance(args[0], CodeObj) else (
                args[0] if args else None)
        if func is builtins.open or func is builtins.__build_class__:
            raise _ExprRefuse("refused call")
        if not callable(func):
            raise _ExprRefuse("not callable")
        return func(*args, **kwargs)

_VERSION_GATE = re.compile(r"version\s*\[\s*0\s*:\s*\d\s*\]")
_VERSION_LITERAL = re.compile(r"^[23]\.\d{1,2}$")


def _version_candidates(tree: ast.AST) -> list[str]:
    """Versions the sample itself claims to target, most likely first.

    A packer guards its payload with ``if sys.version[:4] == '3.13'``.  Our
    ``sys`` stub used to answer 3.14 no matter what, so such a sample evaluated
    its *decoy* branch and the tool reported a two-line "install python 3.13"
    warning as the recovered program.  The gate literal is evidence; use it.
    """
    seen: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        texts = [side for side in [node.left, *node.comparators]
                 if isinstance(side, ast.Constant) and isinstance(side.value, str)]
        if not texts:
            continue
        guarded = any(isinstance(side, (ast.Subscript, ast.Attribute, ast.Call))
                      for side in [node.left, *node.comparators])
        for side in texts:
            value = side.value.strip()
            if _VERSION_LITERAL.match(value) and (guarded or len(value) == 4):
                if value not in seen:
                    seen.append(value)
    return seen


def _payload_score(kind: str, value) -> float:
    """How much this looks like the payload rather than a decoy branch."""
    if kind == "code":
        return 100.0 + (len(value[1].code) / 1000.0 if hasattr(value[1], "code") else 0.0)
    if kind == "bytes":
        return 60.0 + min(30.0, len(value) / 1000.0)
    if kind == "text":
        text = value.strip()
        if not text:
            return 0.0
        score = min(40.0, len(text) / 200.0)
        try:
            parsed = ast.parse(text)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return 0.0
        body = [stmt for stmt in parsed.body if not isinstance(stmt, (ast.Import, ast.ImportFrom))]
        score += min(30.0, len(body) * 2.0)
        if len(body) <= 1 and len(text) < 120:      # a one-line warning string
            score *= 0.1
        return score
    return 0.0


def _evaluate_source(tree: ast.AST, target_version: str | None):
    engine = ExprEval(target_version=target_version)
    try:
        payload = engine.run_module(tree)
    except (_ExprRefuse, _ExprCaptured, Exception):   # noqa: BLE001 - best effort
        return None
    return payload


def resolve_expression_payload(source: str):
    """Try to evaluate a source file's own payload expression.

    Returns ``("code", (version, CodeObj))``, ``("text", str)``,
    ``("bytes", bytes)`` or ``None``.  When the sample gates its payload on an
    interpreter version, each version it names is tried and the branch that
    yields a real payload wins over a decoy.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    attempts: list[str | None] = _version_candidates(tree) or [None]
    if None not in attempts and len(attempts) < 3:
        attempts.append(None)                       # also try the stub default
    best: tuple[float, str, object] | None = None
    for candidate in attempts[:3]:
        payload = _evaluate_source(tree, candidate)
        if payload is None:
            continue
        coerced = _coerce_payload(payload)
        if coerced is not None:
            kind, value = "code", coerced
        elif isinstance(payload, CodeObj):
            kind, value = "code", ((3, 14), payload)
        elif isinstance(payload, (bytes, bytearray)):
            kind, value = "bytes", bytes(payload)
        elif isinstance(payload, str):
            kind, value = "text", payload
        elif isinstance(payload, tuple) and len(payload) == 2 \
                and isinstance(payload[1], CodeObj):
            kind, value = "code", payload
        else:
            continue
        score = _payload_score(kind, value)
        if best is None or score > best[0]:
            best = (score, kind, value)
    if best is None:
        return None
    payload = best[2]
    if best[1] == "code":
        return "code", payload
    if best[1] == "bytes":
        return "bytes", payload
    return "text", payload


def _legacy_resolve_expression_payload(source: str):
    """Kept for reference: the single-attempt path this replaced."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    payload = _evaluate_source(tree, None)
    if payload is None:
        return None
    coerced = _coerce_payload(payload)
    if coerced is not None:
        return "code", coerced
    if isinstance(payload, CodeObj):
        # the marshal layout cannot tell 3.11-3.15 apart; the instruction stream
        # can, so let the opcode plausibility choose
        best = (3, 14)          # the sample gates itself on 3.14; trust that
        return "code", (best, payload)
    if isinstance(payload, (bytes, bytearray)):
        return "bytes", bytes(payload)
    if isinstance(payload, str):
        return "text", payload
    if isinstance(payload, tuple) and len(payload) == 2 \
            and isinstance(payload[1], CodeObj):
        return "code", payload
    return None
