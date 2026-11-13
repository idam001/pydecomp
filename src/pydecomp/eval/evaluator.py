"""pydecomp - evaluator."""
from __future__ import annotations

import ast
import itertools

from ..core.util import _cap, to_bytes
from ..core.values import Val
from ..crypto.shims import CIPHER_CONSTANTS, FACTORIES, _Instance
from ..eval.whitelist import BUILTINS, METHOD_NAMES_EXTRA, MODULE_NAMES, WHITELIST
from ..exceptions import (
    EvalFailed, EvalUnsafe, MarshalPayload, _BreakSignal, _ContinueSignal, _EXC_BY_NAME,
    _ReturnSignal,
)
from ..limits import EXEC_SINKS, MAX_LOOP_ROUNDS

#: statements a single simulated body may run.  A round of a decoding loop costs
#: one unit, so this has to be at least as large as the loop cap or a long loop
#: inside a function would be cut off exactly where it matters.
DEFAULT_BUDGET = MAX_LOOP_ROUNDS + 10000

class Evaluator:
    """Evaluate *pure* expressions only. Anything else raises EvalUnsafe."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}     # local name -> canonical dotted path
        self.env: dict[str, Val] = {}         # name -> constant value
        self.lambdas: dict[str, ast.Lambda] = {}
        self.functions: dict[str, ast.AST] = {}   # loader functions we can inline
        self.classes: dict[str, ast.AST] = {}     # loader classes we can instantiate

    # -- name resolution ---------------------------------------------------
    def dotted(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            # __import__('zlib')  /  __import__('base64').b64decode
            f = self.dotted(node.func) if not isinstance(node.func, ast.Call) else ""
            if f in ("__import__", "importlib.import_module"):
                if node.args and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, str):
                    mod = node.args[0].value.split(".")[0]
                    if mod in MODULE_NAMES:
                        return mod
                    raise EvalUnsafe(f"import of {mod!r}")
            # getattr(builtins, "exec")  /  getattr(__import__('zlib'), 'decompress')
            # - the spelling a loader uses when it wants the call to look dynamic
            if f in ("getattr", "builtins.getattr"):
                if len(node.args) == 2 and all(
                        isinstance(a, ast.Constant) and isinstance(a.value, str)
                        for a in node.args[1:]):
                    base = self.dotted(node.args[0])
                    return f"{base}.{node.args[1].value}"
                raise EvalUnsafe("dynamic getattr")
            raise EvalUnsafe("dynamic call in attribute chain")
        if isinstance(node, ast.Subscript):
            raise EvalUnsafe("subscript in attribute chain")
        raise EvalUnsafe(f"unsupported node in dotted name: {type(node).__name__}")

    # -- assignment collection --------------------------------------------
    def absorb(self, tree: ast.Module) -> None:
        """Collect import aliases, constant/lambda assignments, in source order."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in MODULE_NAMES:
                        self.aliases[a.asname or a.name.split(".")[0]] = a.name
                    else:
                        self.aliases[a.asname or a.name.split(".")[0]] = a.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{mod}.{a.name}"

        # `e = exec` / `d = base64.b64decode` / `f = getattr(zlib, "decompress")`
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            source = None
            if isinstance(node.value, ast.Name):
                source = self.aliases.get(node.value.id, node.value.id)
            elif isinstance(node.value, ast.Attribute):
                try:
                    source = self.dotted(node.value)
                except EvalUnsafe:
                    source = None
            else:
                try:
                    source = self._getattr_path(node.value)
                except EvalUnsafe:
                    source = None
            if not source:
                continue
            if source.split(".")[0] not in MODULE_NAMES and source not in EXEC_SINKS \
                    and not source.startswith(("cryptography.", "Crypto.", "Cryptodome.",
                                               "hashlib.", "hmac.", "operator.")):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases.setdefault(target.id, source)

        # loader functions: any def we are asked to call is simulated in place
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
            elif isinstance(node, ast.ClassDef):
                self.classes.setdefault(node.name, node)

        # simulate the module body in order: this is what follows a key that is
        # built by a loop, a comprehension or a chain of temporaries
        try:
            self.run_body(tree.body)
        except (EvalUnsafe, EvalFailed, MarshalPayload):
            pass
        except RecursionError:
            pass

        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                    continue
                name = targets[0].id
                value = node.value
                if value is None or name in self.env:
                    continue
                if isinstance(value, ast.Lambda):
                    self.lambdas[name] = value
                    continue
                try:
                    v = self.eval(value)
                except (EvalUnsafe, EvalFailed, MarshalPayload):
                    continue
                self.env[name] = v

        # second pass: plain constants / lambdas assigned anywhere (nested scopes)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name) or node.value is None:
                continue
            name = targets[0].id
            if name in self.env or name in self.lambdas:
                continue
            if isinstance(node.value, ast.Lambda):
                self.lambdas[name] = node.value
            elif isinstance(node.value, ast.Constant) and \
                    isinstance(node.value.value, (bytes, str, int)):
                self.env[name] = Val(node.value.value, [])

    # -- the evaluator -----------------------------------------------------
    def eval(self, node: ast.AST) -> Val:
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, (bytes, str, int, float, bool)) or v is None:
                return Val(v, [])
            raise EvalUnsafe(f"constant of type {type(v).__name__}")

        if isinstance(node, ast.Name):
            if node.id in self.env:
                v = self.env[node.id]
                return Val(v.value, list(v.recipe))
            raise EvalUnsafe(f"unknown name {node.id!r}")

        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                a, b = self.eval(node.left), self.eval(node.right)
                if isinstance(a.value, bytes) and isinstance(b.value, bytes):
                    return Val(_cap(a.value + b.value), a.recipe + b.recipe)
                if isinstance(a.value, str) and isinstance(b.value, str):
                    return Val(a.value + b.value, a.recipe + b.recipe)
                if isinstance(a.value, (int, float)) and isinstance(b.value, (int, float)) \
                        and not isinstance(a.value, bool) and not isinstance(b.value, bool):
                    return Val(a.value + b.value, a.recipe + b.recipe + ["add"])
                if isinstance(a.value, list) and isinstance(b.value, list):
                    return Val(a.value + b.value, a.recipe + b.recipe + ["concat"])
                if isinstance(a.value, tuple) and isinstance(b.value, tuple):
                    return Val(a.value + b.value, a.recipe + b.recipe + ["concat"])
                raise EvalFailed("mixed-type concatenation")
            if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
                    and isinstance(node.left.value, str):
                # "abc".replace-ish % formatting over constants
                parts = [self.eval(node.right)] if not isinstance(node.right, ast.Tuple) \
                    else [self.eval(e) for e in node.right.elts]
                try:
                    out = node.left.value % tuple(p.value for p in parts)
                except Exception as exc:
                    raise EvalFailed(str(exc))
                rec: list[str] = []
                for p in parts:
                    rec += p.recipe
                return Val(out, rec)
            return self._bitop(node)

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
                and isinstance(node.operand, ast.Constant):
            return Val(-node.operand.value, [])

        if isinstance(node, ast.Subscript):
            base = self.eval(node.value)
            sl = node.slice
            record = base.recipe + ["index"]
            if isinstance(sl, ast.Slice):
                index = slice(self._index(sl.lower), self._index(sl.upper),
                              self._index(sl.step))
                try:
                    return Val(base.value[index], base.recipe + ["slice"])
                except Exception as exc:             # noqa: BLE001 - report and move on
                    raise EvalFailed(f"slice: {exc}")
            index = self._index(sl)
            try:
                return Val(base.value[index], record)
            except Exception as exc:                 # noqa: BLE001 - report and move on
                raise EvalFailed(f"index {index!r}: {exc}")

        if isinstance(node, (ast.List, ast.Tuple)):
            items, rec = [], []
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    inner = self.eval(element.value)
                    items.extend(inner.value)
                    rec += inner.recipe
                    continue
                v = self.eval(element)
                items.append(v.value)
                rec += v.recipe
            return Val(items, rec)

        if isinstance(node, ast.JoinedStr):
            out = ""
            rec = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    out += str(part.value)
                elif isinstance(part, ast.FormattedValue):
                    v = self.eval(part.value)
                    out += str(v.value)
                    rec += v.recipe
                else:
                    raise EvalUnsafe("odd f-string part")
            return Val(out, rec)

        if isinstance(node, ast.Call):
            return self._call(node)

        if isinstance(node, ast.Attribute):
            try:
                base = self.eval(node.value)
            except EvalUnsafe:
                base = None
            if base is not None and isinstance(base.value, _Instance):
                if node.attr in base.value.attrs:
                    return Val(base.value.attrs[node.attr], base.recipe + [f".{node.attr}"])
                raise EvalFailed(f"{base.value.class_name}.{node.attr} is unset")
            path = self.dotted(node)
            if path in CIPHER_CONSTANTS:
                return Val(CIPHER_CONSTANTS[path], [])
            raise EvalUnsafe(f"attribute {path!r} is not a constant")

        if isinstance(node, ast.BinOp):
            return self._bitop(node)

        if isinstance(node, ast.Compare):
            return self._compare(node)

        if isinstance(node, ast.BoolOp):
            values = [self.eval(v) for v in node.values]
            rec = []
            for v in values:
                rec += v.recipe
            if isinstance(node.op, ast.And):
                return Val(all(bool(v.value) for v in values), rec)
            return Val(any(bool(v.value) for v in values), rec)

        if isinstance(node, ast.UnaryOp):
            operand = self.eval(node.operand)
            if isinstance(node.op, ast.Not):
                return Val(not operand.value, operand.recipe)
            if isinstance(node.op, ast.USub):
                return Val(-operand.value, operand.recipe)
            if isinstance(node.op, ast.UAdd):
                return Val(+operand.value, operand.recipe)
            if isinstance(node.op, ast.Invert):
                return Val(~operand.value, operand.recipe)
            raise EvalUnsafe(f"unary {type(node.op).__name__}")

        if isinstance(node, ast.IfExp):
            test = self.eval(node.test)
            return self.eval(node.body if test.value else node.orelse)

        if isinstance(node, ast.Dict):
            keys = [self.eval(k) for k in node.keys]
            values = [self.eval(v) for v in node.values]
            out = {}
            rec = []
            for k, v in zip(keys, values):
                out[k.value] = v.value
                rec += k.recipe
                rec += v.recipe
            return Val(out, rec)

        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            values, rec = self._comprehend(node, "list")
            if isinstance(node, ast.SetComp):
                values = list(dict.fromkeys(values))
            return Val(values, rec)

        if isinstance(node, ast.DictComp):
            pairs, rec = self._comprehend(node, "dict")
            return Val(dict(pairs), rec)

        if isinstance(node, ast.Starred):
            inner = self.eval(node.value)
            return Val(list(inner.value), inner.recipe)

        raise EvalUnsafe(f"unsupported expression: {type(node).__name__}")

    def _call(self, node: ast.Call) -> Val:
        """Dispatch a call, and never let a simulated call crash the analysis.

        Everything below this line runs *whitelisted* pure code, and pure code
        can still raise on bad input: `bytearray.append(300)`, `to_bytes` on a
        number that does not fit, `int("zz")`.  Those are the loader's bug and
        they end this branch only - a whole file must not die because one
        decoder was called with nonsense.
        """
        try:
            return self._dispatch_call(node)
        except (EvalUnsafe, EvalFailed, MarshalPayload):
            raise
        except RecursionError:
            raise EvalFailed("call nested too deeply")
        except Exception as exc:                    # noqa: BLE001 - a miss, not a crash
            raise EvalFailed(f"call failed: {type(exc).__name__}: {exc}")

    def _dispatch_call(self, node: ast.Call) -> Val:
        func = node.func

        # lambda loader:  _ = lambda __: zlib.decompress(base64.b64decode(__))
        if isinstance(func, ast.Name) and func.id in self.lambdas:
            lam = self.lambdas[func.id]
            if node.keywords:
                raise EvalUnsafe("kwargs into lambda loader")
            args = [self.eval(a) for a in node.args]
            rec: list[str] = []
            for a in args:
                rec += a.recipe
            saved = dict(self.env)
            try:
                for p, a in zip(lam.args.args, args):
                    self.env[p.arg] = a
                inner = self.eval(lam.body)
            finally:
                self.env = saved
            return Val(inner.value, rec + inner.recipe)

        # method call on a statically-known receiver:
        #   "".join([...]) / blob.decode('utf-8') / <call>.decode()
        if isinstance(func, ast.Attribute):
            receiver = None
            try:
                receiver = self.eval(func.value)
            except (EvalUnsafe, EvalFailed):
                receiver = None
            if receiver is not None:
                return self._method(receiver, func.attr, node)

        if isinstance(func, ast.Name) and func.id in self.classes:
            return self._instantiate(self.classes[func.id], node)

        if isinstance(func, ast.Name) and func.id in self.functions:
            return self._call_function(self.functions[func.id], node)

        path = self._getattr_path(func) or self.dotted(func)

        if path in ("globals", "locals", "vars") and not node.args:
            visible = {name: val.value for name, val in self.env.items()
                       if not name.startswith("_pydecomp_")}
            return Val(visible, ["globals"])

        if path in FACTORIES:
            args = [self.eval(a) for a in node.args]
            kwargs = {}
            for kw in node.keywords:
                if kw.arg is None:
                    raise EvalUnsafe("**kwargs")
                kwargs[kw.arg] = self.eval(kw.value).value
            rec: list[str] = []
            for a in args:
                rec += a.recipe
            try:
                out = FACTORIES[path](*[a.value for a in args], **kwargs)
            except EvalUnsafe:
                raise
            except MarshalPayload:
                raise
            except Exception as exc:                 # noqa: BLE001 - report and move on
                raise EvalFailed(f"{path}: {exc}")
            if isinstance(out, Val):
                return Val(out.value, rec + out.recipe)
            return Val(out, rec)

        if path in BUILTINS:
            args = [self.eval(a) for a in node.args]
            kwargs = {}
            for kw in node.keywords:
                if kw.arg is None:
                    raise EvalUnsafe("**kwargs")
                kwargs[kw.arg] = self.eval(kw.value).value
            rec = []
            for a in args:
                rec += a.recipe
            try:
                out = BUILTINS[path](*[a.value for a in args], **kwargs)
            except EvalUnsafe:
                raise
            except Exception as exc:                 # noqa: BLE001 - report and move on
                raise EvalFailed(f"{path}(): {exc}")
            return Val(out, rec + [path])

        # marshal.loads: never unmarshal untrusted data (crash/exploit risk).
        # Surface the blob so the analyst can decide what to do next.
        if path in ("marshal.loads", "marshal.load"):
            if not node.args:
                raise EvalFailed("marshal.loads without argument")
            arg = self.eval(node.args[0])
            if isinstance(arg.value, (bytes, bytearray)):
                raise MarshalPayload(bytes(arg.value), arg.recipe.copy())
            raise EvalFailed("marshal.loads of non-constant")

        if path not in WHITELIST:
            raise EvalUnsafe(f"call to non-whitelisted {path!r}")

        impl, label = WHITELIST[path]
        args = [self.eval(a) for a in node.args]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg is None:
                raise EvalUnsafe("**kwargs")
            kwargs[kw.arg] = self.eval(kw.value).value
        rec: list[str] = []
        for a in args:
            rec += a.recipe
        try:
            out = impl(*[a.value for a in args], **kwargs)
        except EvalUnsafe:
            raise
        except MarshalPayload:
            raise
        except Exception as exc:
            raise EvalFailed(f"{label}: {exc}")
        return Val(out, rec + [label])

    def _index(self, node):
        if node is None:
            return None
        value = self.eval(node).value
        if isinstance(value, (int, slice, str, bytes, tuple, float, bool)):
            return value
        raise EvalFailed(f"index of type {type(value).__name__}")

    # -- comprehensions, comparisons, bit tricks ---------------------------
    def _comprehend(self, node, kind):
        """Evaluate a comprehension over constant iterables (never calls out)."""
        out, rec, budget = [], [], [200000]

        def run(index, local):
            budget[0] -= 1
            if budget[0] < 0:
                raise EvalUnsafe("comprehension budget exhausted")
            if index == len(node.generators):
                saved = dict(self.env)
                self.env.update(local)
                try:
                    if kind == "dict":
                        out.append((self.eval(node.key).value, self.eval(node.value).value))
                    else:
                        out.append(self.eval(node.elt).value)
                finally:
                    self.env = saved
                return
            gen = node.generators[index]
            saved = dict(self.env)
            self.env.update(local)
            try:
                seq = self.eval(gen.iter).value
            except (EvalUnsafe, EvalFailed):
                self.env = saved
                raise
            self.env = saved
            if isinstance(seq, (str, bytes)):
                seq = list(seq)
            if not isinstance(seq, (list, tuple, range)):
                raise EvalUnsafe("comprehension over a non-constant iterable")
            for item in itertools.islice(seq, 100000):
                bound = dict(local)
                bound.update(self._bind(gen.target, Val(item, [])))
                saved = dict(self.env)
                self.env.update(bound)
                try:
                    keep = all(bool(self.eval(cond).value) for cond in gen.ifs)
                except (EvalUnsafe, EvalFailed):
                    self.env = saved
                    raise
                finally:
                    self.env = saved
                if keep:
                    run(index + 1, bound)

        run(0, {})
        return out, rec

    def _bind(self, target, val):
        """Turn `for a, b in ...` into a dict of bindings."""
        out = {}
        if isinstance(target, ast.Name):
            out[target.id] = val
        elif isinstance(target, (ast.Tuple, ast.List)):
            try:
                items = list(val.value)
            except TypeError:
                raise EvalUnsafe("cannot unpack comprehension target")
            if len(items) != len(target.elts):
                raise EvalFailed("unpack length mismatch")
            for sub, item in zip(target.elts, items):
                out.update(self._bind(sub, Val(item, [])))
        else:
            raise EvalUnsafe("unsupported comprehension target")
        return out

    def _compare(self, node):
        left = self.eval(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = self.eval(comparator)
            a, b = left.value, right.value
            if isinstance(op, ast.Eq):
                verdict = a == b
            elif isinstance(op, ast.NotEq):
                verdict = a != b
            elif isinstance(op, ast.Lt):
                verdict = a < b
            elif isinstance(op, ast.LtE):
                verdict = a <= b
            elif isinstance(op, ast.Gt):
                verdict = a > b
            elif isinstance(op, ast.GtE):
                verdict = a >= b
            elif isinstance(op, ast.In):
                verdict = a in b
            elif isinstance(op, ast.NotIn):
                verdict = a not in b
            elif isinstance(op, ast.Is):
                verdict = a is b
            elif isinstance(op, ast.IsNot):
                verdict = a is not b
            else:
                raise EvalUnsafe(f"comparison {type(op).__name__}")
            if not verdict:
                return Val(False, left.recipe + right.recipe)
            left = right
        return Val(True, left.recipe)

    def _bitop(self, node):
        left, right = self.eval(node.left), self.eval(node.right)
        a, b = left.value, right.value
        rec = left.recipe + right.recipe
        op = node.op
        try:
            if isinstance(op, ast.BitXor):
                if isinstance(a, (int,)) and isinstance(b, (int,)):
                    return Val(a ^ b, rec + ["xor"])
                raise EvalFailed("^ needs integers")
            if isinstance(op, ast.BitAnd):
                return Val(a & b, rec + ["and"])
            if isinstance(op, ast.BitOr):
                return Val(a | b, rec + ["or"])
            if isinstance(op, ast.LShift):
                return Val(a << b, rec + ["shl"])
            if isinstance(op, ast.RShift):
                return Val(a >> b, rec + ["shr"])
            if isinstance(op, ast.Sub) and isinstance(a, int) and isinstance(b, int):
                return Val(a - b, rec + ["minus"])
            if isinstance(op, ast.Mult):
                if isinstance(a, (str, bytes)) and isinstance(b, int):
                    return Val(_cap(a * b) if isinstance(a, bytes) else a * b, rec + ["repeat"])
                if isinstance(a, int) and isinstance(b, (str, bytes)):
                    return Val(b * a, rec + ["repeat"])
                if isinstance(a, int) and isinstance(b, int):
                    return Val(a * b, rec + ["mul"])
            if isinstance(op, ast.FloorDiv) and isinstance(b, int) and b:
                return Val(a // b, rec + ["div"])
            if isinstance(op, ast.Div) and isinstance(b, int) and b:
                return Val(a / b, rec + ["div"])
            if isinstance(op, ast.Mod) and isinstance(a, int) and isinstance(b, int) and b:
                return Val(a % b, rec + ["mod"])
            if isinstance(op, ast.Pow) and isinstance(a, int) and isinstance(b, int) and 0 <= b <= 64:
                return Val(a ** b, rec + ["pow"])
        except EvalUnsafe:
            raise
        except Exception as exc:                     # noqa: BLE001 - report as EvalFailed
            raise EvalFailed(f"bitop: {exc}")
        raise EvalUnsafe(f"binary operator {type(op).__name__}")

    def _instantiate(self, classdef, node):
        """Build an instance and run `__init__` on it, statically."""
        args = [self.eval(a) for a in node.args]
        kwargs = {kw.arg: self.eval(kw.value) for kw in node.keywords if kw.arg}
        rec: list[str] = []
        for value in args + list(kwargs.values()):
            rec += value.recipe
        instance = _Instance(classdef.name)
        init = next((stmt for stmt in classdef.body
                     if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and stmt.name == "__init__"), None)
        if init is not None:
            self._run_method(init, instance, args, kwargs)
        return Val(instance, rec + [f"{classdef.name}()"])

    def _call_method(self, instance, attr, values, kwargs, rec):
        classdef = self.classes.get(instance.class_name)
        if classdef is None:
            raise EvalUnsafe(f"unknown class {instance.class_name}")
        method = next((stmt for stmt in classdef.body
                       if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and stmt.name == attr), None)
        if method is None:
            if attr in instance.attrs:
                return Val(instance.attrs[attr], rec + [f".{attr}"])
            raise EvalUnsafe(f"{instance.class_name}.{attr} is not a method")
        holder = [Val(value, []) for value in values]
        result = self._run_method(method, instance, holder, kwargs)
        return Val(result.value, rec + result.recipe)

    def _run_method(self, method, instance, arg_vals, kwargs):
        """Simulate one method body with `self` bound to ``instance``."""
        spec = method.args
        positional = list(getattr(spec, "posonlyargs", [])) + list(spec.args)
        if positional and positional[0].arg in ("self", "cls", "this", "obj"):
            positional = positional[1:]
        saved_env, saved_functions = dict(self.env), dict(self.functions)
        try:
            self.env["self"] = Val(instance, [])
            for index, param in enumerate(positional):
                if index < len(arg_vals):
                    value = arg_vals[index]
                    self.env[param.arg] = Val(value.value if isinstance(value, Val) else value,
                                              list(getattr(value, "recipe", [])))
            for name, val in kwargs.items():
                self.env[name] = Val(val.value if isinstance(val, Val) else val,
                                     list(getattr(val, "recipe", [])))
            try:
                self.run_body(method.body, [DEFAULT_BUDGET])
            except _ReturnSignal as signal:
                return signal.value if isinstance(signal.value, Val) else Val(signal.value, [])
            return Val(None, [])
        finally:
            self.env, self.functions = saved_env, saved_functions

    def _getattr_path(self, func):
        """`getattr(base64, 'b64decode')` -> `base64.b64decode`."""
        if not isinstance(func, ast.Call) or len(func.args) < 2:
            return None
        try:
            head = self.dotted(func.func)
        except EvalUnsafe:
            return None
        if head not in ("getattr", "builtins.getattr", "operator.attrgetter"):
            return None
        if not isinstance(func.args[1], ast.Constant) or not isinstance(func.args[1].value, str):
            return None
        try:
            base = self.dotted(func.args[0])
        except EvalUnsafe:
            return None
        return f"{base}.{func.args[1].value}"

    def _call_function(self, fndef, node):
        """Inline a loader function: bind the arguments and simulate its body."""
        if getattr(fndef, "decorator_list", None):
            raise EvalUnsafe("decorated loader")
        args = [self.eval(a) for a in node.args]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg is None:
                raise EvalUnsafe("**kwargs into a loader")
            kwargs[kw.arg] = self.eval(kw.value)
        rec: list[str] = []
        for a in args:
            rec += a.recipe
        for a in kwargs.values():
            rec += a.recipe

        spec = fndef.args
        extra_args = list(args)
        extra_kwargs = dict(kwargs)
        positional = list(getattr(spec, "posonlyargs", [])) + list(spec.args)
        defaults = list(spec.defaults)
        unbound = len(positional) - len(defaults)

        saved_env, saved_functions = dict(self.env), dict(self.functions)
        try:
            values = [a.value for a in args]
            if len(values) > len(positional) and not spec.vararg:
                raise EvalFailed("too many arguments for the loader")
            for index, param in enumerate(positional):
                if index < len(values):
                    self.env[param.arg] = Val(values[index], [])
                elif index < unbound:
                    raise EvalFailed(f"missing argument {param.arg!r}")
                else:
                    default = defaults[index - unbound]
                    self.env[param.arg] = self.eval(default)
            for name, val in kwargs.items():
                self.env[name] = val
            if spec.vararg:
                self.env[spec.vararg.arg] = Val(values[len(positional):], [])
            if spec.kwarg:
                leftover = {key: val.value for key, val in kwargs.items()
                            if key not in {p.arg for p in positional}
                            and key not in {p.arg for p in spec.kwonlyargs}}
                self.env[spec.kwarg.arg] = Val(leftover, [])
            for param, default in zip(spec.kwonlyargs, spec.kw_defaults):
                if param.arg not in self.env and default is not None:
                    self.env[param.arg] = self.eval(default)
            try:
                self.run_body(fndef.body, [DEFAULT_BUDGET])
            except _ReturnSignal as signal:
                inner = signal.value
            else:
                raise EvalFailed("loader never returned")
        finally:
            self.env, self.functions = saved_env, saved_functions
        return Val(inner.value, rec + inner.recipe)

    def run_function(self, fndef, values=(), kwargs=None) -> dict[str, Val]:
        """Simulate a loader function and hand back everything it computed.

        `_call_function` needs a ``return``.  The loaders that matter most do not
        have one - they decode into a name and ``exec`` it, or a helper fills a
        global - so a body with no return used to be a dead end.  This runs the
        same body and reports the local namespace, which is where the payload of
        a statement-style loader actually lives.
        """
        saved_env, saved_functions = dict(self.env), dict(self.functions)
        locals_after: dict[str, Val] = {}
        try:
            spec = fndef.args
            positional = list(getattr(spec, "posonlyargs", [])) + list(spec.args)
            for param, value in zip(positional, values):
                self.env[param.arg] = Val(value, [])
            defaults = list(spec.defaults)
            for param, default in zip(positional[len(positional) - len(defaults):],
                                      defaults):
                if param.arg not in self.env:
                    try:
                        self.env[param.arg] = self.eval(default)
                    except (EvalUnsafe, EvalFailed, MarshalPayload):
                        pass
            for name, val in (kwargs or {}).items():
                self.env[name] = val if isinstance(val, Val) else Val(val, [])
            if spec.vararg:
                self.env[spec.vararg.arg] = Val(list(values[len(positional):]), [])
            try:
                self.run_body(fndef.body, [DEFAULT_BUDGET])
            except _ReturnSignal as signal:
                if signal.value is not None:
                    self.env["__return__"] = signal.value
        except (EvalUnsafe, EvalFailed, MarshalPayload):
            pass
        except RecursionError:
            pass
        finally:
            locals_after = dict(self.env)
            self.env, self.functions = saved_env, saved_functions
        return locals_after

    # -- statement simulation ---------------------------------------------
    def run_body(self, body, budget=None, strict=False):
        """Walk statements in order, keeping every value that can be proven.

        Only whitelisted pure functions run here; anything unknown stops that
        branch and the value simply stays unknown.  This is what recovers keys
        and payloads that are assembled in loops instead of written literally.
        """
        if budget is None:
            budget = [DEFAULT_BUDGET]
        for node in body:
            budget[0] -= 1
            if budget[0] < 0:
                return
            try:
                self._run_statement(node, budget)
            except (_BreakSignal, _ContinueSignal, _ReturnSignal):
                raise
            except (EvalUnsafe, EvalFailed, MarshalPayload):
                if strict:
                    raise
                continue

    def _run_statement(self, node, budget):
        if isinstance(node, ast.Break):
            raise _BreakSignal()
        if isinstance(node, ast.Continue):
            raise _ContinueSignal()
        if isinstance(node, ast.Pass):
            return

        if isinstance(node, ast.Try):
            # a loader's `try: <decode> except: <other decode>` is everywhere:
            # run the first branch that works instead of giving up on the file
            try:
                self.run_body(node.body, budget, strict=True)
            except (EvalUnsafe, EvalFailed, MarshalPayload) as exc:
                if not node.handlers:
                    raise
                self.env["_pydecomp_exc"] = Val(exc, [])
                for handler in node.handlers:
                    if handler.type is not None:
                        try:
                            wanted = self.dotted(handler.type).split(".")[-1]
                        except EvalUnsafe:
                            wanted = ""
                        if wanted and not isinstance(exc, _EXC_BY_NAME.get(wanted, ())):
                            continue
                    if handler.name:
                        self.env[handler.name] = Val(exc, [])
                    self.run_body(handler.body, budget, strict=True)
                    break
            finally:
                if node.finalbody:
                    try:
                        self.run_body(node.finalbody, budget)
                    except _ReturnSignal:
                        raise
            if node.orelse:
                self.run_body(node.orelse, budget)
            return

        if isinstance(node, ast.Return):
            raise _ReturnSignal(self.eval(node.value) if node.value is not None
                                else Val(None, []))

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                return
            if isinstance(value, ast.Lambda):
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.lambdas[target.id] = value
                return
            computed = self.eval(value)
            for target in targets:
                self._store(target, computed)
            return

        if isinstance(node, ast.AugAssign):
            if not isinstance(node.target, ast.Name):
                raise EvalUnsafe("augmented assignment to a non-name")
            merged = ast.BinOp(left=ast.Name(id=node.target.id, ctx=ast.Load()),
                               op=node.op, right=node.value)
            self._store(node.target, self.eval(merged))
            return

        if isinstance(node, ast.Expr):
            self.eval(node.value)
            return

        if isinstance(node, ast.If):
            test = self.eval(node.test)
            self.run_body(node.body if test.value else node.orelse, budget)
            return

        if isinstance(node, ast.For):
            seq = self.eval(node.iter).value
            if isinstance(seq, (str, bytes)):
                seq = list(seq)
            if not isinstance(seq, (list, tuple, range)):
                raise EvalUnsafe("loop over a non-constant iterable")
            if len(seq) > MAX_LOOP_ROUNDS:
                # same rule as the while loop: never publish a partial iteration
                raise EvalFailed("iterable too long to finish inside the budget")
            broke = False
            for item in seq:
                budget[0] -= 1
                if budget[0] < 0:
                    raise EvalFailed("statement budget exhausted inside a loop")
                self._store(node.target, Val(item, []))
                try:
                    self.run_body(node.body, budget)
                except _BreakSignal:
                    broke = True
                    break
                except _ContinueSignal:
                    continue
            if not broke and node.orelse:
                self.run_body(node.orelse, budget)
            return
            return

        if isinstance(node, ast.While):
            test = self.eval(node.test)                 # constant-only conditions
            rounds = 0
            while test.value:
                rounds += 1
                # a cap that silently stops is worse than no cap: the rest of the
                # file then decodes a *truncated* value and the analyser writes it
                # out as if it were the answer.  1125 rounds of a base45 loop is
                # an ordinary loader; 1000 was not a budget, it was a wrong answer.
                if rounds > MAX_LOOP_ROUNDS:
                    raise EvalFailed("loop did not finish within the simulation budget")
                budget[0] -= 1
                if budget[0] < 0:
                    raise EvalFailed("statement budget exhausted inside a loop")
                try:
                    self.run_body(node.body, budget)
                except _BreakSignal:
                    break
                except _ContinueSignal:
                    pass
                test = self.eval(node.test)
            return

        raise EvalUnsafe(f"statement {type(node).__name__}")

    def _store(self, target, val):
        """Bind an assignment target, mutating lists/dicts in place."""
        if isinstance(target, ast.Name):
            self.env[target.id] = Val(val.value, list(val.recipe))
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            items = list(val.value)
            if len(items) != len(target.elts):
                raise EvalFailed("unpack length mismatch")
            for sub, item in zip(target.elts, items):
                self._store(sub, Val(item, []))
            return
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            holder = self.env.get(target.value.id)
            if holder is None or not isinstance(holder.value, _Instance):
                raise EvalUnsafe("attribute store on a non-instance")
            holder.value.attrs[target.attr] = val.value
            return
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            holder = self.env.get(target.value.id)
            if holder is None:
                raise EvalUnsafe("subscript store on an unknown name")
            index = self.eval(target.slice).value
            if isinstance(holder.value, list) and isinstance(index, int):
                holder.value[index] = val.value
                return
            if isinstance(holder.value, dict):
                holder.value[index] = val.value
                return
            raise EvalFailed("subscript store on a non-container")
        raise EvalUnsafe("unsupported assignment target")


    # -- whitelisted methods on computed values ----------------------------
    def _method(self, recv: Val, attr: str, node: ast.Call) -> Val:
        args = [self.eval(a) for a in node.args]
        rec = list(recv.recipe)
        for a in args:
            rec += a.recipe
        vals = [a.value for a in args]
        kwargs = {}
        for kw in getattr(node, "keywords", ()):
            if kw.arg is None:
                raise EvalUnsafe("**kwargs")
            kwargs[kw.arg] = self.eval(kw.value).value
        v = recv.value

        if isinstance(v, _Instance):
            return self._call_method(v, attr, vals, kwargs, rec)

        # cipher / hash objects answer for themselves
        if hasattr(v, "_pydecomp_call"):
            try:
                out = v._pydecomp_call(attr, vals, kwargs)
            except EvalUnsafe:
                raise
            except MarshalPayload:
                raise
            except Exception as exc:                 # noqa: BLE001 - report and move on
                raise EvalFailed(f".{attr}(): {exc}")
            if isinstance(out, Val):
                return Val(out.value, rec + out.recipe)
            return Val(out, rec)

        # in-place container edits (a key built by append() in a loop)
        if isinstance(v, (list, bytearray)) and attr in ("append", "extend", "insert",
                                                         "pop", "reverse", "clear",
                                                         "sort", "remove"):
            out = getattr(v, attr)(*vals)
            if attr in ("pop", "clear", "reverse", "sort", "append", "extend",
                        "insert", "remove"):
                return Val(out, rec + [attr])
        if isinstance(v, dict) and attr in ("get", "keys", "values", "items",
                                            "update", "setdefault", "pop"):
            out = getattr(v, attr)(*vals)
            if attr in ("keys", "values"):
                return Val(list(out), rec + [attr])
            if attr == "items":
                return Val([list(pair) for pair in out], rec + [attr])
            return Val(out, rec + [attr])
        if isinstance(v, int) and attr in METHOD_NAMES_EXTRA:
            try:
                out = METHOD_NAMES_EXTRA[attr](v, *vals, **kwargs)
            except (EvalUnsafe, MarshalPayload):
                raise
            except Exception as exc:                 # noqa: BLE001 - a bad length is a miss, not a crash
                # `n.to_bytes(4, "big")` on a 300-bit number raises OverflowError:
                # that is the loader's bug, and it must end this branch only
                raise EvalFailed(f".{attr}(): {type(exc).__name__}: {exc}")
            return Val(out, rec + [attr])
        if isinstance(v, (str, bytes)) and attr in ("translate", "format", "split",
                                                    "rsplit", "zfill", "ljust",
                                                    "rjust", "center", "partition",
                                                    "rpartition", "count", "find",
                                                    "index", "startswith", "endswith",
                                                    "splitlines", "title", "capitalize",
                                                    "swapcase", "casefold"):
            try:
                if attr in ("split", "rsplit") and not vals:
                    out = v.split()
                elif attr in ("split", "rsplit"):
                    out = getattr(v, attr)(*vals, kwargs.get("maxsplit", -1))
                else:
                    out = getattr(v, attr)(*vals)
            except Exception as exc:                 # noqa: BLE001 - report as a miss
                raise EvalFailed(f".{attr}(): {exc}")
            if isinstance(out, (list, tuple)):
                return Val(list(out), rec + [attr])
            return Val(out, rec + [attr])
        try:
            if attr == "decode":
                if not isinstance(v, (bytes, bytearray)):
                    raise EvalFailed("decode on non-bytes")
                return Val(bytes(v).decode(vals[0] if vals else "utf-8"), rec + ["decode"])
            if attr == "encode":
                enc = vals[0] if vals else "utf-8"
                if isinstance(v, (bytes, bytearray)):
                    return Val(bytes(v), rec)
                return Val(str(v).encode(enc), rec + ["encode"])
            if attr == "join":
                sep, seq = v, (vals[0] if vals else None)
                if not isinstance(seq, (list, tuple)):
                    raise EvalFailed("join over non-sequence")
                if isinstance(sep, bytes):
                    return Val(sep.join(x if isinstance(x, bytes) else to_bytes(x)
                                        for x in seq), rec + ["join"])
                return Val(str(sep).join(str(x) for x in seq), rec + ["join"])
            if attr == "hex" and isinstance(v, (bytes, bytearray)):
                return Val(bytes(v).hex(), rec + ["hex"])
            if attr in ("upper", "lower", "strip", "lstrip", "rstrip", "replace") \
                    and isinstance(v, (str, bytes)):
                out = getattr(v, attr)(*vals)
                return Val(out, rec + [attr])
        except EvalUnsafe:
            raise
        except Exception as exc:
            raise EvalFailed(f".{attr}(): {exc}")
        raise EvalUnsafe(f"method .{attr} on {type(v).__name__} not allowed")
