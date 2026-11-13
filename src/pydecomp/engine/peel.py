"""pydecomp - peel."""
from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
import hashlib

from ..bytecode.magic import MAGIC_VERSIONS_BYTES
from ..core.util import looks_like_python, to_bytes
from ..core.values import Val
from ..eval.evaluator import Evaluator
from ..exceptions import EvalFailed, EvalUnsafe, MarshalPayload
from ..limits import EXEC_SINKS, MAX_LAYERS

# Calls that turn bytes into a code object.  A packer that ships a marshalled
# payload almost never calls exec() on a literal: it calls one of these and keeps
# the result in a name, so the sink scan has to know them by name.
MARSHAL_SINKS = {"marshal.loads", "marshal.load", "marshal.load_code",
                 "_marshal.loads", "imp.load_compiled"}
MARSHAL_SINK_TAIL = {"marshal.loads", "marshal.load", "_marshal.loads"}


@dataclass
class Layer:
    index: int
    recipe: list[str]
    data: bytes
    sha256: str
    size: int
    is_source: bool

@dataclass
class Payload:
    recipe: list[str]
    data: bytes
    kind: str          # "python" | "marshal" | "opaque"

class _FoldArithmetic(ast.NodeTransformer):
    """Replace ``bytes(b ^ K for b in <static>)`` with the bytes it produces.

    An xor layer in the middle of a chain is written as a comprehension, and the
    expression evaluator will not run a comprehension - so a five-layer stack with
    one xor in the middle used to end there.  The key is in the sample and the
    input is static, so the value is not a guess: compute it, put a bytes literal
    in its place, and let the ordinary pipeline carry on.  Only the exact shape is
    touched; anything with a filter, a second iterable or a non-constant operand
    is left alone.
    """

    OPS = {ast.BitXor: lambda a, b: a ^ b,
           ast.Add: lambda a, b: (a + b) & 0xFF,
           ast.Sub: lambda a, b: (a - b) & 0xFF}

    def __init__(self, evaluator) -> None:
        self.evaluator = evaluator
        self.folded = 0

    def visit_Call(self, node):                        # noqa: N802
        node = self.generic_visit(node)
        if not (isinstance(node.func, ast.Name) and node.func.id == "bytes"):
            return node
        if len(node.args) != 1 or node.keywords:
            return node
        gen = node.args[0]
        if not isinstance(gen, (ast.GeneratorExp, ast.ListComp)) \
                or len(gen.generators) != 1 or gen.generators[0].ifs:
            return node
        target = gen.generators[0].target
        if not isinstance(target, ast.Name):
            return node
        element = gen.elt
        if not isinstance(element, ast.BinOp) or type(element.op) not in self.OPS:
            return node
        left, right = element.left, element.right
        loop = None
        counter = None
        for this, other in ((left, right), (right, left)):
            if isinstance(this, ast.Name) and this.id == target.id:
                if isinstance(other, ast.Constant) and isinstance(other.value, int):
                    loop, counter = this, other.value
        if loop is None or counter is None:
            return node
        try:
            value = self.evaluator.eval(gen.generators[0].iter)
        except Exception:                              # noqa: BLE001 - not static
            return node
        data = value.value
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        if not isinstance(data, (bytes, bytearray)):
            return node
        apply = self.OPS[type(element.op)]
        try:
            out = bytes(apply(item, counter & 0xFF) for item in data)
        except (OverflowError, ValueError):
            return node
        self.folded += 1
        return ast.copy_location(ast.Constant(value=out), node)


def _carries_content(data: bytes) -> bool:
    return bool(data) and data.count(data[0]) != len(data)


def _backend_payloads(tree: ast.AST) -> list[Payload]:
    """Last resort: open the module's literals with the plugin tree.

    Used only when every loader-reading path came up empty, so a file the
    peeler already understands never takes this route.  The chain that opened
    the blob is the recipe, which means the report says *how* it was read
    rather than presenting a result with no provenance.
    """
    if not _bare_data_or_loader(tree):
        return []
    try:
        from .plugins_pass import explore_blobs
    except ImportError:                                # pragma: no cover - layout
        return []
    blobs = [blob for blob, _node in _literal_blobs(tree, floor=64)]
    if not blobs:
        return []
    try:
        found = explore_blobs(blobs)
    except RecursionError:
        return []
    return [Payload(recipe, data, kind) for recipe, data, kind in found]


#: calls a data file may make without becoming a program: it ends, or it says so
_QUIET_CALLS = frozenset({"SystemExit", "print", "exit", "quit"})


def _bare_data_or_loader(tree: ast.AST) -> bool:
    """Is this file trying to run something, or is it just carrying bytes?

    Without this check the backend tree would "recover" the payload of any
    ordinary program that happens to hold an archive - a zip extractor would be
    reported as obfuscated, and its own source replaced by whatever it extracts.
    A loader executes what it built; a data file does nothing but carry it.
    """
    if _has_dynamic_sink(tree):
        return True
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Import, ast.ImportFrom)):
            return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in _QUIET_CALLS:
                return False
    return True


def _sink_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """Every exec/eval/compile() argument this module can resolve statically."""
    found: list[Payload] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        try:
            path = ev.dotted(node.func)
        except EvalUnsafe:
            continue
        if path not in EXEC_SINKS and not path.endswith(".exec"):
            continue
        if not node.args:
            continue
        try:
            v = ev.eval(node.args[0])
            data = v.value
            if isinstance(data, (bytes, bytearray, str)) and data:
                found.append(Payload(v.recipe, to_bytes(data), "python"))
        except MarshalPayload as m:
            if m.data:
                found.append(Payload(m.recipe + ["marshal"], m.data, "marshal"))
        except (EvalUnsafe, EvalFailed):
            continue
    return found


def _constant_folded(source: str) -> str | None:
    """The same program with its constant expressions evaluated, or None."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    try:
        from ..polish.evaluate import fold_expressions
        if not fold_expressions(tree, {}):
            return None
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:                                  # noqa: BLE001
        return None


def _folded_source(source: str) -> str | None:
    """The same program with its arithmetic comprehensions folded, or None."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    evaluator = Evaluator()
    try:
        evaluator.absorb(tree)
    except Exception:                                  # noqa: BLE001
        pass
    folder = _FoldArithmetic(evaluator)
    try:
        tree = folder.visit(tree)
        ast.fix_missing_locations(tree)
    except Exception:                                  # noqa: BLE001
        return None
    if not folder.folded:
        return None
    try:
        return ast.unparse(tree)
    except Exception:                                  # noqa: BLE001
        return None


def find_payloads(source: str) -> list[Payload]:
    """Statically evaluate every exec/eval/compile() argument. Nothing runs."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    ev = Evaluator()
    ev.absorb(tree)

    found: list[Payload] = list(_sink_payloads(tree, ev))
    found.extend(_namespace_payloads(tree, ev))
    found.extend(_marshal_payloads(tree, ev))
    found.extend(_alphabet_payloads(tree))
    found.extend(_xor_comprehension_payloads(tree, ev))
    found.extend(_loop_chain_payloads(tree, ev))
    # an accumulator leaves what it built in the environment, so the sinks get a
    # second look with the container's value in hand
    built = _accumulator_payloads(tree, ev)
    if built:
        found.extend(_sink_payloads(tree, ev))
        found.extend(built)
    if not found:
        # a mid-chain arithmetic layer or a constant the loader hid behind a
        # class body: fold it and read the file again
        for folded in (_folded_source(source), _constant_folded(source)):
            if folded is None or folded == source:
                continue
            try:
                recovered = find_payloads(folded)
            except RecursionError:
                recovered = []
            if recovered:
                # the fold is what turned the loader into a literal, so the layer
                # has a provenance even when the folded call has no recipe of its own
                return [payload if payload.recipe
                        else Payload(["constant-fold"] + payload.recipe, payload.data,
                                     payload.kind)
                        for payload in recovered]
    found.extend(_builtin_uu_payloads(tree))
    # a buffer that was allocated and never written is a shape, not content:
    # `bytearray(len(data))` folded to zeros is not a payload, and saying it is
    # would stop the search before it started
    found = [payload for payload in found if _carries_content(payload.data)]
    if not found:
        # nothing in the code explains the data: hand the literals to the
        # backend tree and let structure, not the loader, name the layers
        found.extend(_backend_payloads(tree))

    # prefer a payload that really is source; among those, the biggest, because
    # a small parseable fragment (a stub) is rarely the program
    def rank(payload: Payload) -> tuple:
        try:
            parses = payload.kind == "python" and _is_program(
                payload.data.decode("utf-8", "surrogateescape"))
        except (UnicodeDecodeError, RecursionError):
            parses = False
        return (parses, len(payload.data))

    found.sort(key=rank, reverse=True)
    return found


# Alphabets a loader has to spell out because there is no stdlib codec for
# them.  When a module carries one of these tables and a literal blob, the blob
# is that codec's output - no guessing, no execution, just naming the alphabet.
ALPHABETS = {
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz": "base58",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz": "base62",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:": "base45",
    ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
     ".-:+=^!/*?&<>()[]{}@%$#"): "z85",
}


#: node types that mean "this is a program", not "this happens to parse"
_PROGRAM_NODES = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.FunctionDef,
                  ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom,
                  ast.If, ast.For, ast.AsyncFor, ast.While, ast.Return, ast.Try,
                  ast.With, ast.AsyncWith, ast.Raise, ast.Call, ast.Assert,
                  ast.Delete, ast.Global, ast.Nonlocal)


def _is_program(text: str) -> bool:
    """Does this text parse *and* have the shape of a program?

    ``ast.parse`` alone is not enough: a base64 blob is one enormous identifier,
    which parses perfectly and is not source.  Requiring one statement-bearing
    node is what lets the peeler tell "the payload" from "the layer before it".
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return any(isinstance(node, _PROGRAM_NODES) for node in ast.walk(tree))


def _has_dynamic_sink(tree: ast.AST) -> bool:
    """Does this module execute code it built at runtime?"""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name and (name in ("exec", "eval", "compile", "loads", "load_module")
                     or f"{name}" in {sink.rsplit(".", 1)[-1] for sink in EXEC_SINKS}):
            return True
    return False


def _namespace_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """The payload of a *statement* loader: whatever the decoding left in a name.

    A one-line loader decodes inside the ``exec(...)`` argument, so reading the
    argument is enough.  A loader that decodes into a variable and then calls
    ``exec(_p)`` (- which is what most packers emit, and what a `def` wrapper
    makes unavoidable -) has no decoding expression to read: the work happened in
    the statements before.  After the module body is simulated, those statements
    have values, and so does the local namespace of every function the module
    calls.  Both are candidates.
    """
    # A program that merely *computes* something is not a loader.  Only a module
    # that hands bytes to exec/eval/compile is one, and only then is a decoded
    # local a payload - otherwise every script with a function in it would have
    # its innards offered up as "the payload" and the file would be replaced by
    # its own return value.
    if not _has_dynamic_sink(tree):
        return []

    candidates: dict[bytes, Payload] = {}

    def offer(val) -> None:
        value = getattr(val, "value", None)
        if not isinstance(value, (bytes, bytearray, str)) or not value:
            return
        data = to_bytes(value)
        if len(data) < 8 or data in candidates:
            return
        # a candidate that is neither source nor a layer we can name is noise
        if not (val.recipe or _is_program(data.decode("utf-8", "surrogateescape"))):
            return
        candidates[data] = Payload(list(val.recipe), data, "python")

    for val in list(ev.env.values()):
        offer(val)

    # functions the module body calls: their locals hold what they decoded
    interesting = {name for name, fndef in ev.functions.items()
                   if isinstance(fndef, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in interesting:
            continue
        fndef = ev.functions[node.func.id]
        values = []
        for arg in node.args:
            try:
                values.append(ev.eval(arg).value)
            except (EvalUnsafe, EvalFailed, MarshalPayload):
                break
        else:
            for val in ev.run_function(fndef, values).values():
                offer(val)

    # a `def` that is never called by name still runs: a class method is invoked
    # through an instance (`_Loader().run()`), and a loader hidden in a method is
    # the shape Hyperion ships.  Simulating the body needs no caller - the work is
    # in the statements, and the only thing a caller adds is arguments.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _has_dynamic_sink(node):
            continue
        for val in ev.run_function(node, _default_arguments(ev, node)).values():
            offer(val)

    return list(candidates.values())


def _default_arguments(ev: Evaluator, fndef: ast.AST) -> list:
    """Argument values to simulate a body with: the declared defaults, else None."""
    spec = fndef.args
    positional = list(getattr(spec, "posonlyargs", [])) + list(spec.args)
    if positional and positional[0].arg in ("self", "cls"):
        positional = positional[1:]
    values = []
    for param in positional:
        values.append(None)
    defaults = list(spec.defaults)
    for offset, default in enumerate(defaults):
        index = len(positional) - len(defaults) + offset
        if index < 0:
            continue
        try:
            values[index] = ev.eval(default).value
        except (EvalUnsafe, EvalFailed, MarshalPayload):
            pass
    return values


def _literal_blobs(tree: ast.AST, floor: int = 24) -> list[tuple[bytes, ast.AST]]:
    """Every byte/str literal in the module, biggest first."""
    blobs: list[tuple[bytes, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
            data = (node.value if isinstance(node.value, bytes)
                    else node.value.encode("utf-8", "surrogateescape"))
            if len(data) >= floor:
                blobs.append((data, node))
    blobs.sort(key=lambda item: len(item[0]), reverse=True)
    return blobs


def _alphabet_payloads(tree: ast.AST) -> list[Payload]:
    """A declared alphabet plus a literal blob: that blob is the codec's output.

    Hand-rolled base58/62/45/z85 loaders cannot be evaluated by following an
    expression tree - they loop.  What they *can* be recognised by is the table
    they carry: a module that spells out the base58 alphabet and holds one big
    literal is holding base58.  The registry does the arithmetic, statically.
    """
    declared = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            codec = ALPHABETS.get(node.value)
            if codec is not None and codec not in declared:
                declared.append(codec)
    if not declared:
        return []
    from ..decoders.registry import TRANSFORMS
    from ..decoders.emoji import parses_as_python
    found: list[Payload] = []
    for codec in declared:
        decode = TRANSFORMS.get(codec)
        if decode is None:
            continue
        for blob, _node in _literal_blobs(tree, floor=32):
            if set(blob) - set(b"\n\r \t") <= set(b"") :
                continue
            try:
                out = decode(blob)
            except Exception:                        # noqa: BLE001 - wrong alphabet for this blob
                continue
            if not out:
                continue
            try:
                text = out.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if parses_as_python(text):
                found.append(Payload([codec], out, "python"))
                break
            if out[:2] in MAGIC_VERSIONS_BYTES:
                found.append(Payload([codec], out, "marshal"))
                break
    return found


_REPLAY_LIMIT = 16
_REPLAY_BYTES = 64 << 20


def _range_count(node) -> int | None:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "range"):
        return None
    args = []
    for arg in node.args:
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, int)):
            return None
        args.append(arg.value)
    if not args or len(args) > 3:
        return None
    try:
        return len(range(*args))
    except (TypeError, ValueError):
        return None


def _loop_chain_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """Replay `for _ in range(k): x = decode(x)` statically, k times.

    A loader that reassigns one name through a counted loop is a chain with the
    loop written out longhand; the count is a literal, so the chain is too.
    """
    from ..decoders.emoji import parses_as_python

    found: list[Payload] = []
    spent = 0
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name):
            try:
                ev.env[stmt.targets[0].id] = ev.eval(stmt.value)
            except (EvalUnsafe, EvalFailed, MarshalPayload):
                pass
            continue
        if not isinstance(stmt, ast.For):
            continue
        count = _range_count(stmt.iter)
        if not count or count > _REPLAY_LIMIT:
            continue
        targets = {inner.targets[0].id for inner in stmt.body
                   if isinstance(inner, ast.Assign) and len(inner.targets) == 1
                   and isinstance(inner.targets[0], ast.Name)}
        if len(targets) != 1:
            continue
        name = targets.pop()
        if name not in ev.env or not all(isinstance(inner, ast.Assign) for inner in stmt.body):
            continue
        value = ev.env[name]
        try:
            for _ in range(count):
                for inner in stmt.body:
                    ev.env[name] = ev.eval(inner.value)
                    value = ev.env[name]
                    spent += len(value.value) if isinstance(value.value, (bytes, str)) else 0
                    if spent > _REPLAY_BYTES:
                        raise EvalFailed("replay budget")
        except (EvalUnsafe, EvalFailed, MarshalPayload, RecursionError):
            del ev.env[name]
            continue
        data = value.value
        if not isinstance(data, (bytes, bytearray, str)) or not data:
            del ev.env[name]
            continue
        raw = to_bytes(data)
        recipe = list(value.recipe) + ["replay"]
        try:
            if parses_as_python(raw.decode("utf-8")):
                found.append(Payload(recipe, raw, "python"))
            elif raw[:2] in MAGIC_VERSIONS_BYTES:
                found.append(Payload(recipe, raw, "marshal"))
            else:
                from ..bytecode.marshal_reader import parse_marshal_blob
                _version, obj, _layout = parse_marshal_blob(raw)
                if obj is not None:
                    found.append(Payload(recipe, raw, "marshal"))
        except UnicodeDecodeError:
            pass
        del ev.env[name]
    return found


def _grow_shape(statement):
    """`c.append(x)`, `c.extend(x)` or `c += x` - one way to grow a container."""
    if isinstance(statement, ast.AugAssign):
        if isinstance(statement.target, ast.Name) and isinstance(statement.op, ast.Add):
            return statement.target.id, "add", statement.value
        return None
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        call = statement.value
        if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                and call.func.attr in ("append", "extend") and len(call.args) == 1):
            return call.func.value.id, call.func.attr, call.args[0]
    return None


def _accumulator_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """Replay `for c in LITERAL: out.append(f(c))` against the literal.

    A payload assembled character by character is the same chain written out one
    element at a time.  The iterable has to be a value the file already holds, so
    nothing is guessed and nothing runs.
    """
    from ..decoders.emoji import parses_as_python

    found: list[Payload] = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.For) or not isinstance(stmt.target, ast.Name):
            continue
        shapes = [_grow_shape(inner) for inner in stmt.body]
        if not shapes or any(shape is None for shape in shapes):
            continue
        names = {shape[0] for shape in shapes}
        if len(names) != 1:
            continue
        name = names.pop()
        start = ev.env.get(name)
        if start is None or not isinstance(start.value, (bytearray, list, str, bytes)):
            continue
        try:
            movable = ev.eval(stmt.iter)
        except (EvalUnsafe, EvalFailed, MarshalPayload):
            continue
        items = movable.value
        if not isinstance(items, (list, tuple, bytes, str, bytearray, range)):
            continue
        if len(items) > _REPLAY_LIMIT * 4096:
            continue
        built = start.value if isinstance(start.value, bytearray) else type(start.value)()
        if isinstance(built, str):
            built = ""
        spent = 0
        try:
            for item in items:
                if isinstance(item, (list, tuple, dict, set)):
                    raise EvalFailed("element is not a scalar")
                ev.env[stmt.target.id] = Val(item, ["loop"])
                for target, method, node in shapes:
                    piece = ev.eval(node).value
                    if method == "append":
                        if isinstance(built, str):
                            built += str(piece)
                        else:
                            built.append(piece)
                    elif method == "extend":
                        if isinstance(built, str):
                            built += str(piece)
                        else:
                            built.extend(piece)
                    else:
                        built = built + piece
                spent += len(built)
                if spent > _REPLAY_BYTES:
                    raise EvalFailed("replay budget")
        except (EvalUnsafe, EvalFailed, MarshalPayload, RecursionError, TypeError,
                ValueError, AttributeError):
            continue
        finally:
            ev.env.pop(stmt.target.id, None)
        try:
            if isinstance(built, (bytearray, bytes)):
                data = bytes(built)
            elif isinstance(built, list) and built and isinstance(built[0], str):
                data = "".join(built).encode("utf-8", "surrogateescape")
            elif isinstance(built, str):
                data = built.encode("utf-8", "surrogateescape")
            else:
                data = bytes(built)
        except (TypeError, ValueError):
            continue
        if not data:
            continue
        recipe = list(start.recipe) + ["accumulate"]
        ev.env[name] = Val(built, recipe)
        try:
            if parses_as_python(data.decode("utf-8")):
                found.append(Payload(recipe, data, "python"))
        except UnicodeDecodeError:
            continue
    return found


def _xor_comprehension_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """``bytes(b ^ K for b in blob)`` - a decrypt loop written as a comprehension.

    This is the most common shape in current string-encryption loaders: the blob
    is a literal, the key is a literal, and the only thing between the reader and
    the payload is a generator expression the statement evaluator will not run.
    The arithmetic is three lines, so do it directly - nothing is executed, no
    candidate key is tried that the file did not name.
    """
    found: list[Payload] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "bytes"):
            continue
        argument = node.args[0]
        if not isinstance(argument, (ast.GeneratorExp, ast.ListComp)):
            continue
        if len(argument.generators) != 1:
            continue
        element = argument.elt
        if not (isinstance(element, ast.BinOp) and isinstance(element.op, ast.BitXor)):
            continue
        sides = (element.left, element.right)
        key = None
        for side in sides:
            if isinstance(side, ast.Constant) and isinstance(side.value, int):
                key = side.value & 0xFF
        if key is None:
            continue
        source = None
        iterated = argument.generators[0].iter
        try:
            value = ev.eval(iterated)
        except Exception:                            # noqa: BLE001 - not static
            value = None
        if value is not None and isinstance(value.value, (bytes, bytearray)) \
                and value.value:
            source = bytes(value.value)
        if not source:
            continue
        plain = bytes(item ^ key for item in source)
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # `looks_like_python` is a heuristic and base64 text passes it, which made
        # the peeler pick the layer *before* the last one and call it the program.
        # Parse it instead: only real source counts.
        if _is_program(text):
            found.append(Payload([f"xor(key={key:#04x})"], plain, "python"))
        elif plain[:2] in MAGIC_VERSIONS_BYTES:
            found.append(Payload([f"xor(key={key:#04x})"], plain, "marshal"))
    return found


def _builtin_uu_payloads(tree: ast.AST) -> list[Payload]:
    """``binascii.a2b_uu(literal)`` - the stdlib uudecode, spelled out."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "a2b_uu":
            names.add("uu")
        if isinstance(node, ast.Name) and node.id == "a2b_uu":
            names.add("uu")
    if not names:
        return []
    import binascii
    from ..decoders.emoji import parses_as_python
    found: list[Payload] = []
    for blob, _node in _literal_blobs(tree, floor=32):
        try:
            out = b"".join(binascii.a2b_uu(line) for line in blob.splitlines() if line)
        except Exception:                            # noqa: BLE001
            continue
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if parses_as_python(text):
            found.append(Payload(["uu"], out, "python"))
            break
    return found


def _marshal_payloads(tree: ast.AST, ev: Evaluator) -> list[Payload]:
    """Code-loading calls whose argument is already known statically.

    ``marshal.loads(_p)`` with ``_p`` bound to a literal is a marshalled payload
    sitting in the file; the bytes can be read by the static marshal reader, so
    this is exactly as safe as reading a .pyc.  ``marshal.loads(blob[16:])`` - the
    usual header strip - is handled by evaluating the inner value and letting the
    pyc parser deal with the header it still carries.
    """
    found: list[Payload] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        try:
            path = ev.dotted(node.func)
        except EvalUnsafe:
            continue
        if path not in MARSHAL_SINKS:
            continue
        data, recipe = b"", []
        for argument in (node.args[0], getattr(node.args[0], "value", None)):
            if argument is None:
                continue
            try:
                value = ev.eval(argument)
            except MarshalPayload as m:
                data, recipe = m.data, m.recipe + ["marshal"]
                break
            except (EvalUnsafe, EvalFailed):
                continue
            if isinstance(value.value, (bytes, bytearray)) and value.value:
                data, recipe = bytes(value.value), value.recipe + ["marshal"]
                break
        if not data:
            continue
        if data[:2] in MAGIC_VERSIONS_BYTES or data[:2] in (b"\x00\x00", b"\x01\x00"):
            pass
        found.append(Payload(recipe or ["raw", "marshal"], data, "marshal"))
    return found

def peel(source: str, max_layers: int = MAX_LAYERS,
         on_layer=None) -> tuple[list[Layer], list[str]]:
    layers: list[Layer] = []
    notes: list[str] = []
    current = source
    for _ in range(max_layers):
        found = find_payloads(current)
        if not found:
            break
        best = found[0]
        if not best.recipe:
            notes.append("exec/compile() of a plain literal — the text is already in the "
                         "file, so this is not obfuscation; no layer peeled")
            break
        raw = best.data
        # "source" must mean *parses*.  `looks_like_python` accepts base64 text,
        # so a chain whose last layer was still encoded got written out as the
        # recovered program - the layer before the payload, sold as the payload.
        is_src = best.kind == "python" and _is_program(
            raw.decode("utf-8", "surrogateescape"))
        if best.kind == "marshal":
            note = ("payload is a marshalled code object (marshal.loads). It was NOT "
                    "unmarshalled - that is unsafe on hostile input. Strings were carved.")
        elif not is_src:
            note = ("payload decoded but is not Python source (ciphertext, truncated "
                    "layer, or unsupported encoding) - stopped")
        else:
            note = ""
        layers.append(Layer(index=len(layers) + 1, recipe=best.recipe, data=raw,
                            sha256=hashlib.sha256(raw).hexdigest(),
                            size=len(raw), is_source=is_src))
        if on_layer is not None:
            on_layer(layers[-1])
        if len(found) > 1:
            notes.append(f"layer {len(layers)}: {len(found)} exec payloads found, "
                         f"kept the largest ({len(raw)} bytes)")
        if not is_src:
            if note:
                notes.append(f"layer {len(layers)}: {note}")
            break
        current = raw.decode("utf-8", "surrogateescape")
    if len(layers) >= max_layers:
        notes.append(f"hit --max-layers ({max_layers}); the chain may continue")
    return layers, notes
