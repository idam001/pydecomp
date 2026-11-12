"""pydecomp - peel."""
from __future__ import annotations

from dataclasses import dataclass, field
import ast
import hashlib

from ..bytecode.magic import MAGIC_VERSIONS_BYTES
from ..core.util import looks_like_python, to_bytes
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

    found.extend(_marshal_payloads(tree, ev))
    found.extend(_alphabet_payloads(tree))
    found.extend(_xor_comprehension_payloads(tree, ev))
    if not found:
        # a mid-chain arithmetic layer: fold it and read the file again
        folded = _folded_source(source)
        if folded is not None and folded != source:
            try:
                return find_payloads(folded)
            except RecursionError:
                pass
    found.extend(_builtin_uu_payloads(tree))

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
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return any(isinstance(node, _PROGRAM_NODES) for node in ast.walk(tree))


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
