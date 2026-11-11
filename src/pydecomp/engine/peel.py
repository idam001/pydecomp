"""pydecomp - peel."""
from __future__ import annotations

from dataclasses import dataclass, field
import ast
import hashlib

from ..core.util import looks_like_python, to_bytes
from ..eval.evaluator import Evaluator
from ..exceptions import EvalFailed, EvalUnsafe, MarshalPayload
from ..limits import EXEC_SINKS, MAX_LAYERS

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

    # prefer the biggest payload (that is nearly always the real one)
    found.sort(key=lambda pl: len(pl.data), reverse=True)
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
        is_src = best.kind == "python" and looks_like_python(raw)
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
