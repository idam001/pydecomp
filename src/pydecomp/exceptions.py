"""pydecomp - exceptions."""
from __future__ import annotations

from typing import Any, Iterable
import ast


class EvalUnsafe(Exception):
    """Raised when we hit anything outside the pure-decoder whitelist."""

class EvalFailed(Exception):
    """Raised when a whitelisted decoder could not handle the input."""

class _BreakSignal(Exception):
    """Internal: `break` inside a simulated loop."""

class _ContinueSignal(Exception):
    """Internal: `continue` inside a simulated loop."""

class _ReturnSignal(Exception):
    """Internal: a simulated function body hit `return`."""

    def __init__(self, value: Any) -> None:
        super().__init__("return")
        self.value = value

class MarshalPayload(Exception):
    """marshal.loads() hit: we surface the blob instead of unmarshalling it."""

    def __init__(self, data: bytes, recipe: list[str]) -> None:
        super().__init__("marshal payload")
        self.data = data
        self.recipe = recipe

_EXC_BY_NAME = {
    "Exception": (EvalUnsafe, EvalFailed, MarshalPayload),
    "BaseException": (EvalUnsafe, EvalFailed, MarshalPayload),
    "ValueError": (EvalFailed,),
    "TypeError": (EvalFailed,),
    "KeyError": (EvalFailed,),
    "IndexError": (EvalFailed,),
    "UnicodeDecodeError": (EvalFailed,),
    "AttributeError": (EvalUnsafe,),
    "NameError": (EvalUnsafe,),
    "ImportError": (EvalUnsafe,),
    "ModuleNotFoundError": (EvalUnsafe,),
    "binascii.Error": (EvalFailed,),
    "zlib.error": (EvalFailed,),
    "OverflowError": (EvalFailed,),
}

def const_int(node: ast.AST) -> int | None:
    """Fold `-1`, which the CPython parser emits as UnaryOp(USub, Constant)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = const_int(node.operand)
        if inner is not None:
            return -inner
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
        return const_int(node.operand)
    return None

class _ExprRefuse(Exception):
    """The expression wanted to do something the analyser will not do."""

class _ExprCaptured(Exception):
    def __init__(self, payload):
        self.payload = payload
