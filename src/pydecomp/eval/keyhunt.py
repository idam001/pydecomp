"""pydecomp - hunt for key material the sample computes at run time.

Some loaders derive their key from something that only exists while the program
runs::

    import os
    _k = len(os.urandom(16))
    exec(bytes(c ^ _k for c in _d).decode())

A static evaluator cannot know ``_k``, and for a long time that was the end of
the story: the file was reported as unrecoverable.  It should not be.  The *set
of possible values* is tiny - ``len`` of 16 bytes is 16, a byte XOR key is one
of 256 values - so the key space can be enumerated and each candidate tested
against an oracle that cannot be fooled: does the decoded payload parse as
Python, or marshal into a code object?

What this module does **not** do is cheat: it never runs the sample, and it does
not guess a key that merely "looks" right.  A candidate is accepted only when
the payload it produces is structurally valid, and when several candidates
produce valid payloads the run is reported as ambiguous rather than decided.
"""
from __future__ import annotations

import ast
import marshal
import re
import time
import zlib

from ..decoders.emoji import parses_as_python
from .expr_eval import resolve_expression_payload

BYTE_SPACE = 256
MAX_SOURCE = 400_000          # a bigger file is not worth 256 evaluations
TIME_BUDGET = 12.0            # seconds for the whole hunt
MAX_STATEMENTS = 4_000

RUNTIME_SOURCES = ("urandom", "random", "randint", "randrange", "randbytes",
                   "token_bytes", "token_hex", "time", "monotonic", "perf_counter",
                   "now", "today", "utcnow", "input", "getpass", "uuid", "getpid",
                   "hash", "id", "environ", "getenv", "stdin", "socket", "platform",
                   "hostname", "machine", "cpu_count", "gettid", "pid")

_INT_CONST = (int,)


def _constant_length(node) -> int | None:
    """Length of something whose size is fixed without running anything."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, bytes, bytearray, tuple, list)):
            return len(node.value)
        return None
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        tail = name.rsplit(".", 1)[-1]
        if tail in ("urandom", "randbytes", "token_bytes") and node.args:
            size = node.args[0]
            if isinstance(size, ast.Constant) and isinstance(size.value, int):
                return size.value
        if tail in ("bytes", "bytearray", "range", "list", "tuple") and node.args:
            size = node.args[0]
            if isinstance(size, ast.Constant) and isinstance(size.value, int):
                return size.value
        if tail == "join":
            return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        for left, right in ((node.left, node.right), (node.right, node.left)):
            if isinstance(right, ast.Constant) and isinstance(right.value, int):
                inner = _constant_length(left)
                if inner is not None:
                    return inner * right.value
    if isinstance(node, (ast.List, ast.Tuple)):
        return len(node.elts)
    return None


def _mentions_runtime(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and any(word == sub.id for word in RUNTIME_SOURCES):
            return True
        if isinstance(sub, ast.Attribute) and sub.attr in RUNTIME_SOURCES:
            return True
        if isinstance(sub, ast.Name) and sub.id in ("os", "time", "random", "secrets",
                                                   "uuid", "platform"):
            return True
    return False


def candidates(source: str) -> list[tuple[str, list[int]]]:
    """Names whose value is computed at run time, with the values they can take.

    Exact where the shape allows it (``len(os.urandom(16))`` is 16), a byte-wide
    space where a key is obviously one byte, and nothing at all when the value is
    genuinely unbounded - in that case the caller is told, not guessed at.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    found: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        value = node.value
        name = target.id
        if not _mentions_runtime(value):
            continue
        length = None
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                and value.func.id == "len" and len(value.args) == 1:
            length = _constant_length(value.args[0])
        if length is not None:
            found[name] = [length]
            continue
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod) \
                and isinstance(value.right, ast.Constant) \
                and isinstance(value.right.value, int) and 0 < value.right.value <= BYTE_SPACE:
            size = value.right.value
            found[name] = list(range(size))
            continue
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitAnd) \
                and isinstance(value.right, ast.Constant) \
                and isinstance(value.right.value, int) and 0 < value.right.value <= BYTE_SPACE:
            size = value.right.value
            found[name] = list(range(size + 1))
            continue
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                and value.func.id == "ord" and len(value.args) == 1:
            chr_length = _constant_length(value.args[0])
            if chr_length == 1:
                try:
                    literal = ast.literal_eval(value.args[0])
                except Exception:                    # noqa: BLE001
                    literal = None
                if isinstance(literal, str) and len(literal) == 1:
                    found[name] = [ord(literal)]
                    continue
            found[name] = list(range(BYTE_SPACE))
            continue
        # a scalar derived from run-time state: one byte is the overwhelming case
        found[name] = list(range(BYTE_SPACE))
    return [(name, values) for name, values in found.items() if values]


PROGRAM_WORDS = ("import", "from", "def", "class", "return", "for", "while",
                 "elif", "else", "print", "exec", "eval", "compile", "lambda",
                 "try", "except", "raise", "assert", "yield", "global",
                 "__name__", "__file__", "None", "True", "False", "self")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_ASSIGN = re.compile(r"(?m)^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=")


def _plausible_program(text: str) -> bool:
    """Would a human read this as a program rather than as shredded bytes?

    Parsing alone is not enough: nonsense such as ``uwlkq-'HDWN@WZ2c6d<4',`` is
    a valid Python expression.  A real payload names things - it imports,
    assigns, calls - so at least one program keyword has to appear, and the text
    has to be mostly letters, digits, spaces and ordinary punctuation.
    """
    if not parses_as_python(text) or len(text.strip()) < 8:
        return False
    letters = sum(1 for ch in text if ch.isalpha())
    if letters < len(text) * 0.40:
        return False                                 # shredded bytes, not code
    words = set(_WORD.findall(text))
    if not words & set(PROGRAM_WORDS) and not _ASSIGN.search(text):
        return False
    printable = sum(1 for ch in text if ch.isalnum() or ch in " \n\t_.,:;'\"()[]{}=+-*/<>!%&|^~@#$?\\")
    return printable >= len(text) * 0.97


def _statement_count(text: str) -> int:
    try:
        return sum(1 for _ in ast.walk(ast.parse(text)))
    except (SyntaxError, ValueError, RecursionError):
        return 0


def _score(kind: str, value) -> tuple[int, int]:
    """Rank a candidate: a code object beats parsed source beats opened bytes."""
    if kind == "code":
        return (3, 0)
    if kind == "text":
        if _plausible_program(value):
            return (2, _statement_count(value))
        return (0, 0)
    if kind == "bytes":
        for decoder in (marshal.loads, zlib.decompress):
            try:
                decoder(bytes(value))
            except Exception:                        # noqa: BLE001
                continue
            return (1, len(value))
    return (0, 0)


def hunt(source: str, versions: list | None = None) -> dict | None:
    """Enumerate run-time key candidates and return the one that opens the file.

    Returns ``{"name", "value", "kind", "payload", "tried", "ambiguous"}`` or
    ``None`` when no candidate produces something structurally valid.
    """
    if len(source) > MAX_SOURCE:
        return None
    spaces = candidates(source)
    if not spaces:
        return None
    started = time.time()
    best = None
    winners: list[tuple[str, dict]] = []
    tried = 0
    for name, values in spaces:
        exact = len(values) < BYTE_SPACE
        # An "exact" inference is a hypothesis: ``len(os.urandom(16))`` is 16,
        # but a packer may derive its byte from that length differently
        # (``_k = len(...) % 251`` inside a helper, say).  When the exact set
        # fails, fall back to the whole byte space before giving up.
        plan = list(values)
        if len(plan) < BYTE_SPACE and values and max(values) <= BYTE_SPACE:
            plan = plan + [value for value in range(BYTE_SPACE) if value not in set(plan)]
        for value in plan:
            if time.time() - started > TIME_BUDGET:
                break
            tried += 1
            try:
                resolved = resolve_expression_payload(source, {name: value})
            except Exception:                        # noqa: BLE001
                continue
            if resolved is None:
                continue
            kind, payload = resolved
            rank = _score(kind, payload)
            if rank[0] == 0:
                continue
            winners.append((f"{name}={value}", {"name": name, "value": value,
                                                "kind": kind, "payload": payload,
                                                "score": rank}))
            confidence = 2 if exact else 1
            rank = (rank[0], confidence, rank[1])
            if best is None or rank > best["score"]:
                best = dict(winners[-1][1], score=rank)
        if best is not None and best["score"][0] == 3:
            break                                    # a real code object: done
    if best is None:
        return None
    rivals = {(entry[1]["kind"], str(entry[1]["payload"])[:64]) for entry in winners}
    ambiguous = len(rivals) > 1 and best["score"][0] < 3
    return {"name": best["name"], "value": best["value"], "kind": best["kind"],
            "payload": best["payload"], "tried": tried,
            "ambiguous": ambiguous, "rivals": len(rivals)}


def describe(result: dict) -> str:
    """One line for the trace and the report."""
    name, value = result["name"], result["value"]
    shown = f"0x{value:02x}" if isinstance(value, int) and 0 <= value <= 255 else repr(value)
    line = (f"run-time key: enumerated {result['tried']} candidate value(s) of "
            f"`{name}` → payload opens with {name} = {shown}")
    if result.get("ambiguous"):
        line += " (ambiguous: more than one candidate produced valid output)"
    return line
