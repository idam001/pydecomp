"""Where the backend tree meets the peeler.

The peeler reads a loader.  When it cannot - the key came from the environment,
the file was read at run time, the scheme is the packer's own - the bytes are
still in the file, and the backend tree can open them without knowing anything
about the code around them.

Two rules keep this honest.  It only runs when the expression paths found
nothing, so a file the peeler understands is never second-guessed.  And a chain
only ends in a payload when the result survives a check that is stricter than
"it parsed": a program has statements, compiles, and does not read as noise.
"""
from __future__ import annotations

import ast
import hashlib
import types
import warnings

from ..bytecode.magic import MAGIC_VERSIONS_BYTES
from ..bytecode.marshal_reader import parse_marshal_blob
from ..plugins.backends import Budget, explore

#: chains longer than this are not a loader, they are an accident
MAX_CHAIN = 5
#: literal blobs smaller than this are keys and tables, not payloads
MIN_BLOB = 64
#: how many starts one file may offer the explorer
MAX_STARTS = 3


def _compiles(text: str) -> bool:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compile(text, "<payload>", "exec")
        return True
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False


def looks_like_payload(data: bytes) -> bool:
    """Stricter than the peeler's own check, because this is a search result.

    A chain search passes through a lot of bytes that happen to parse.  A
    payload is source with a statement in it that compiles, or a marshal stream
    that parses - anything else is a candidate that did not survive.
    """
    if not data:
        return False
    if data[:2] in MAGIC_VERSIONS_BYTES and len(data) > 20:
        return True
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if len(text.strip()) < 24:
        return False
    if not _compiles(text):
        return False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return False
    # Noise parses too: `W:l@AG#HA1+9...` is a bare annotation, `'W8j>AG#'` is a
    # string literal.  What both lack is the thing every real file has - a name
    # a person would write, and something that does work.
    statements = (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef, ast.Import,
                  ast.ImportFrom, ast.If, ast.For, ast.While, ast.With, ast.Try,
                  ast.Return, ast.Raise)
    if not any(isinstance(node, statements) for node in tree.body):
        if not any(isinstance(node, ast.Call) for node in ast.walk(tree)):
            return False
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
    return any(len(name) >= 3 and (name.islower() or "_" in name or name[1:].islower())
               for name in names)


def _holds_code(obj, depth: int = 0) -> bool:
    if isinstance(obj, types.CodeType):
        return True
    if depth >= 3:
        return False
    if isinstance(obj, dict):
        return any(_holds_code(item, depth + 1) for item in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_holds_code(item, depth + 1) for item in obj)
    return False


def _marshal_shape(data: bytes) -> str | None:
    """A marshal stream counts when it actually holds code.

    ``parse_marshal_blob`` is deliberately permissive - it will read a tuple of
    integers out of almost anything - so a payload has to be a code object or a
    container of them.  Without that, a shifted string of punctuation "parses"
    and the search reports it as a payload.
    """
    if data[:2] in MAGIC_VERSIONS_BYTES and len(data) > 20:
        return "marshal"
    try:
        version, obj, _layout = parse_marshal_blob(data)
    except Exception:                                    # noqa: BLE001
        return None
    if obj is None or not version:
        return None
    return "marshal" if _holds_code(obj) else None


def _accept(data: bytes, chain) -> bool:
    return bool(looks_like_payload(data)) or _marshal_shape(data) == "marshal"


def explore_blobs(blobs, budget: Budget | None = None):
    """Open each blob with the backend tree; returns ``[(recipe, data, kind)]``.

    Blobs are tried biggest first: a loader's payload is the large literal, and
    the small ones are keys, alphabets and IVs.
    """
    results = []
    seen = set()
    starts = 0
    for blob in sorted(blobs, key=len, reverse=True):
        if len(blob) < MIN_BLOB or starts >= MAX_STARTS:
            break
        starts += 1
        outcome = explore(blob, _accept, depth=MAX_CHAIN,
                          budget=budget or Budget(opens=400))
        if outcome.exhausted and not outcome.hits:
            # the search stopped early, so "nothing found" is not a result yet
            outcome = explore(blob, _accept, depth=MAX_CHAIN,
                              budget=budget or Budget(opens=2000))
        for hit in outcome.hits:
            digest = hashlib.sha256(hit.data).digest()
            if digest in seen:
                continue
            seen.add(digest)
            kind = _marshal_shape(hit.data) or "python"
            results.append((list(hit.chain), hit.data, kind))
    return results
