"""pydecomp - __init__."""
from __future__ import annotations

from ..decoders.emoji import parses_as_python
from ..polish.dead import _strip_dead
from ..polish.demangle import _ast, _demangle
from ..polish.fold import _fold_constants, _fold_literals
from ..polish.unflatten import _unflatten
from ..terminal.banner import header

def polish_source(text: str, clean: bool = True) -> tuple[str, list[str]]:
    """Readability passes over the recovered file.  Never changes what it does."""
    notes = []
    if not clean or len(text) > 4 * 1024 * 1024:
        return text, notes
    header, body = "", text
    if text.startswith("#"):
        split = text.find("\n\n")
        if 0 < split < 4000:
            header, body = text[:split + 2], text[split + 2:]
    try:
        tree = _ast.parse(body)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return text, notes
    try:
        mapping = _demangle(tree)
        if mapping:
            notes.append(f"de-mangled {len(mapping)} identifiers")
        folded = _fold_constants(tree)
        literals = _fold_literals(tree)
        if literals:
            notes.append(f"inlined {literals} encoded literal(s)")
        dead = _strip_dead(tree)
        if dead:
            notes.append(f"dropped {dead} dead branch(es)")
        flat = _unflatten(tree)
        if flat:
            notes.append(f"un-flattened {flat} state machine(s)")
        if not any((mapping, literals, dead, flat)):
            return text, notes
        out = _ast.unparse(tree)
        if mapping:
            legend = "\n".join(f"#   {new} = {old}" for old, new in
                               sorted(mapping.items(), key=lambda kv: kv[1])[:40])
            out = ("# identifiers renamed for readability (original on the right):\n"
                   + legend + "\n\n" + out)
        if not parses_as_python(out):
            return text, []
        return header + out + "\n", notes
    except Exception:                                # noqa: BLE001 - never break a run
        return text, []
