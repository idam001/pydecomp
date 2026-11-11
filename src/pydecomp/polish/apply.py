"""pydecomp - apply.

The Almighty pipeline, run to a **fixed point**.

That last part matters.  Deobfuscation passes feed each other: a constant
propagation exposes a decoder call, the decoder inlining turns it into a literal,
folding collapses the chain, the new literal makes an opaque predicate provable,
and the pruned branch drops a whole junk function.  Running each pass once gets a
fraction of the work - so the loop below repeats the whole set until an iteration
changes nothing (bounded, so a pathological file cannot spin).

Every pass here is cosmetic: it rewrites *how* the recovered program reads,
never what it does.
"""
from __future__ import annotations

import time

from ..decoders.emoji import parses_as_python
from ..polish.aliases import normalize_aliases, selfdoc_payload
from ..polish.dead import _strip_dead
from ..polish.demangle import _ast, _demangle
from ..polish.evaluate import fold_expressions
from ..polish.fold import _fold_constants, _fold_literals
from ..polish.inline import inline_pure_functions, propagate_constants
from ..polish.mba import simplify_mba
from ..polish.opaque import strip_opaque
from ..polish.strarrays import resolve_string_arrays
from ..polish.unflatten import _unflatten

_LEGEND_LIMIT = 40
_ROUNDS = 6
_TIME_BUDGET = 25.0          # seconds; a runaway pass must not hang a batch run


def _one_round(tree, notes, fast: bool) -> int:
    """Run the pass set once.  Returns how many things changed."""
    changed = 0
    try:
        strings = resolve_string_arrays(tree)
        if strings:
            notes.append(f"resolved {strings} string-table lookup(s)")
            changed += strings
    except Exception:                                    # noqa: BLE001
        pass
    try:
        aliases, unicode_legend = normalize_aliases(tree)
        if aliases:
            notes.append(f"resolved {aliases} alias/unicode name(s)")
            changed += aliases
        else:
            unicode_legend = {}
    except Exception:                                    # noqa: BLE001
        unicode_legend = {}
    try:
        propagated, env = propagate_constants(tree)
        if propagated:
            notes.append(f"propagated {propagated} constant(s)")
            changed += propagated
    except Exception:                                    # noqa: BLE001
        env = {}
    try:
        replaced = inline_pure_functions(tree)
        if replaced:
            notes.append(f"inlined {replaced} decoder call(s)")
            changed += replaced
    except Exception:                                    # noqa: BLE001
        pass
    try:
        folded = fold_expressions(tree, env)
        if folded:
            notes.append(f"evaluated {folded} pure expression(s)")
            changed += folded
    except Exception:                                    # noqa: BLE001
        pass
    try:
        mba = simplify_mba(tree)
        if mba:
            notes.append(f"simplified {mba} mixed-boolean expression(s)")
            changed += mba
    except Exception:                                    # noqa: BLE001
        pass
    if not fast:
        try:
            opaque = strip_opaque(tree)
            if opaque:
                notes.append(f"proved {opaque} opaque predicate(s) away")
                changed += opaque
        except Exception:                                # noqa: BLE001
            pass
    try:
        literals = _fold_literals(tree)
        if literals:
            notes.append(f"inlined {literals} encoded literal(s)")
            changed += literals
    except Exception:                                    # noqa: BLE001
        pass
    try:
        dead = _strip_dead(tree)
        if dead:
            notes.append(f"dropped {dead} dead branch(es)")
            changed += dead
    except Exception:                                    # noqa: BLE001
        pass
    try:
        flat = _unflatten(tree)
        if flat:
            notes.append(f"un-flattened {flat} state machine(s)")
            changed += flat
    except Exception:                                    # noqa: BLE001
        pass
    return changed, unicode_legend


def polish_source(text: str, clean: bool = True, fast: bool = False) -> tuple[str, list[str]]:
    """Readability passes over the recovered file.  Never changes what it does."""
    notes: list[str] = []
    if not clean or len(text) > 64 * 1024 * 1024:
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

    # a self-hosting module: the program is the docstring
    try:
        hidden = selfdoc_payload(tree)
        if hidden:
            tree.body = hidden
            notes.append("recovered the program hidden in the module docstring")
    except Exception:                                    # noqa: BLE001
        pass

    legend: dict[str, str] = {}
    started = time.monotonic()
    total = 0
    try:
        for _round in range(_ROUNDS):
            changed, unicode_legend = _one_round(tree, notes, fast)
            total += changed
            legend.update(unicode_legend or {})
            if not changed or time.monotonic() - started > _TIME_BUDGET:
                break
        mapping = _demangle(tree)
        if mapping:
            notes.append(f"de-mangled {len(mapping)} identifiers")
            total += len(mapping)

        # one last fold, so freshly de-mangled names do not hide a literal
        folded = _fold_constants(tree)
        if not total:
            return text, notes
        out = _ast.unparse(tree)
        lines = []
        if mapping:
            lines.append("# identifiers renamed for readability "
                         "(original on the right):")
            lines.extend(f"#   {new} = {old}" for old, new in
                         sorted(mapping.items(), key=lambda kv: kv[1])[:_LEGEND_LIMIT])
        if legend:
            lines.append("# unicode identifiers transliterated:")
            lines.extend(f"#   {new} = {old}" for old, new in
                         list(legend.items())[:_LEGEND_LIMIT])
        if lines:
            out = "\n".join(lines) + "\n\n" + out
        if not parses_as_python(out):
            return text, []
        return header + out + "\n", notes
    except Exception:                                    # noqa: BLE001 - never break a run
        return text, []
