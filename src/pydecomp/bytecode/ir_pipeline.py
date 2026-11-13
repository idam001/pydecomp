"""pydecomp - the SSA pipeline, from code object to source.

Two engines now share the front of the decompiler:

* the **stack engine** walks the stack and prints statements as it goes;
* the **SSA engine** builds :mod:`pydecomp.bytecode.ir`, recovers structure from
  the control-flow graph, and emits an AST.

The SSA engine runs first and only its *verified* output is kept: the text it
produces is recompiled and diffed instruction-for-instruction against the
original code object, and if a single instruction differs the file falls back to
the stack engine.  That is the rule that makes a second engine safe to add - a
reconstruction is accepted when it is provably identical, not when it looks
right.
"""
from __future__ import annotations

from ..bytecode.codeobj import codeobj_from_host
from ..bytecode.ir_build import Unsupported, build_ir
from ..bytecode.ir_emit import emit_module
from ..proof import tiers

#: past this much bytecode the IR attempt costs more than it returns; the stack
#: engine already reproduces large files, so the SSA pass is skipped
IR_SIZE_LIMIT = 400_000


def emit_ir(code, version: tuple) -> tuple[str | None, str]:
    """Emit source from the SSA form.  Returns ``(text, reason)``."""
    try:
        fir = build_ir(code, version)
    except Unsupported as exc:
        return None, f"unsupported: {exc}"
    except RecursionError:
        return None, "unsupported: nesting"
    if not fir.blocks:
        return None, "empty code object"
    try:
        text = emit_module(fir, version)
    except Unsupported as exc:
        return None, f"unsupported: {exc}"
    except RecursionError:
        return None, "unsupported: nesting"
    return text, "emitted"


def lift_module_ir(code, version: tuple) -> tuple[str | None, dict]:
    """The module as source, but only when the SSA text is instruction-identical."""
    report: dict = {"engine": "ssa-ir", "blocks": 0, "values": 0, "loops": 0,
                    "tier": "none", "detail": ""}
    size = len(getattr(code, "code", b"") or b"")
    if size > IR_SIZE_LIMIT:
        report["detail"] = f"code object is {size:,} B; stack engine takes it"
        return None, report
    try:
        fir = build_ir(code, version)
    except Unsupported as exc:
        report["detail"] = f"opcode outside the IR: {exc}"
        return None, report
    except (RecursionError, MemoryError):
        report["detail"] = "nesting too deep for the IR"
        return None, report
    stats = fir.stats()
    report.update(blocks=stats["blocks"], values=stats["values"],
                  loops=stats["loops"])
    try:
        text = emit_module(fir, version)
    except Unsupported as exc:
        report["detail"] = f"structure outside the emitter: {exc}"
        return None, report
    except (RecursionError, MemoryError):
        report["detail"] = "structure too deep for the emitter"
        return None, report
    try:
        rebuilt = codeobj_from_host(compile(text, "<ir>", "exec"))
    except (SyntaxError, ValueError, TypeError) as exc:
        report["detail"] = f"emitted text does not compile: {exc}"
        return None, report
    grade = tiers.grade(text, code, version)
    report["tier"] = grade
    if grade != "semantic":
        report["detail"] = "emitted text is not instruction-identical"
        return None, report
    report["detail"] = f"{len(text):,} chars, {stats['blocks']} blocks, " \
                       f"{stats['values']} values, {stats['loops']} loop edge(s)"
    return text, report


def available() -> str:
    return "in-house"


def describe() -> dict:
    return {"engine": "ssa-ir", "builder": "ir_build", "emitter": "ir_emit",
            "size_limit": IR_SIZE_LIMIT}
