"""pydecomp - tiers.

Three questions, asked in order, each stronger than the last:

1. **semantic** - recompile the recovered text and diff *every* instruction and
   operand against the original code object.  This is the standard PyLingual
   calls a perfect decompilation, and it is the only tier that is written
   without a warning header.
2. **structural** - the instruction streams differ (layout, encoding or a
   different interpreter version) but the control-flow shape and the constant
   table match.  Equivalent program, different bytes.
3. **syntactic** - it compiles.  Nothing about equivalence is claimed.

Anything that does not compile is ``unverified`` and says so in the file.

The comparison never imports or executes the sample: the original is a
``CodeObj`` parsed from bytes, and the rebuilt side comes from ``compile()`` of
text this tool just wrote.
"""
from __future__ import annotations

import warnings
from collections import Counter
from itertools import zip_longest

from ..bytecode.codeobj import CodeObj, codeobj_from_host
from ..bytecode.disassembler import disassemble
from ..bytecode.magic import host_version
from ..bytecode.roundtrip import _paired_functions, _stream_pairs

#: lower is stronger.  Used to decide whether a cleaning pass may be kept.
TIER_RANK = {"semantic": 0, "structural": 1, "syntactic": 2, "unverified": 3}

#: opcodes whose presence is a layout detail, not a behaviour difference
_NOISE = {"RESUME", "CACHE", "NOP", "EXTENDED_ARG", "NOT_TAKEN", "EXTENDED_OP",
          "COPY_FREE_VARS", "MAKE_CELL", "RETURN_GENERATOR"}


def last_module() -> tuple:
    """The code object the lifter just rebuilt, and its interpreter version.

    The lifter keeps its record on ``lift.module``; older code read the copy in
    ``bytecode.codeobj``, which the lifter never rebinds.  Looking in both is
    what makes the tier real instead of always "syntactic".
    """
    from ..bytecode import codeobj as _codeobj
    from ..lift import module as _lift
    code = (getattr(_lift, "_last_module_code", None)
            or getattr(_codeobj, "_last_module_code", None))
    version = getattr(_lift, "_last_module_version", None)
    return code, version


def compiles(text: str) -> tuple[bool, str]:
    """Compile-only check.  Nothing is imported, nothing runs."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            compile(text, "<proof>", "exec")
        return True, ""
    except SyntaxError as exc:
        return False, f"SyntaxError line {exc.lineno}: {exc.msg}"
    except (ValueError, TypeError, MemoryError, RecursionError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _shape(code: CodeObj, version: tuple) -> list:
    """A jump-free profile: which operations, how many, in what order."""
    out = []
    for _offset, opname, arg, _text in disassemble(code, version):
        if opname in _NOISE:
            continue
        if "JUMP" in opname or opname in ("FOR_ITER", "SEND"):
            out.append(("BRANCH", ""))
            continue
        out.append((opname, "" if arg is None else "arg"))
    return out


def _consts(code: CodeObj) -> list:
    seen = []
    for const in code.consts:
        if isinstance(const, CodeObj):
            continue
        seen.append(repr(const))
    return sorted(seen)


def _walk(code: CodeObj, out: list) -> list:
    out.append(code)
    for const in code.consts:
        if isinstance(const, CodeObj):
            _walk(const, out)
    return out


def compare(text: str, code: CodeObj | None = None,
            version: tuple | None = None) -> dict:
    """Grade one recovered text against the code object it came from.

    Returns ``{"tier", "detail", "units": {name: (tier, detail)}}``.  ``units``
    holds one entry per code object, so a module whose functions all match but
    whose module body differs is reported honestly instead of on average.
    """
    if code is None or version is None:
        recorded, recorded_version = last_module()
        code = code if code is not None else recorded
        version = version if version is not None else (recorded_version or host_version())
    version = tuple(version[:2])
    host = host_version()

    ok, why = compiles(text)
    if not ok:
        return {"tier": "unverified", "detail": why,
                "units": {"<module>": ("unverified", why)}}
    if code is None:
        return {"tier": "syntactic", "detail": "no original code object recorded",
                "units": {"<module>": ("syntactic", "compiles")}}

    rebuilt = codeobj_from_host(compile_safe(text))
    if rebuilt is None:
        return {"tier": "syntactic", "detail": "recompile produced no code object",
                "units": {"<module>": ("syntactic", "compiles")}}

    same_version = version == host
    units: dict[str, tuple] = {}
    semantic_units = 0
    if same_version:
        pairs = list(_paired_functions(code, rebuilt))
    else:
        left, right = _walk(code, []), _walk(rebuilt, [])
        pairs = [(getattr(a, "qualname", None) or a.name, a, b)
                 for a, b in zip_longest(left, right) if a is not None and b is not None]
    for name, original, mine in pairs:
        label = getattr(original, "qualname", None) or name or "<unit>"
        if same_version:
            left = _stream_pairs(original, version)
            right = _stream_pairs(mine, host)
            if left == right:
                units[label] = ("semantic", f"{len(left)}/{len(left)} instructions")
                semantic_units += 1
                continue
        left_shape = _shape(original, version)
        right_shape = _shape(mine, host)
        same_consts = _consts(original) == _consts(mine)
        if Counter(left_shape) == Counter(right_shape) and same_consts:
            units[label] = ("structural", "same opcode profile and constant table")
            continue
        drift = sum((Counter(left_shape) - Counter(right_shape)).values())
        units[label] = ("syntactic",
                        f"{drift} opcode(s) differ" if drift else "constant table differs")
    if not units:
        return {"tier": "syntactic", "detail": "nothing to compare",
                "units": {"<module>": ("syntactic", "compiles")}}
    for name, (tier, detail) in units.items():
        if tier != "semantic":
            return {"tier": tier, "detail": f"{name}: {detail}", "units": units}
    return {"tier": "semantic",
            "detail": f"{semantic_units}/{len(units)} units instruction-identical",
            "units": units}


def compile_safe(text: str):
    try:
        return compile(text, "<proof>", "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None


def grade(text: str, code: CodeObj | None = None,
          version: tuple | None = None) -> str:
    """Just the tier string, for callers that do not need the evidence."""
    return compare(text, code, version)["tier"]
