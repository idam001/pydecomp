"""pydecomp - tiers.

Proof grades distinguish exact instruction rendering, instruction semantics,
control-flow shape and compilation.

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
from ..bytecode.roundtrip import (_instruction_records, _paired_functions,
                                           _stream_pairs)

#: lower is stronger.  Used to decide whether a cleaning pass may be kept.
TIER_RANK = {"perfect": 0, "semantic": 1, "structural": 2,
             "syntactic": 3, "unverified": 4}

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



def _perfect_stream(code: CodeObj, version: tuple) -> list:
    return _instruction_records(code, version)


def _paired_all(original: CodeObj, rebuilt: CodeObj) -> list | None:
    left = _walk(original, [])
    right = _walk(rebuilt, [])
    buckets: dict[str, list] = {}
    for node in right:
        key = getattr(node, "qualname", None) or node.name
        buckets.setdefault(key, []).append(node)
    pairs = []
    for node in left:
        key = getattr(node, "qualname", None) or node.name
        bucket = buckets.get(key)
        if not bucket:
            return None
        pairs.append((key, node, bucket.pop(0)))
    if any(bucket for bucket in buckets.values()):
        return None
    return pairs

def compare(text: str, code: CodeObj | None = None,
            version: tuple | None = None) -> dict:
    if code is None or version is None:
        recorded, recorded_version = last_module()
        code = code if code is not None else recorded
        version = version if version is not None else (recorded_version or host_version())
    version = tuple(version[:2])
    host = host_version()
    ok, why = compiles(text)
    if not ok:
        return {"tier": "unverified", "detail": why,
                "units": {"<module>": ("unverified", why)},
                "tier_0_units": [], "perfect_match": "0/0 instructions identical"}
    if code is None:
        return {"tier": "syntactic", "detail": "no original code object recorded",
                "units": {"<module>": ("syntactic", "compiles")},
                "tier_0_units": [], "perfect_match": "0/0 instructions identical"}
    rebuilt_code = compile_safe(text)
    if rebuilt_code is None:
        return {"tier": "syntactic", "detail": "recompile produced no code object",
                "units": {"<module>": ("syntactic", "compiles")},
                "tier_0_units": [], "perfect_match": "0/0 instructions identical"}
    rebuilt = codeobj_from_host(rebuilt_code)
    same_version = version == host
    pairs = _paired_all(code, rebuilt) if same_version else None
    units: dict[str, tuple] = {}
    tier_0_units: list[str] = []
    matched_instructions = total_instructions = 0
    if pairs is None:
        fallback = list(_paired_functions(code, rebuilt))
        pairs = fallback
        units["<code-object set>"] = ("syntactic", "code-object names or counts differ")
    for name, original, mine in pairs:
        label = getattr(original, "qualname", None) or name or "<unit>"
        if same_version:
            left_exact = _perfect_stream(original, version)
            right_exact = _perfect_stream(mine, host)
            limit = max(len(left_exact), len(right_exact))
            same = left_exact == right_exact
            total_instructions += limit
            matched_instructions += (len(left_exact) if same else
                                     sum(a == b for a, b in zip(left_exact, right_exact)))
            if same:
                units[label] = ("perfect", f"{len(left_exact)}/{len(left_exact)} instructions")
                tier_0_units.append(label)
                continue
            left = _stream_pairs(original, version)
            right = _stream_pairs(mine, host)
            if left == right:
                units[label] = ("semantic", f"{len(left)}/{len(left)} non-branch instructions")
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
                "units": {"<module>": ("syntactic", "compiles")},
                "tier_0_units": [], "perfect_match": "0/0 instructions identical"}
    for name, (tier, detail) in units.items():
        if tier not in ("perfect", "semantic"):
            return {"tier": tier, "detail": f"{name}: {detail}", "units": units,
                    "tier_0_units": tier_0_units,
                    "perfect_match": f"{matched_instructions}/{total_instructions} instructions identical"}
    result_tier = "perfect" if all(tier == "perfect" for tier, _ in units.values()) else "semantic"
    perfect_match = f"{matched_instructions}/{total_instructions} instructions identical"
    return {"tier": result_tier,
            "detail": f"{len(tier_0_units)}/{len(units)} units instruction-identical"
                      if result_tier == "perfect" else f"all units match outside control-flow operands; {perfect_match}",
            "units": units, "tier_0_units": tier_0_units,
            "perfect_match": perfect_match}


def compile_safe(text: str):
    try:
        return compile(text, "<proof>", "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None


def grade(text: str, code: CodeObj | None = None,
          version: tuple | None = None) -> str:
    """Just the tier string, for callers that do not need the evidence."""
    return compare(text, code, version)["tier"]
