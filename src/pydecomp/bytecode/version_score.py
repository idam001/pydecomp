"""pydecomp - version_score."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj
from ..bytecode.disassembler import _pool, disassemble
from ..bytecode.opcodes.tables import OPNAMES

def _version_score(code: "CodeObj", version: tuple) -> float:
    """How plausible is it that ``code`` was compiled by ``version``?

    The marshal layout of a code object is identical for 3.11 - 3.15, so the
    layout cannot tell versions apart.  The instruction stream can: opcode
    numbers were renumbered, so the wrong table produces unknown opcodes,
    *out-of-range operands* (a name/const/local index that does not exist) and
    jumps that land outside the code.  All three are counted, over the whole
    code tree, and normalised by the instruction count so a version cannot win
    just by decoding into more instructions.
    """
    names = OPNAMES.get(version)
    if not names or not isinstance(code.code, (bytes, bytearray)) or len(code.code) < 2:
        return -1e9
    name_ops = {"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "LOAD_GLOBAL",
                "STORE_GLOBAL", "DELETE_GLOBAL", "LOAD_ATTR", "STORE_ATTR",
                "DELETE_ATTR", "LOAD_METHOD", "IMPORT_NAME", "IMPORT_FROM",
                "LOAD_FROM_DICT_OR_GLOBALS", "LOAD_SUPER_ATTR"}
    shifted = {"LOAD_GLOBAL", "STORE_GLOBAL", "LOAD_ATTR", "STORE_ATTR",
               "DELETE_ATTR", "LOAD_METHOD", "LOAD_SUPER_ATTR"}
    fast_ops = {"LOAD_FAST", "STORE_FAST", "DELETE_FAST", "LOAD_FAST_CHECK",
                "LOAD_FAST_AND_CLEAR", "LOAD_FAST_BORROW", "STORE_FAST_MAYBE_NULL",
                "LOAD_FAST_BORROW_AND_CLEAR", "MAKE_CELL", "LOAD_CLOSURE"}
    pair_ops = {"STORE_FAST_STORE_FAST", "STORE_FAST_LOAD_FAST",
                "LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"}
    const_ops = {"LOAD_CONST", "RETURN_CONST", "KW_NAMES"}

    totals = {"ops": 0, "unknown": 0, "bad_operand": 0, "bad_jump": 0, "jumps": 0}
    last = [""]

    def scan(unit):
        raw = unit.code if isinstance(unit.code, (bytes, bytearray)) else b""
        # a candidate decode without tables gets no operand-range scoring, so it
        # is scored on what it does hold
        local_names, local_vars = _pool(unit.names), _pool(unit.varnames)
        local_consts = _pool(unit.consts)
        for off, opname, arg, _text in disassemble(unit, version):
            totals["ops"] += 1
            last[0] = opname
            if opname.startswith("OP_"):
                totals["unknown"] += 1
                continue
            if opname in name_ops:
                index = arg >> 1 if opname in shifted else arg
                if index >= len(local_names):
                    totals["bad_operand"] += 1
            elif opname in fast_ops:
                if arg >= len(local_vars):
                    totals["bad_operand"] += 1
            elif opname in pair_ops:
                if (arg & 15) >= len(local_vars) or (arg >> 4) >= len(local_vars):
                    totals["bad_operand"] += 1
            elif opname in const_ops:
                if arg >= len(local_consts):
                    totals["bad_operand"] += 1
            elif "JUMP" in opname or opname in ("FOR_ITER", "SEND"):
                totals["jumps"] += 1
                delta = arg * 2
                target = (off + 2 - delta) if "BACKWARD" in opname else (off + 2 + delta)
                if not (-4 <= target <= len(raw) + 4):
                    totals["bad_jump"] += 1
        for const in local_consts:
            if isinstance(const, CodeObj):
                scan(const)

    try:
        scan(code)
    except RecursionError:
        return -1e9
    ops = max(totals["ops"], 1)
    score = 0.0
    if names.get(code.code[0]) == "RESUME" and code.code[1] == 0:
        score += 12.0
    score -= 900.0 * (totals["unknown"] / ops)
    score -= 900.0 * (totals["bad_operand"] / ops)
    if totals["jumps"]:
        score -= 400.0 * (totals["bad_jump"] / totals["jumps"])
    if last[0] in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "INTERPRETER_EXIT"):
        score += 6.0
    return score
