"""pydecomp - disassembler."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj
from ..bytecode.opcodes.tables import BINARY_SYMS, COMPARE_SYMS, OPNAMES

def disassemble(code: CodeObj, version: tuple):
    names = OPNAMES.get(version) or OPNAMES.get((3, 14), {})
    consts, nm, vars_ = code.consts, code.names, code.varnames
    raw = code.code
    extended = 0
    off = 0
    name_pool_ops = {"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "LOAD_GLOBAL",
                     "STORE_GLOBAL", "DELETE_GLOBAL", "LOAD_ATTR", "STORE_ATTR",
                     "DELETE_ATTR", "IMPORT_NAME", "IMPORT_FROM", "LOAD_METHOD",
                     "LOAD_SUPER_ATTR", "LOAD_FROM_DICT_OR_GLOBALS"}
    while off < len(raw) - 1:
        op = raw[off]
        if op == 0:                                      # inline CACHE slot
            off += 2
            continue
        arg = (extended << 8) | raw[off + 1]
        extended = 0
        opname = names.get(op, f"OP_{op}")
        if opname == "EXTENDED_ARG":
            extended = arg
            off += 2
            continue
        text = ""
        if opname in ("LOAD_CONST", "RETURN_CONST"):
            text = repr(consts[arg]) if arg < len(consts) else f"<const {arg}>"
        elif opname in name_pool_ops:
            idx = arg >> 1 if opname in ("LOAD_GLOBAL", "STORE_GLOBAL", "LOAD_ATTR",
                                         "STORE_ATTR", "LOAD_SUPER_ATTR") else arg
            text = nm[idx] if idx < len(nm) else f"<{idx}>"
        elif opname in ("LOAD_FAST", "STORE_FAST", "DELETE_FAST", "LOAD_FAST_CHECK",
                        "LOAD_FAST_AND_CLEAR", "LOAD_FAST_BORROW", "LOAD_DEREF",
                        "STORE_DEREF", "MAKE_CELL"):
            text = vars_[arg] if arg < len(vars_) else f"<{arg}>"
        elif opname in ("LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW",
                        "STORE_FAST_LOAD_FAST", "STORE_FAST_STORE_FAST"):
            a, b = arg >> 4, arg & 15
            text = "%s, %s" % (vars_[a] if a < len(vars_) else "?",
                               vars_[b] if b < len(vars_) else "?")
        elif opname == "LOAD_SMALL_INT":
            text = str(arg)
        elif opname == "LOAD_COMMON_CONSTANT":
            text = f"<common {arg}>"
        elif opname == "BINARY_OP":
            text = BINARY_SYMS.get(arg, str(arg))
        elif opname == "COMPARE_OP":
            # 3.12 packs flags in the low 4 bits, 3.13+ in the low 5 bits;
            # verified against a real `a == b` compile for each table we ship.
            if version >= (3, 13):
                idx = arg >> 5
            elif version >= (3, 12):
                idx = arg >> 4
            else:
                idx = arg
            if idx >= len(COMPARE_SYMS):
                idx = arg & 0x0F
            text = COMPARE_SYMS[idx] if idx < len(COMPARE_SYMS) else f"cmp({arg})"
        elif opname == "IS_OP":
            text = "is not" if arg else "is"
        elif opname == "CONTAINS_OP":
            text = "not in" if arg else "in"
        elif "JUMP" in opname or opname in ("FOR_ITER", "SEND"):
            text = (f"to {off + 2 - arg * 2}" if "BACKWARD" in opname
                    else f"to {off + 2 + arg * 2}")
        yield off, opname, arg, text
        off += 2
