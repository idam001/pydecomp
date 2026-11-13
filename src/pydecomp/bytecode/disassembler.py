"""pydecomp - disassembler."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj
from ..bytecode.opcodes.tables import (BINARY_SYMS, COMPARE_SYMS, compare_table,
                                       jump_kind, table_for)

def _jump_target(version: tuple, off: int, opname: str, arg: int) -> int:
    """Absolute offset a jump lands on, by that version's own convention.

    Three conventions are in play, and which one applies is read from the
    release's own opcode listing rather than guessed from the name:

    * up to 3.10, ``hasjabs`` opcodes name an absolute address in code units and
      ``hasjrel`` ones count from the end of their own instruction;
    * 3.11 made every jump relative;
    * 3.13 measures from the end of the instruction that follows instead - two
      bytes further - which is checked against the interpreter.

    The third rule is the one no opcode table states: it lives in the eval loop,
    so ``tests/unit/test_ir.py`` compares every target with ``dis``.
    """
    if version < (3, 11):
        if jump_kind(version, opname) == "absolute":
            return arg * 2
        return off + 2 + arg * 2
    pad = 2 if version >= (3, 13) else 0
    if "BACKWARD" in opname:
        return off + 2 + pad - arg * 2
    return off + 2 + pad + arg * 2


def _pool(value):
    """A constant/name table, or an empty one.

    A code object that came out of a partly-decoded stream can hold a scalar where
    a table belongs.  Rendering `<arg>` for it keeps the disassembly going, which
    is what the caller wants: it is scoring a candidate decode, and a decode that
    does not even hold tables should score badly rather than raise.
    """
    return value if isinstance(value, (list, tuple)) else ()


def disassemble(code: CodeObj, version: tuple):
    names = table_for(version)
    consts, nm, vars_ = _pool(code.consts), _pool(code.names), _pool(code.varnames)
    raw = code.code if isinstance(code.code, (bytes, bytearray)) else b""
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
            table = compare_table(version)
            if table and version < (3, 12):
                # 3.8-3.11 index the release's own cmp_op list, which on 3.8
                # also holds `in`, `is` and `exception match`
                text = table[arg] if arg < len(table) else f"cmp({arg})"
            else:
                # 3.12 packs flags in the low 4 bits, 3.13+ in the low 5 bits;
                # verified against a real `a == b` compile on each interpreter
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
        elif "JUMP" in opname or opname in ("FOR_ITER", "SEND") \
                or opname.startswith("SETUP_"):
            text = f"to {_jump_target(version, off, opname, arg)}"
        yield off, opname, arg, text
        off += 2
