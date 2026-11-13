"""The version matrix: 3.8 through 3.15, in-house, end to end.

Three things are checked here, and none of them needs another interpreter on the
machine:

* every version this build reads has its own opcode table, and the tables agree
  with the language changes they belong to - a 3.8 table that knows `MATCH_*`
  or a 3.9 table that still knows `SETUP_LOOP` fails the build;
* hand-assembled 3.8/3.9/3.10 bytecode - the block-stack era, where a loop
  pushes a block and `JUMP_ABSOLUTE` closes it - reaches the same IR and the
  same emitter as 3.13's relative jumps;
* the constructs 3.14 and 3.15 added are named and decoded: NOT_TAKEN,
  LOAD_FAST_BORROW, LOAD_SMALL_INT, RETURN_CONST and BINARY_OP's NB_SUBSCR.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pytest                                              # noqa: E402

from pydecomp.bytecode.codeobj import CodeObj, codeobj_from_host  # noqa: E402
from pydecomp.bytecode.disassembler import disassemble       # noqa: E402
from pydecomp.bytecode.ir_build import build_ir, Unsupported  # noqa: E402
from pydecomp.bytecode.ir_emit import emit_module            # noqa: E402
from pydecomp.bytecode.opcodes.tables import (BINARY_SYMS, OPNAMES,  # noqa: E402
                                              compare_table, jump_kind,
                                              table_for)

VERSIONS = [(3, 8), (3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14), (3, 15)]


# -- the tables -------------------------------------------------------------

@pytest.mark.parametrize("version", VERSIONS)
def test_every_version_has_its_own_table(version):
    table = OPNAMES.get(version)
    assert table, f"no opcode table for {version}"
    assert len(table) >= 80, (version, len(table))
    # the three names no decoder can do without
    assert table[table and min(table)] is not None
    assert "RETURN_VALUE" in table.values()
    assert "LOAD_CONST" in table.values()
    assert "LOAD_FAST" in table.values()


def test_38_keeps_the_finally_block_stack():
    """3.8 is the last release that hands the decompiler a block stack."""
    names = set(OPNAMES[(3, 8)].values())
    for name in ("SETUP_FINALLY", "POP_BLOCK", "BEGIN_FINALLY", "END_FINALLY",
                 "CALL_FINALLY", "POP_FINALLY", "WITH_CLEANUP_START",
                 "WITH_CLEANUP_FINISH"):
        assert name in names, name


@pytest.mark.parametrize("version", VERSIONS)
def test_loop_blocks_are_not_an_opcode(version):
    """No version this build reads pushes a block for a loop: the compiler
    stopped emitting SETUP_LOOP before 3.8, and the operand space it freed is
    what the cell and exception opcodes moved into."""
    names = set(OPNAMES[version].values())
    for name in ("SETUP_LOOP", "SETUP_EXCEPT", "BREAK_LOOP", "CONTINUE_LOOP"):
        assert name not in names, (version, name)


@pytest.mark.parametrize("version", VERSIONS)
def test_finally_regions_belong_to_their_era(version):
    names = set(OPNAMES[version].values())
    assert ("SETUP_FINALLY" in names) is (version <= (3, 10))
    assert ("END_FINALLY" in names) is (version == (3, 8))
    assert ("PUSH_EXC_INFO" in names) is (version >= (3, 11))


@pytest.mark.parametrize("version", VERSIONS)
def test_the_calling_convention_belongs_to_its_era(version):
    names = set(OPNAMES[version].values())
    if version < (3, 11):
        assert "CALL_FUNCTION" in names
        assert "CALL" not in names
    else:
        assert "CALL" in names
        assert "CALL_FUNCTION" not in names


@pytest.mark.parametrize("version", VERSIONS)
def test_language_changes_land_in_the_right_table(version):
    names = set(OPNAMES[version].values())
    assert ("IS_OP" in names) is (version >= (3, 9))
    assert ("MATCH_CLASS" in names) is (version >= (3, 10))
    assert ("PRECALL" in names) is (version == (3, 11)), "3.11 only"
    assert ("RETURN_CONST" in names) is ((3, 12) <= version <= (3, 13))
    assert ("FORMAT_SIMPLE" in names) is (version >= (3, 13))
    assert ("LOAD_FAST_BORROW" in names) is (version >= (3, 14))
    assert ("NOT_TAKEN" in names) is (version >= (3, 14))
    assert ("LOAD_SMALL_INT" in names) is (version >= (3, 14))


def test_315_has_its_own_numbering():
    """3.15 is read from its own release, not inherited from 3.14."""
    assert OPNAMES[(3, 15)]
    assert OPNAMES[(3, 15)] is not OPNAMES[(3, 14)]
    assert BINARY_SYMS[26] == "[]", "NB_SUBSCR is the folded subscript operator"


def test_a_version_without_a_table_decodes_with_the_one_below_it():
    assert table_for((3, 9)) is OPNAMES[(3, 9)]
    assert table_for((3, 15)) is OPNAMES[(3, 15)]
    assert table_for((3, 16)) is OPNAMES[(3, 15)]      # newest table wins
    # 3.8's LOAD_CONST must never be read as 3.14's POP_JUMP_IF_FALSE
    assert table_for((3, 8))[100] == "LOAD_CONST"


# -- hand-assembled legacy bytecode ----------------------------------------

class Assembler:
    """A tiny label-based assembler for one version's two-byte encoding.

    Labels matter here: a 3.8 jump operand is an absolute code-unit address, so
    writing the operand by hand makes the test about arithmetic rather than
    about control flow.  The assembler resolves labels the way that version's
    compiler does.
    """

    def __init__(self, version: tuple):
        self.version = version
        self.numbers = {name: number for number, name in OPNAMES[version].items()}
        self.items: list[tuple] = []              # (opname, arg or label)

    def op(self, name: str, arg: int | str = 0) -> "Assembler":
        if name not in self.numbers:
            raise AssertionError(f"{name} does not exist in {self.version}")
        self.items.append((name, arg))
        return self

    #: comparison name -> index in COMPARE_OP's operand
    CMP_INDEX = {"<": 0, "<=": 1, "==": 2, "!=": 3, ">": 4, ">=": 5}

    def cmp(self, symbol: str) -> "Assembler":
        """COMPARE_OP, with the operand packed the way this version packs it."""
        index = self.CMP_INDEX[symbol]
        if self.version >= (3, 13):
            index <<= 5                      # 3.13 keeps flags in the low 5 bits
        elif self.version >= (3, 12):
            index <<= 4
        return self.op("COMPARE_OP", index)

    def jump_if_false(self, label: str) -> "Assembler":
        """The conditional-jump opcode that version actually has.

        3.11 split the conditional jumps into forward and backward forms, 3.12
        folded them back into one that takes a signed displacement.
        """
        if self.version == (3, 11):
            return self.op("POP_JUMP_FORWARD_IF_FALSE", label)
        return self.op("POP_JUMP_IF_FALSE", label)

    def label(self, name: str) -> "Assembler":
        self.items.append((":label:", name))
        return self

    def _offsets(self) -> dict:
        offsets, offset = {}, 0
        for name, arg in self.items:
            if name == ":label:":
                offsets[arg] = offset
                continue
            offset += 4 if isinstance(arg, int) and arg > 0xFF else 2
        return offsets

    def _encode(self, name: str, arg: str, offset: int, labels: dict) -> int:
        """Turn a label into the operand that version's compiler would emit."""
        target = labels[arg]
        if self.version < (3, 11):
            if jump_kind(self.version, name) == "absolute":
                return target // 2                    # absolute code units
            return (target - (offset + 2)) // 2       # relative to the end
        pad = 2 if self.version >= (3, 13) else 0
        base = offset + 2 + pad
        if "BACKWARD" in name:
            return (base - target) // 2
        return (target - base) // 2

    def assemble(self) -> bytes:
        labels = self._offsets()
        out = bytearray()
        offset = 0
        for name, arg in self.items:
            if name == ":label:":
                continue
            opcode = self.numbers[name]
            if isinstance(arg, str):
                arg = self._encode(name, arg, offset, labels)
            offset += 4 if arg > 0xFF else 2
            if arg > 0xFF:
                out += bytes((self.numbers["EXTENDED_ARG"], (arg >> 8) & 0xFF))
            out += bytes((opcode, arg & 0xFF))
        return bytes(out)

    def code(self, *, consts=(), names=(), varnames=("x",), argcount=1) -> CodeObj:
        code = CodeObj()
        code.name = code.qualname = "f"
        code.filename = "<assembled>"
        code.argcount = argcount
        code.stacksize = 8
        code.code = self.assemble()
        code.consts = tuple(consts)
        code.names = tuple(names)
        code.varnames = tuple(varnames)
        return code


LEGACY_VERSIONS = [(3, 8), (3, 9), (3, 10)]


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
def test_a_branch_in_308_survives_to_source(version):
    """`if x > 3: return 1` / `return 0`, with absolute jump targets."""
    a = Assembler(version)
    a.op("LOAD_FAST", 0)
    a.op("LOAD_CONST", 0)
    a.cmp(">")
    a.jump_if_false("small")
    a.op("LOAD_CONST", 1)
    a.op("RETURN_VALUE", 0)
    a.label("small")
    a.op("LOAD_CONST", 2)
    a.op("RETURN_VALUE", 0)
    code = a.code(consts=(3, 1, 0), names=())
    fir = build_ir(code, version)
    text = emit_module(fir, version)
    assert "if x > 3:" in text
    assert "return 1" in text and "return 0" in text
    assert fir.stats()["blocks"] == 3


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
def test_a_while_loop_in_308_survives_to_source(version):
    """3.8 pushes a block for the loop; 3.9 and 3.10 do not."""
    a = Assembler(version)
    a.op("LOAD_CONST", 0)
    a.op("STORE_NAME", 0)                     # n = 0
    a.label("test")
    a.op("LOAD_NAME", 0)
    a.op("LOAD_CONST", 1)
    a.cmp("<")
    a.jump_if_false("exit")
    a.op("LOAD_NAME", 0)
    a.op("LOAD_CONST", 2)
    a.op("INPLACE_ADD", 0)                    # n += 1
    a.op("STORE_NAME", 0)
    a.op("JUMP_ABSOLUTE", "test")
    a.label("exit")
    a.op("LOAD_CONST", 3)
    a.op("RETURN_VALUE", 0)
    code = a.code(consts=(0, 3, 1, None), names=("n",), varnames=(), argcount=0)
    fir = build_ir(code, version)
    text = emit_module(fir, version)
    assert "while n < 3:" in text, text
    assert "n += 1" in text
    assert text.count("n = 0") == 1, "the prologue must not be repeated in the body"
    assert "return" not in text, "a module has no explicit return"
    assert fir.stats()["loops"] >= 1


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
def test_a_for_loop_in_308_survives_to_source(version):
    """GET_ITER / FOR_ITER / CALL_METHOD, the 3.8 way of appending."""
    a = Assembler(version)
    a.op("BUILD_LIST", 0)
    a.op("STORE_NAME", 0)                     # out = []
    a.op("LOAD_NAME", 1)                      # range
    a.op("LOAD_CONST", 0)
    a.op("CALL_FUNCTION", 1)
    a.op("GET_ITER", 0)
    a.label("head")
    a.op("FOR_ITER", "exit")
    a.op("STORE_NAME", 2)                     # i
    a.op("LOAD_NAME", 0)                      # out
    a.op("LOAD_METHOD", 3)                    # .append
    a.op("LOAD_NAME", 2)                      # i
    a.op("LOAD_CONST", 1)
    a.op("BINARY_MULTIPLY", 0)
    a.op("CALL_METHOD", 1)
    a.op("POP_TOP", 0)
    a.op("JUMP_ABSOLUTE", "head")
    a.label("exit")
    a.op("LOAD_CONST", 2)
    a.op("RETURN_VALUE", 0)
    code = a.code(consts=(4, 2, None), names=("out", "range", "i", "append"),
                  varnames=(), argcount=0)
    fir = build_ir(code, version)
    text = emit_module(fir, version)
    assert "for i in range(4):" in text, text
    assert "out.append(i * 2)" in text


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
def test_a_legacy_except_region_is_named_not_guessed(version):
    """A protected region needs an exception table this build never sees."""
    a = Assembler(version)
    a.op("SETUP_FINALLY", "handler")
    a.op("LOAD_FAST", 0)
    a.op("RETURN_VALUE", 0)
    a.label("handler")
    a.op("LOAD_CONST", 0)
    a.op("RETURN_VALUE", 0)
    code = a.code(consts=(0,), names=())
    fir = build_ir(code, version)
    with pytest.raises(Unsupported) as raised:
        emit_module(fir, version)
    assert "SETUP_FINALLY" in str(raised.value)


# -- 3.14 / 3.15 ------------------------------------------------------------

def test_314_names_the_opcodes_it_added():
    names = set(OPNAMES[(3, 14)].values())
    for name in ("NOT_TAKEN", "LOAD_FAST_BORROW", "LOAD_SMALL_INT",
                 "LOAD_COMMON_CONSTANT", "SET_FUNCTION_ATTRIBUTE", "POP_ITER"):
        assert name in names, name


def test_315_keeps_the_jump_families():
    names = set(OPNAMES[(3, 15)].values())
    for name in ("JUMP_FORWARD", "JUMP_BACKWARD", "POP_JUMP_IF_FALSE",
                 "POP_JUMP_IF_TRUE", "FOR_ITER", "RETURN_VALUE"):
        assert name in names, name
    assert table_for((3, 15)) is OPNAMES[(3, 15)]


def test_nb_subscr_reads_as_a_subscript():
    """BINARY_OP 26 is 3.14's folded subscript read."""
    table = {name: number for number, name in OPNAMES[(3, 14)].items()}
    code = CodeObj()
    code.name = code.qualname = "f"
    code.code = bytes((table["BINARY_OP"], 26))
    decoded = list(disassemble(code, (3, 14)))
    assert decoded[0][1] == "BINARY_OP"
    assert decoded[0][3] == "[]"


def test_a_314_function_lifts_through_the_same_ir():
    """Hand-assembled 3.14 bytecode: LOAD_FAST_BORROW, NOT_TAKEN, RETURN_CONST."""
    assembler = Assembler((3, 14))
    assembler.op("LOAD_FAST_BORROW", 0)
    assembler.op("LOAD_SMALL_INT", 3)
    assembler.cmp(">")
    assembler.jump_if_false("small")
    assembler.op("NOT_TAKEN", 0)
    assembler.op("LOAD_CONST", 0)
    assembler.op("RETURN_VALUE", 0)
    assembler.label("small")
    assembler.op("LOAD_CONST", 1)
    assembler.op("RETURN_VALUE", 0)
    code = assembler.code(consts=(1, 0), names=(), varnames=("x",), argcount=1)
    text = emit_module(build_ir(code, (3, 14)), (3, 14))
    assert "if x > 3:" in text
    assert "return 1" in text and "return 0" in text


# -- the whole pipeline, from bytes -----------------------------------------

class MarshalWriter:
    """Write the subset of marshal a code object needs, in one version's layout.

    This is what makes the matrix a test of the *pipeline* rather than of the
    emitter: the bytecode goes into a real ``.pyc`` for that version and comes
    back through ``parse_pyc`` -> ``CodeObj`` -> IR -> AST -> source.
    """

    def __init__(self, version: tuple):
        self.version = version

    def i32(self, value: int) -> bytes:
        """A marshalled int: the tag is part of the object."""
        return b"i" + value.to_bytes(4, "little", signed=True)

    def header_i32(self, value: int) -> bytes:
        """A code object's own header fields are raw ints, with no tag."""
        return value.to_bytes(4, "little", signed=True)

    def text(self, value: str) -> bytes:
        raw = value.encode()
        return b"u" + len(raw).to_bytes(4, "little") + raw

    def raw(self, value: bytes) -> bytes:
        return b"s" + len(value).to_bytes(4, "little") + value

    def none(self) -> bytes:
        return b"N"

    def seq(self, items) -> bytes:
        out = b"(" + len(items).to_bytes(4, "little")
        for item in items:
            out += self.value(item)
        return out

    def value(self, item) -> bytes:
        if item is None:
            return self.none()
        if isinstance(item, CodeObj):
            return self.codeobj(item)
        if isinstance(item, bool):
            return b"T" if item else b"F"
        if isinstance(item, int):
            return self.i32(item)
        if isinstance(item, str):
            return self.text(item)
        if isinstance(item, (bytes, bytearray)):
            return self.raw(bytes(item))
        if isinstance(item, tuple):
            return self.seq(item)
        raise AssertionError(f"cannot marshal {type(item).__name__}")

    def codeobj(self, code: CodeObj) -> bytes:
        minor = self.version[1]
        out = b"c"
        out += self.header_i32(code.argcount)
        if minor >= 8:
            out += self.header_i32(code.posonly)
        out += self.header_i32(code.kwonly)
        if minor < 11:
            out += self.header_i32(len(code.varnames))   # nlocals
        out += self.header_i32(code.stacksize)
        out += self.header_i32(code.flags)
        out += self.raw(code.code)
        out += self.seq(tuple(code.consts))
        out += self.seq(tuple(code.names))
        if minor >= 11:
            out += self.seq(tuple(code.varnames))
            out += self.raw(code.kinds or b"")
        else:
            out += self.seq(tuple(code.varnames))
            out += self.seq(())                          # cellvars
            out += self.seq(())                          # freevars
        out += self.text(code.filename)
        out += self.text(code.name)
        if minor >= 11:
            out += self.text(code.qualname or code.name)
        out += self.header_i32(code.firstlineno)
        out += self.raw(code.linetable or b"")
        if minor >= 11:
            out += self.raw(code.exceptiontable or b"")
        return out


def pyc_bytes(version: tuple, module: CodeObj) -> bytes:
    """A .pyc for *version*: magic, 16-byte header, marshalled module."""
    from pydecomp.bytecode.magic import MAGIC_VERSIONS

    magic = next(number for number, ver in MAGIC_VERSIONS.items() if ver == version)
    header = magic.to_bytes(2, "little") + b"\r\n" + b"\x00" * 12
    return header + MarshalWriter(version).codeobj(module)


def module_with_one_function(version: tuple) -> CodeObj:
    """`def f(x): if x > 3: return 1; return 0` as a module code object."""
    inner = Assembler(version)
    inner.op("LOAD_FAST", 0)
    inner.op("LOAD_CONST", 0)
    inner.cmp(">")
    inner.jump_if_false("small")
    inner.op("LOAD_CONST", 1)
    inner.op("RETURN_VALUE", 0)
    inner.label("small")
    inner.op("LOAD_CONST", 2)
    inner.op("RETURN_VALUE", 0)
    function = inner.code(consts=(3, 1, 0), names=(), varnames=("x",), argcount=1)
    function.name = function.qualname = "f"

    outer = Assembler(version)
    outer.op("LOAD_CONST", 0)                        # the code object
    if version >= (3, 11):
        outer.op("LOAD_CONST", 1)                    # qualname, for flags 0x08 only
        outer.items.pop()                            # arg 0 needs no qualname
    outer.op("MAKE_FUNCTION", 0)
    outer.op("STORE_NAME", 0)
    outer.op("LOAD_CONST", 2)
    outer.op("RETURN_VALUE", 0)
    module = outer.code(consts=(function, "f", None), names=("f",),
                        varnames=(), argcount=0)
    module.name = module.qualname = "<module>"
    return module


@pytest.mark.parametrize("version", VERSIONS)
def test_every_version_goes_from_bytes_to_source(version):
    """bytes -> parse_pyc -> CodeObj -> IR -> AST -> source, for all eight."""
    from pydecomp.bytecode.magic import parse_pyc

    payload = pyc_bytes(version, module_with_one_function(version))
    parsed_version, module = parse_pyc(payload)
    assert parsed_version == version, (parsed_version, version)
    assert module is not None and module.name == "<module>"

    fir = build_ir(module, version)
    assert fir.blocks, "the module has no blocks"
    text = emit_module(fir, version)
    assert "def f(x):" in text, text
    assert "if x > 3:" in text, text
    assert "return 1" in text and "return 0" in text
    assert compile(text, "<emitted>", "exec")        # the source is real Python
