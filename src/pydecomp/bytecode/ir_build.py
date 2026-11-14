"""pydecomp - bytecode → SSA IR.

The builder is version-neutral on purpose: it reads opcode *names* from the
project's own tables, so 3.8's ``CALL_FUNCTION`` and 3.13's ``CALL`` land in the
same IR, and one emitter serves every version.

Three passes:

1. **blocks.**  Leaders are the entry, every jump target and every instruction
   after a terminator; a block runs to its terminator.
2. **values.**  Each block is interpreted with a symbolic stack and an
   environment of local versions.  Every value gets an SSA id the moment it is
   produced, and the instruction that produced it is recorded with the bytecode
   offset it came from, so an emitted line stays traceable to the file.
3. **phis.**  A block with more than one predecessor merges the environments of
   those predecessors: where two paths bring different versions of a name, a phi
   names both inputs.  That is the whole reason for SSA - a loop header that
   could otherwise see only one of the two versions gets both.

Nothing here executes the sample.  An opcode the builder does not model raises
:class:`Unsupported`, and the caller falls back to the stack engine instead of
emitting a guess.
"""
from __future__ import annotations

from ..bytecode.disassembler import disassemble
from ..bytecode.ir import BasicBlock, FunctionIR, IRInstr, SSAValue

#: opcodes that carry no meaning for the IR
_TRANSPARENT = {"RESUME", "NOP", "CACHE", "EXTENDED_ARG", "PRECALL", "PUSH_NULL",
                "TO_BOOL", "INSTRUMENTED_", "SETUP_CLEANUP", "END_FOR",
                "END_SEND", "POP_ITER", "POP_BLOCK", "SETUP_LOOP",
                "MAKE_CELL", "COPY_FREE_VARS", "NOT_TAKEN", "RETURN_GENERATOR",
                "POP_BLOCK", "SETUP_ANNOTATIONS", "GEN_START", "INSTRUMENTED_RESUME"}

#: binary operator names, by the symbol the disassembler prints
_AUGMENTED = {"+=", "-=", "*=", "/=", "//=", "%=", "**=", "<<=", ">>=", "&=",
              "|=", "^=", "@="}

#: 3.8-3.10 spell every operator as its own opcode instead of packing the
#: operator number into BINARY_OP; the IR wants the symbol either way
_LEGACY_BINOPS = {
    "BINARY_ADD": "+", "BINARY_SUBTRACT": "-", "BINARY_MULTIPLY": "*",
    "BINARY_TRUE_DIVIDE": "/", "BINARY_FLOOR_DIVIDE": "//", "BINARY_MODULO": "%",
    "BINARY_POWER": "**", "BINARY_LSHIFT": "<<", "BINARY_RSHIFT": ">>",
    "BINARY_AND": "&", "BINARY_OR": "|", "BINARY_XOR": "^",
    "BINARY_MATRIX_MULTIPLY": "@",
    "INPLACE_ADD": "+=", "INPLACE_SUBTRACT": "-=", "INPLACE_MULTIPLY": "*=",
    "INPLACE_TRUE_DIVIDE": "/=", "INPLACE_FLOOR_DIVIDE": "//=",
    "INPLACE_MODULO": "%=", "INPLACE_POWER": "**=", "INPLACE_LSHIFT": "<<=",
    "INPLACE_RSHIFT": ">>=", "INPLACE_AND": "&=", "INPLACE_OR": "|=",
    "INPLACE_XOR": "^=", "INPLACE_MATRIX_MULTIPLY": "@=",
}

#: block-stack machinery.  3.8 pushes a block for a loop, a `try`, a `finally`
#: or a `with`; the IR records the region so the emitter can name what it is
#: looking at, and refuses the ones that need an exception table it never sees.
_BLOCK_REGIONS = {"SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH", "SETUP_ASYNC_WITH",
                  "BEGIN_FINALLY", "END_FINALLY", "WITH_CLEANUP_START",
                  "WITH_CLEANUP_FINISH", "RERAISE", "POP_EXCEPT"}

#: comparison symbols the disassembler can print
_COMPARES = {"<", "<=", "==", "!=", ">", ">="}


#: block-ending instructions: nothing falls through any of these
_TERMINATORS = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE",
                "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE",
                "JUMP_BACKWARD_NO_INTERRUPT", "END_ASYNC_FOR"}


class Unsupported(Exception):
    """This opcode or shape is not modelled; the stack engine takes the file."""


def _const_hint(value) -> str:
    if isinstance(value, str):
        return "str"
    if isinstance(value, bool):
        return "int"
    if isinstance(value, int):
        return "int"
    if isinstance(value, (bytes, bytearray)):
        return "bytes"
    if hasattr(value, "code"):
        return "code_object"
    if value is None:
        return "none"
    if isinstance(value, (tuple, list, frozenset, set, dict)):
        return "container"
    return "unknown"


class Builder:
    """Turn one code object into :class:`FunctionIR`."""

    def __init__(self, code, version: tuple = (3, 13)):
        self.code = code
        self.version = tuple(version[:2])
        self.stream = list(disassemble(code, self.version))
        self.returns: dict[int, None] = {}
        self.exit_env: dict = {}

    # -- pass 1: blocks ----------------------------------------------------
    def _targets(self) -> dict[int, int]:
        """bytecode offset -> block id, for every jump target."""
        return self._labels

    def _split(self) -> list[list[tuple]]:
        rows = self.stream
        leaders_by_offset: dict[int, int] = {}
        blocks: list[list[tuple]] = []
        current: list[tuple] = []
        pending_leaders: set[int] = set()

        for index, row in enumerate(rows):
            off, opname, _arg, text = row
            if off in pending_leaders or not current:
                if current:
                    blocks.append(current)
                current = []
            current.append(row)
            if opname in _BLOCK_REGIONS or opname.startswith("SETUP_"):
                # the target is the handler (or the loop's end): both are leaders
                target = self._jump_target(off, opname, text)
                if target is not None:
                    pending_leaders.add(target)
                pending_leaders.add(rows[index + 1][0] if index + 1 < len(rows) else -1)
            if opname.startswith("JUMP") or opname.startswith("POP_JUMP") \
                    or opname == "FOR_ITER" or opname == "SEND":
                target = self._jump_target(off, opname, text)
                if target is not None:
                    pending_leaders.add(target)
                if not opname.startswith("JUMP_"):        # conditional: two ways on
                    pending_leaders.add(rows[index + 1][0]
                                        if index + 1 < len(rows) else -1)
            if opname in _TERMINATORS:
                # whatever follows a terminator starts a block
                pending_leaders.add(rows[index + 1][0] if index + 1 < len(rows) else -1)
        if current:
            blocks.append(current)
        for number, block in enumerate(blocks):
            # every offset maps to its block, so a jump into the middle of a
            # range (a loop head that starts with a fused instruction) still lands
            for row in block:
                leaders_by_offset[row[0]] = number
        self._labels = leaders_by_offset
        return blocks

    @staticmethod
    def _jump_target(off: int, opname: str, text: str) -> int | None:
        if not text.startswith("to "):
            return None
        try:
            return int(text.split("to ", 1)[1])
        except ValueError:
            return None

    # -- pass 3: merges ----------------------------------------------------
    @staticmethod
    def _merge(fir: FunctionIR, block: BasicBlock, envs: list[dict]) -> dict:
        """One environment for a block with several predecessors, phis included."""
        names: list[str] = []
        for env in envs:
            for name in env:
                if name not in names:
                    names.append(name)
        merged: dict = {}
        for name in names:
            incoming = [env.get(name) for env in envs if env.get(name) is not None]
            if not incoming:
                continue
            first = incoming[0]
            if all(value is first for value in incoming[1:]):
                merged[name] = first
                continue
            if all(getattr(value, "source", "") == "const" for value in incoming) \
                    and len({repr(value.const) for value in incoming}) == 1:
                merged[name] = first
                continue
            phi = fir.value("phi", type_hint=first.type_hint, name=name,
                            phi_inputs=tuple(value.id for value in incoming))
            merged[name] = phi
        return merged

    # -- pass 2: interpret -------------------------------------------------
    def build(self) -> FunctionIR:
        fir = FunctionIR(name=self.code.name or "<module>", version=self.version)
        blocks = self._split()
        env_of_block: dict[int, dict] = {}
        stacks: dict[int, tuple] = {}
        for number, rows in enumerate(blocks):
            fir.block(number, start=rows[0][0], end=rows[-1][0])
        # predecessors first, so a merge always has its inputs
        for number, rows in enumerate(blocks):
            for row in rows:
                off, opname, _arg, text = row
                if not opname.startswith(("JUMP", "POP_JUMP", "FOR_ITER", "SEND")):
                    continue
                target = self._jump_target(off, opname, text)
                if target is None or target not in self._labels:
                    continue
                succ = self._labels[target]
                if succ == number and not opname.startswith("FOR_ITER"):
                    continue
                self._link(fir, number, succ)
            fall = self._fall_through(number, blocks)
            if fall is not None:
                self._link(fir, number, fall)

        reachable = set()
        pending = [fir.entry]
        while pending:
            bid = pending.pop()
            if bid in reachable:
                continue
            reachable.add(bid)
            pending.extend(fir.blocks[bid].successors)

        # Walk reachable normal-flow blocks; exception-table-only cleanup blocks
        # are not represented as ordinary CFG edges by the bytecode reader.
        for number, rows in enumerate(blocks):
            if number not in reachable:
                continue
            block = fir.blocks[number]
            preds = [env_of_block[p] for p in block.predecessors if p in env_of_block]
            if number == 0 or not preds:
                env: dict = {}
            elif len(preds) == 1:
                env = dict(preds[0])
            else:
                env = self._merge(fir, block, preds)
            stack = self._entry_stack(block, stacks)
            env, stack = self._walk(fir, block, rows, env, stack)
            env_of_block[number] = env
            stacks[number] = stack
            fir.exits = env
        return fir

    def _varname(self, index: int) -> str:
        names = self.code.varnames
        if index < len(names):
            return names[index]
        return f"_local{index}"

    def _link(self, fir: FunctionIR, src: int, dst: int) -> None:
        block, other = fir.blocks[src], fir.blocks[dst]
        if dst not in block.successors:
            block.successors.append(dst)
        if src not in other.predecessors:
            other.predecessors.append(src)

    def _fall_through(self, number: int, blocks: list[list[tuple]]) -> int | None:
        last = blocks[number][-1][1]
        if last in _TERMINATORS:
            return None
        return number + 1 if number + 1 < len(blocks) else None

    # -- the interpreter ---------------------------------------------------
    @staticmethod
    def _entry_stack(block: BasicBlock, stacks: dict) -> list:
        """The stack a block starts with: whatever its predecessors pushed.

        Carrying the stack across block boundaries is what lets a loop body begin
        with the iterator a FOR_ITER pushed, and it is also why a body entered
        two ways with mismatched stack shapes is refused.
        """
        shapes = [stacks[p] for p in block.predecessors if p in stacks]
        if not shapes:
            return []
        first = shapes[0]
        for other in shapes[1:]:
            if len(other) != len(first):
                raise Unsupported("join with mismatched stacks")
        return list(first)

    def _walk(self, fir: FunctionIR, block: BasicBlock, rows: list[tuple],
              env: dict, stack: list | None = None) -> tuple:
        stack: list[SSAValue] = list(stack or [])
        names = self.code.names
        consts = self.code.consts

        def push(value: SSAValue) -> SSAValue:
            stack.append(value)
            return value

        def pop() -> SSAValue:
            if not stack:
                raise Unsupported("stack underflow")
            return stack.pop()

        for row in rows:
            off, opname, arg, text = row
            if opname in _TRANSPARENT:
                continue
            if opname in ("LOAD_CONST", "RETURN_CONST"):
                value = consts[arg] if arg < len(consts) else None
                if opname == "RETURN_CONST":
                    node = fir.value("const", type_hint=_const_hint(value), const=value)
                    block.add(IRInstr("RETURN", (node,), None, off))
                    continue
                push(fir.value("const", type_hint=_const_hint(value), const=value))
            elif opname in ("LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_FAST_BORROW",
                            "LOAD_FAST_AND_CLEAR", "LOAD_DEREF", "LOAD_CLASSDEREF"):
                # a load is its own SSA value: it reads whatever the local holds
                # *at this point*, which is what lets a loop header see the value
                # from the back edge as well as the one from the entry
                push(fir.value("local", name=text))
            elif opname == "LOAD_ASSERTION_ERROR":
                push(fir.value("arg", name="AssertionError"))
            elif opname in ("LOAD_NAME", "LOAD_GLOBAL", "LOAD_FROM_DICT_OR_GLOBALS"):
                # a global read is never the last stored constant: the name is
                # looked up again at run time, so the IR keeps the name
                push(fir.value("arg", name=text.lstrip(".")))
            elif opname in ("STORE_FAST", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"):
                value = pop()
                if value.source == "unknown":
                    # the value a FOR_ITER pushed becomes a real local here
                    value.source = "local"
                    value.name = text
                env[text] = value
                if opname == "STORE_GLOBAL":
                    block.add(IRInstr("GLOBAL", (text,), None, off))
                block.add(IRInstr("STORE", (value, text), None, off))
            elif opname in ("DELETE_FAST", "DELETE_NAME", "DELETE_GLOBAL", "DELETE_DEREF"):
                if opname == "DELETE_GLOBAL":
                    block.add(IRInstr("GLOBAL", (text,), None, off))
                block.add(IRInstr("DELETE", (text, opname), None, off))
                env.pop(text, None)
            elif opname == "GET_ITER":
                push(fir.value("expr", expr=("iter", pop())))
            elif opname == "FOR_ITER":
                iterator = pop()
                block.add(IRInstr("FOR_ITER", (iterator,), None, off))
                push(fir.value("unknown"))
            elif opname in ("BUILD_CONST_KEY_MAP", "BUILD_MAP"):
                if opname == "BUILD_CONST_KEY_MAP":
                    keys = pop()
                    pairs = []
                    for _ in range(arg):
                        pairs.append((None, pop()))
                    pairs.reverse()
                    if keys.source != "const" or not isinstance(keys.const, tuple):
                        raise Unsupported("computed keywords")
                    pairs = [(key, value) for key, (_key, value)
                             in zip(keys.const, pairs)]
                else:
                    pairs = []
                    for _ in range(arg):
                        value, key = pop(), pop()
                        pairs.append((key, value))
                    pairs.reverse()
                push(fir.value("expr", type_hint="container",
                               expr=("dict", tuple(pairs))))
            elif opname == "IMPORT_FROM":
                module = pop()
                push(fir.value("expr", type_hint="unknown",
                               expr=("import_from", module, text)))
            elif opname == "IMPORT_NAME":
                fromlist, level = pop(), pop()
                push(fir.value("expr", type_hint="unknown",
                               expr=("import", text, fromlist, level)))
            elif opname == "POP_TOP":
                if stack:
                    block.add(IRInstr("POP", (pop(),), None, off))
                else:
                    # END_FOR has already taken the exhausted iterator
                    block.add(IRInstr("POP", (None,), None, off))
            elif opname == "LOAD_SMALL_INT":
                # 3.14 pushes small integers without a constant-table entry
                push(fir.value("const", type_hint="int", const=arg))
            elif opname in _LEGACY_BINOPS:
                symbol = _LEGACY_BINOPS[opname]
                right, left = pop(), pop()
                if symbol.endswith("="):
                    push(fir.value("expr", expr=("inplace", symbol[:-1], left, right)))
                    continue
                value = fir.value("expr", expr=("binop", symbol, left, right))
                block.add(IRInstr("BINOP", (left, right), value, off))
                push(value)
            elif opname == "BINARY_OP":
                right, left = pop(), pop()
                sym = text
                if sym in _AUGMENTED:
                    # `x += 1` arrives as LOAD_FAST/…/BINARY_OP += /STORE_FAST
                    inplace = fir.value("expr", expr=("inplace", sym[:-1], left, right))
                    push(inplace)
                    continue
                value = fir.value("expr", expr=("binop", sym, left, right))
                block.add(IRInstr("BINOP", (left, right), value, off))
                push(value)
            elif opname == "COMPARE_OP":
                right, left = pop(), pop()
                if text not in _COMPARES:
                    raise Unsupported(f"compare {text}")
                value = fir.value("expr", type_hint="int",
                                  expr=("compare", text, left, right))
                block.add(IRInstr("COMPARE", (left, right), value, off))
                push(value)
            elif opname == "IS_OP":
                right, left = pop(), pop()
                value = fir.value("expr", type_hint="int",
                                  expr=("compare", text, left, right))
                push(value)
            elif opname == "CONTAINS_OP":
                right, left = pop(), pop()
                value = fir.value("expr", type_hint="int",
                                  expr=("compare", text, left, right))
                push(value)
            elif opname == "UNARY_NEGATIVE":
                node = pop()
                push(fir.value("expr", type_hint="int",
                               expr=("unary", "-", node)))
            elif opname in ("UNARY_NOT", "UNARY_INVERT", "UNARY_POSITIVE"):
                node = pop()
                symbol = {"UNARY_NOT": "not", "UNARY_INVERT": "~",
                          "UNARY_POSITIVE": "+"}[opname]
                push(fir.value("expr", expr=("unary", symbol, node)))
            elif opname == "LOAD_METHOD":
                # 3.8-3.10 push the bound method and its receiver as two values;
                # the IR keeps them as one reference so the call reads as a call
                owner = pop()
                push(fir.value("expr", expr=("attr", owner, text)))
            elif opname in ("LOAD_ATTR", "LOAD_SUPER_ATTR"):
                owner = pop()
                value = fir.value("expr", expr=("attr", owner, text.lstrip(".")))
                block.add(IRInstr("LOAD_ATTR", (owner,), value, off))
                push(value)
            elif opname in ("STORE_ATTR", "STORE_SUBSCR"):
                if opname == "STORE_ATTR":
                    owner, value = pop(), pop()
                    block.add(IRInstr("STORE_ATTR", (owner, value, text), None, off))
                else:
                    index, owner, value = pop(), pop(), pop()
                    block.add(IRInstr("STORE_SUBSCR", (owner, index, value), None, off))
            elif opname == "DELETE_SUBSCR":
                index, owner = pop(), pop()
                block.add(IRInstr("DELETE_SUBSCR", (owner, index), None, off))
            elif opname == "BINARY_SUBSCR":
                index, owner = pop(), pop()
                value = fir.value("expr", expr=("subscr", owner, index))
                block.add(IRInstr("BINARY_SUBSCR", (owner, index), value, off))
                push(value)
            elif opname in ("BUILD_TUPLE", "BUILD_LIST", "BUILD_SET", "BUILD_STRING"):
                items = tuple(pop() for _ in range(arg))[::-1]
                kind = {"BUILD_TUPLE": "tuple", "BUILD_LIST": "list",
                        "BUILD_SET": "set", "BUILD_STRING": "str"}[opname]
                push(fir.value("expr", expr=("build", kind, items)))
            elif opname == "BUILD_SLICE":
                items = tuple(pop() for _ in range(arg))[::-1]
                push(fir.value("expr", expr=("slice", items)))
            elif opname in ("SET_UPDATE", "LIST_EXTEND", "LIST_APPEND", "SET_ADD"):
                item = pop()
                if opname in ("LIST_APPEND", "SET_ADD"):
                    # in-place append inside an inlined comprehension
                    target = stack[-arg] if 0 < arg <= len(stack) else None
                    if target is None:
                        raise Unsupported(f"{opname} without a target")
                    push(fir.value("expr", expr=("append", target, item)))
                    continue
                target = stack[-arg] if arg and len(stack) >= arg else None
                kind = "set" if opname == "SET_UPDATE" else "list"
                if target is not None and isinstance(target.expr, tuple) \
                        and target.expr[0] == "build" and target.expr[1] == kind:
                    stack.pop(-1)
                    additions = (tuple(fir.value("const", type_hint=_const_hint(value),
                                                   const=value)
                                       for value in item.const)
                                 if opname == "SET_UPDATE" and item.source == "const"
                                 and isinstance(item.const, frozenset) else (item,))
                    push(fir.value("expr", expr=("build", kind,
                                                 target.expr[2] + additions)))
                else:
                    raise Unsupported(f"{opname} without a literal")
            elif opname == "LIST_EXTEND_HANDLED":
                items = pop()
                target = stack[-arg] if arg and len(stack) >= arg else None
                if target is not None and isinstance(target.expr, tuple) \
                        and target.expr[0] == "build":
                    push(fir.value("expr", expr=("build", "list",
                                                 target.expr[2] + (items,))))
                    stack.pop(-1)                       # replace, not append
                else:
                    raise Unsupported("LIST_EXTEND without a literal list")
            elif opname in ("CALL_FUNCTION", "CALL_METHOD", "CALL_FUNCTION_KW",
                            "CALL_FUNCTION_EX") and self.version < (3, 11):
                keywords: list = []
                if opname == "CALL_FUNCTION_EX":
                    mapping = pop() if arg & 1 else None
                    args_value = pop()
                    callable_ = pop()
                    value = fir.value("call_result",
                                      expr=("call_star", callable_, args_value, mapping))
                    block.add(IRInstr("CALL", (callable_, args_value), value, off))
                    push(value)
                    continue
                kwnames = None
                if opname == "CALL_FUNCTION_KW":
                    key_value = pop()
                    if key_value.source != "const" or not isinstance(key_value.const, tuple):
                        raise Unsupported("computed keyword names")
                    kwnames = key_value.const
                    count = arg
                else:
                    count = arg
                args: list = [pop() for _ in range(count)]
                args.reverse()
                callable_ = pop()
                if opname == "CALL_METHOD":
                    # LOAD_METHOD pushed (method, self); the self is the first
                    # argument of the call, not a separate value
                    pass
                if kwnames:
                    split = len(args) - len(kwnames)
                    keywords = list(zip(kwnames, args[split:]))
                    args = args[:split]
                value = fir.value("call_result",
                                  expr=("call", callable_, tuple(args), tuple(keywords)))
                block.add(IRInstr("CALL", tuple([callable_] + args), value, off))
                push(value)
            elif opname in ("CALL", "CALL_FUNCTION", "CALL_FUNCTION_KW",
                            "CALL_METHOD", "CALL_KW", "CALL_FUNCTION_EX"):
                count = arg
                kwnames = ()
                if opname == "CALL_KW":
                    names_value = pop()
                    if names_value.source != "const" or not isinstance(names_value.const, tuple) \
                            or any(not isinstance(name, str) for name in names_value.const):
                        raise Unsupported("computed keyword names")
                    kwnames = names_value.const
                kwargs = []
                args: list[SSAValue] = []
                for _ in range(count):
                    args.append(pop())
                args.reverse()
                callable_ = pop()
                if kwnames:
                    split = len(args) - len(kwnames)
                    if split < 0:
                        raise Unsupported("keyword count exceeds call arguments")
                    kwargs = list(zip(kwnames, args[split:]))
                    args = args[:split]
                # In 3.13+ a decorator application has no explicit argument
                # count: the function object is the call's implicit stack arg,
                # with the decorator callable immediately below it.
                if count == 0 and isinstance(callable_.expr, tuple) \
                        and callable_.expr[0] == "funcdef" and stack:
                    args = [callable_]
                    callable_ = pop()
                elif count == 0 and stack and stack[-1].source == "arg" \
                        and stack[-1].name == "AssertionError":
                    # 3.11+ lowers `assert test, message` to a special exception
                    # load followed by CALL 0; the message is the implicit arg.
                    args = [callable_]
                    callable_ = pop()
                if stack and stack[-1].source == "arg" and stack[-1].name == "__null__":
                    stack.pop()
                value = fir.value("call_result",
                                  expr=("call", callable_, tuple(args), tuple(kwargs)))
                block.add(IRInstr("CALL", tuple([callable_] + args), value, off))
                push(value)
            elif opname == "MAKE_FUNCTION":
                flags = arg & 0x0F if arg else 0
                modern = self.version >= (3, 11)
                qualname = pop() if modern and flags & 0x08 else None
                if not modern:
                    flags = 0                    # 0x08 means closure here, not name
                code_value = pop()
                if qualname is not None and qualname.source != "const":
                    raise Unsupported("computed function name")
                if not (code_value.source == "const"
                        and hasattr(code_value.const, "code")):
                    raise Unsupported("MAKE_FUNCTION without a code constant")
                if flags & ~0x08:
                    # closures, defaults and annotations each add stack work; the
                    # stack engine models them, so hand the file back
                    raise Unsupported("MAKE_FUNCTION with flags")
                push(fir.value("expr", type_hint="code_object",
                               expr=("funcdef", code_value.const,
                                     qualname.const if qualname is not None else None,
                                     None, None, ())))
            elif opname == "SET_FUNCTION_ATTRIBUTE":
                function, attribute = pop(), pop()
                if not (isinstance(function.expr, tuple)
                        and function.expr[0] == "funcdef"):
                    raise Unsupported("function attribute on a computed value")
                _, nested, qualname, defaults, kwdefaults, decorators = function.expr
                if arg == 1:
                    defaults = attribute
                elif arg == 2:
                    kwdefaults = attribute
                else:
                    raise Unsupported(f"function attribute flag {arg}")
                push(fir.value("expr", type_hint="code_object",
                               expr=("funcdef", nested, qualname,
                                     defaults, kwdefaults, decorators)))
            elif opname == "KW_NAMES":
                continue
            elif opname in ("FORMAT_SIMPLE", "FORMAT_VALUE"):
                push(fir.value("expr", type_hint="str", expr=("format", pop(), None)))
            elif opname == "FORMAT_WITH_SPEC":
                spec, value = pop(), pop()
                push(fir.value("expr", type_hint="str", expr=("format", value, spec)))
            elif opname == "CONVERT_VALUE":
                push(fir.value("expr", type_hint="str",
                               expr=("convert", pop(), arg)))
            elif opname == "UNPACK_SEQUENCE":
                node = pop()
                pieces = [fir.value("expr", expr=("item", node, index))
                          for index in range(arg)]
                for piece in reversed(pieces):
                    push(piece)
            elif opname in ("JUMP_FORWARD", "JUMP_ABSOLUTE", "JUMP_BACKWARD",
                            "JUMP_BACKWARD_NO_INTERRUPT"):
                block.add(IRInstr("JUMP", (), None, off))
            elif opname in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                            "POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE",
                            "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE",
                            "POP_JUMP_FORWARD_IF_NONE", "POP_JUMP_FORWARD_IF_NOT_NONE",
                            "POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_TRUE",
                            "POP_JUMP_BACKWARD_IF_NONE", "POP_JUMP_BACKWARD_IF_NOT_NONE"):
                cond = pop()
                # the *kind* of test, not a boolean: the emitter needs to know
                # whether the jump is taken on false, on true, or on `is None`
                if "IF_NOT_NONE" in opname:
                    kind = "if_not_none"
                elif "IF_NONE" in opname:
                    kind = "if_none"
                elif "IF_FALSE" in opname:
                    kind = "if_false"
                elif "IF_TRUE" in opname:
                    kind = "if_true"
                else:
                    raise Unsupported(f"jump {opname}")
                block.add(IRInstr("BRANCH", (cond, kind), None, off))
            elif opname == "RETURN_VALUE":
                node = pop()
                block.add(IRInstr("RETURN", (node,), None, off))
            elif opname == "RAISE_VARARGS":
                if arg not in (0, 1, 2):
                    raise Unsupported(f"raise arity {arg}")
                cause = pop() if arg == 2 else None
                exception = pop() if arg else None
                block.add(IRInstr("RAISE", (exception, cause), None, off))
            elif opname in ("LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"):
                first = arg >> 4
                second = arg & 15
                names = self.code.varnames
                push(fir.value("local", name=self._varname(first)))
                push(fir.value("local", name=self._varname(second)))
            elif opname == "STORE_FAST_LOAD_FAST":
                first = arg >> 4
                second = arg & 15
                value = pop()
                env[self._varname(first)] = value
                block.add(IRInstr("STORE", (value, self._varname(first)), None, off))
                push(fir.value("local", name=self._varname(second)))
            elif opname == "STORE_FAST_STORE_FAST":
                first = arg >> 4
                second = arg & 15
                right, left = pop(), pop()
                env[self._varname(second)] = right
                env[self._varname(first)] = left
                block.add(IRInstr("STORE", (right, self._varname(second)), None, off))
                block.add(IRInstr("STORE", (left, self._varname(first)), None, off))
            elif opname in ("ROT_TWO", "ROT_THREE", "ROT_FOUR", "ROT_N",
                            "DUP_TOP", "DUP_TOP_TWO"):
                if opname == "DUP_TOP":
                    push(stack[-1])
                elif opname == "DUP_TOP_TWO":
                    push(stack[-2])
                    push(stack[-1])
                elif opname == "ROT_N":
                    if arg > len(stack):
                        raise Unsupported("ROT_N past the stack")
                    stack[-arg:] = stack[-1:] + stack[-arg:-1]
                else:
                    depth = {"ROT_TWO": 2, "ROT_THREE": 3, "ROT_FOUR": 4}[opname]
                    if depth > len(stack):
                        raise Unsupported(f"{opname} past the stack")
                    stack[-depth:] = stack[-1:] + stack[-depth:-1]
            elif opname in ("COPY", "SWAP"):
                if opname == "COPY":
                    if arg > len(stack):
                        raise Unsupported("COPY past the stack")
                    push(stack[-arg])
                else:
                    if arg > len(stack):
                        raise Unsupported(
                            f"SWAP at {off} needs depth {arg}, stack has {len(stack)} value(s)")
                    stack[-1], stack[-arg] = stack[-arg], stack[-1]
                    block.add(IRInstr("SWAP", (arg,), None, off))
            elif opname in _BLOCK_REGIONS:
                block.add(IRInstr("SETUP", (opname,), None, off))
            else:
                raise Unsupported(opname)
        return env, tuple(stack)


def build_ir(code, version: tuple = (3, 13)) -> FunctionIR:
    """Build the SSA form of one code object."""
    return Builder(code, version).build()
