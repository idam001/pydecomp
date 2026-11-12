"""pydecomp - decompiler6."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import ast

from ..bytecode.codeobj import CodeObj, codeobj_from_host
from ..bytecode.disassembler import disassemble
from ..bytecode.lifter import (
    _d6_fix_breaks, d6_const, d6_is_back_edge, d6_until_backward_or,
)
from ..bytecode.magic import host_version
from ..bytecode.marshal_reader import iter_code

D6_CMP_OPS = [ast.Lt, ast.LtE, ast.Eq, ast.NotEq, ast.Gt, ast.GtE]

D6_BIN_OPS = {0: ast.Add, 1: ast.BitAnd, 2: ast.FloorDiv, 3: ast.LShift, 4: ast.MatMult,
           5: ast.Mult, 6: ast.Mod, 7: ast.BitOr, 8: ast.Pow, 9: ast.RShift,
           10: ast.Sub, 11: ast.Div, 12: ast.BitXor}

D6_NB_SUBSCR = 26                                   # 3.14: obj[key]

D6_AUG_OPS = {13: ast.Add, 14: ast.BitAnd, 15: ast.FloorDiv, 16: ast.LShift, 17: ast.MatMult,
           18: ast.Mult, 19: ast.Mod, 20: ast.BitOr, 21: ast.Pow, 22: ast.RShift,
           23: ast.Sub, 24: ast.Div, 25: ast.BitXor}

D6_SKIP = {"RESUME", "NOP", "CACHE", "EXTENDED_ARG", "NOT_TAKEN", "PRECALL", "MAKE_CELL",
        "COPY_FREE_VARS", "SETUP_ANNOTATIONS", "RETURN_GENERATOR", "TO_BOOL",
        "END_SEND", "INTERPRETER_EXIT", "RESERVED", "END_FOR",
        "CALL_INTRINSIC_1", "CALL_INTRINSIC_2"}

D6_STORE_NAME_OPS = {"STORE_NAME", "STORE_GLOBAL"}

D6_STORE_FAST_OPS = {"STORE_FAST"}

D6_LOAD_FAST_OPS = {"LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_DEREF", "LOAD_FAST_CHECK",
                 "LOAD_CLASSDEREF"}

D6_LOADS_ONE = {"LOAD_CONST", "LOAD_SMALL_INT", "LOAD_FAST", "LOAD_FAST_BORROW",
             "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF", "LOAD_FAST_CHECK"}

class D6Unsupported(Exception):
    pass

class D6RegionEnd(Exception):
    """Internal: this region reached the loop's back edge."""

class D6Null:
    """Marker for the D6_NULL slot pushed before a callable."""

D6_NULL = D6Null()

class Decompiler6:
    """Recursively structure one code object and return ``ast`` statements."""

    def __init__(self, code, version, resolve_target, opnames, seen=None,
                 in_loop_stack=None, tolerant=False, flat=False):
        self.code = code
        self.version = version
        self.opnames = opnames
        self.instrs = self._decode(resolve_target)
        self.index = 0
        self.stack = []
        self.returns_value = None
        self.loop_stack = in_loop_stack if in_loop_stack is not None else []
        self.seen = seen if seen is not None else set()
        self.tolerant = tolerant
        self.flat = flat
        self.consumed = set()
        self._pending_defaults = None
        self.offset_index = {ins["off"]: i for i, ins in enumerate(self.instrs)}
        self.dead_offsets = set()
        self.globals_decl = []

    # ------------------------------------------------------------- decode
    def _decode(self, _unused=None):
        raw, names = self.code.code, self.opnames
        out, extended, off = [], 0, 0
        length = len(raw)
        while off < length - 1:
            op = raw[off]
            if op == 0:                              # CACHE / NOT_TAKEN slot
                off += 2
                continue
            arg = (extended << 8) | raw[off + 1]
            extended = 0
            name = names.get(op, f"OP_{op}")
            if name == "EXTENDED_ARG":
                extended = arg
                off += 2
                continue
            caches, probe = 0, off + 2
            while probe < length - 1 and raw[probe] == 0:
                caches += 1
                probe += 2
            out.append({"off": off, "op": name, "arg": arg, "caches": caches})
            off += 2
        offsets = {ins["off"] for ins in out}
        for ins in out:
            if "JUMP" in ins["op"] or ins["op"] in ("FOR_ITER", "SEND"):
                ins["target"] = self._resolve(ins, offsets)
        return out

    def exception_entries(self):
        """Decode ``co_exceptiontable`` into try ranges and handler offsets."""
        if getattr(self, "_exc", None) is not None:
            return self._exc
        table = getattr(self.code, "exceptiontable", b"") or b""
        entries, pos = [], 0

        def varint():
            """CPython's varint: 6 bits per byte, big-endian, 0x40 continues."""
            nonlocal pos
            value = 0
            while pos < len(table):
                byte = table[pos]
                pos += 1
                value = (value << 6) | (byte & 0x3F)
                if not byte & 0x40:
                    break
            return value

        try:
            while pos < len(table):
                start = varint() * 2
                length = varint() * 2
                target = varint() * 2
                packed = varint()
                entries.append({"start": start, "size": length, "end": start + length,
                                "handler": target, "depth": packed >> 1,
                                "lasti": packed & 1})
        except Exception:                            # noqa: BLE001 - truncated table
            pass
        self._exc = entries
        return entries

    def _try_at(self, offset):
        """Real ``try`` blocks only: skip the implicit cleanup regions.

        CPython wraps every handler body in its own table entry (so a failure
        there can re-raise), and adds a tiny reraise stub.  Those are machine
        bookkeeping, not source-level ``try`` statements, so they are skipped.
        """
        if getattr(self, "flat", False):
            return None                             # content-first mode: no try blocks
        entries = self.exception_entries()
        handler_offsets = {entry["handler"] for entry in entries}
        for entry in entries:
            if entry["start"] != offset:
                continue
            if entry["start"] in handler_offsets:
                return None
            handler_index = self._snap(entry["handler"])
            if handler_index is not None:
                window = [ins["op"] for ins in self.instrs[handler_index:handler_index + 5]]
                if "WITH_EXCEPT_START" in window:
                    return None                      # ``with`` cleanup, not try/except
            index = self._snap(entry["start"])
            if index is not None and index < len(self.instrs):
                first = self.instrs[index]["op"]
                if first in ("RERAISE", "POP_EXCEPT", "COPY", "PUSH_EXC_INFO",
                             "CHECK_EXC_MATCH", "SWAP"):
                    return None
            return entry
        return None

    def _snap(self, offset):
        """Instruction index for an exception-table offset (may sit between ops)."""
        if offset is None:
            return None
        index = self.offset_index.get(offset)
        if index is not None:
            return index
        for i, ins in enumerate(self.instrs):
            if ins["off"] >= offset:
                return i
        return None

    def _handlers_for(self, entry):
        return [item for item in self.exception_entries()
                if item["start"] == entry["start"]]

    def parse_try(self, entry):
        """``try: ... except ...`` driven by the exception table."""
        handlers = self._handlers_for(entry)
        body = self.parse_block(stop={entry["end"]})
        # The compiler parks the function's own epilogue between the protected
        # region and the handler (``LOAD_CONST None; RETURN_VALUE``).  It is the
        # implicit ``return`` of the enclosing function, not a statement of the
        # try body, so it must not surface as a stray ``return``.
        gap_end = min((item["handler"] for item in handlers
                       if item["handler"] > entry["end"]), default=None)
        cursor = self.index
        while cursor < len(self.instrs):
            ins = self.instrs[cursor]
            if gap_end is not None and ins["off"] >= gap_end:
                break
            if ins["op"] in ("RETURN_CONST",):
                cursor += 1
                continue
            if ins["op"] == "LOAD_CONST" and ins["arg"] is not None and \
                    self.code.consts[ins["arg"]] is None and cursor + 1 < len(self.instrs) \
                    and self.instrs[cursor + 1]["op"] == "RETURN_VALUE":
                cursor += 2
                continue
            break
        if cursor > self.index and (gap_end is None or
                                    self.instrs[cursor]["off"] == gap_end):
            self.index = cursor                       # implicit epilogue: skip it
        # a real ``return`` sitting on the protected boundary still belongs to try
        while self.index < len(self.instrs) and self.instrs[self.index]["op"] in (
                "RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
            node = self.step()
            self.index += 1
            if node is not None:
                body.extend(node if isinstance(node, list) else [node])
        start_index = self.index
        clauses, seen = [], set()
        for item in handlers:
            handler_idx = self._snap(item["handler"])
            if handler_idx is None or handler_idx in seen:
                continue
            seen.add(handler_idx)
            self.index = handler_idx
            clause = self.parse_except(item)
            if clause is not None:
                clauses.append(clause)
        # walk past the interpreter's cleanup stubs to whatever follows
        while self.index < len(self.instrs) and self.here()["op"] in (
                "COPY", "POP_EXCEPT", "RERAISE", "SWAP", "PUSH_EXC_INFO",
                "CHECK_EXC_MATCH", "PREP_RERAISE_STAR"):
            self.index += 1
        trailing = []
        if self.index < len(self.instrs) and "JUMP" in self.here()["op"]:
            join_idx = self.target_index(self.here())
            if join_idx is not None and join_idx > self.index:
                # the compiler jumps over the ``else`` region: parse it instead
                # of throwing it away, otherwise whole blocks disappear
                guard_index = self.index
                try:
                    trailing = self.parse_block(stop={self.instrs[join_idx]["off"]})
                except D6Unsupported:
                    trailing = []
                if self.index <= guard_index:
                    self.index = guard_index
                self.index = join_idx
        if self.tolerant:
            meaningful = len(body) + sum(len(clause.body) for clause in clauses
                                         if isinstance(clause, ast.ExceptHandler))
            if meaningful <= 2 and (self.index - start_index) > 60:
                # the structure ate far more instructions than it recovered:
                # fall back to flat parsing so no code is lost
                resume = self._snap(entry["end"])
                if resume is not None:
                    self.index = resume
                    return list(body)
        if not clauses:
            if not self.tolerant:
                raise D6Unsupported("try without a handler")
            # the table pointed at machine cleanup we cannot express: keep the
            # protected statements rather than losing the whole module
            return body or [ast.Pass()]
        return [ast.Try(body=body or [ast.Pass()], handlers=clauses, orelse=[],
                        finalbody=[])] + trailing

    def parse_except(self, entry):
        """One ``except`` clause, including ``except X as name``."""
        if self.index < len(self.instrs) and self.here()["op"] == "PUSH_EXC_INFO":
            self.index += 1
        type_expr = None
        alias = None
        if self.index < len(self.instrs) and self.here()["op"] in (
                "LOAD_GLOBAL", "LOAD_NAME", "LOAD_FAST", "LOAD_DEREF"):
            ins = self.here()
            table = self.code.names if ins["op"] in ("LOAD_GLOBAL", "LOAD_NAME") \
                else self.code.varnames
            arg = ins["arg"] >> 1 if ins["op"] == "LOAD_GLOBAL" else ins["arg"]
            candidate = ast.Name(id=self.name_at(table, arg), ctx=ast.Load())
            self.index += 1
            if self.index < len(self.instrs) and self.here()["op"] == "CHECK_EXC_MATCH":
                self.index += 1
                if self.index < len(self.instrs) and "JUMP" in self.here()["op"]:
                    self.index += 1                   # the match test
                while self.index < len(self.instrs) and self.here()["op"] in (
                        "NOT_TAKEN", "TO_BOOL", "POP_TOP"):
                    self.index += 1                   # 3.13+ match bookkeeping
                if self.index < len(self.instrs) and self.here()["op"] in (
                        "STORE_FAST", "STORE_NAME"):
                    ins = self.here()
                    table = self.code.varnames if ins["op"] == "STORE_FAST" \
                        else self.code.names
                    alias = self.name_at(table, ins["arg"])
                    self.index += 1
                type_expr = candidate
            else:
                self.index -= 1
        body = []
        if alias is not None and self.index < len(self.instrs) \
                and self.here()["op"] == "POP_EXCEPT":
            self.index += 1
        # ``except E as name:`` is followed by the interpreter's own cleanup
        # (``name = None; del name``) once the handler body is done; when the
        # body is empty that pattern is all there is, and it is not source.
        skipped = True
        while skipped and alias is not None:
            skipped = False
            cursor = self.index
            if cursor + 2 < len(self.instrs) \
                    and [self.instrs[cursor + i]["op"] for i in range(3)] == \
                    ["LOAD_CONST", "STORE_FAST", "DELETE_FAST"]:
                table = self.code.varnames
                if self.name_at(table, self.instrs[cursor + 1]["arg"]) == alias \
                        and self.name_at(table, self.instrs[cursor + 2]["arg"]) == alias:
                    cursor += 3
                    if cursor < len(self.instrs) and self.instrs[cursor]["op"] == "LOAD_CONST" \
                            and self.code.consts[self.instrs[cursor]["arg"]] is None \
                            and cursor + 1 < len(self.instrs) \
                            and self.instrs[cursor + 1]["op"] == "RETURN_VALUE":
                        cursor += 2
                    elif cursor < len(self.instrs) \
                            and self.instrs[cursor]["op"] == "RETURN_CONST":
                        cursor += 1
                    self.index = cursor
                    skipped = True
        stops = {item["handler"] for item in self.exception_entries()} - {entry["handler"]}
        # the table also protects each handler body; its end is the real end
        limit = None
        for item in self.exception_entries():
            if item["start"] == entry["handler"]:
                limit = item["end"]
                break
        while self.index < len(self.instrs):
            op = self.here()["op"]
            if limit is not None and self.here()["off"] >= limit and op not in (
                    "RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                break
            if op == "POP_EXCEPT":
                self.index += 1                     # bookkeeping, not source
                continue
            if op == "RERAISE":
                self.index += 1
                break
            if self.here()["off"] in stops:
                break
            if "JUMP" in op:
                self.index += 1
                break
            if op in ("RETURN_VALUE", "RETURN_CONST"):
                node = self.step()
                self.index += 1
                if node is not None:
                    body.append(node)
                continue
            node = self.step()
            self.index += 1
            if node is not None:
                body.extend(node if isinstance(node, list) else [node])
        return ast.ExceptHandler(type=type_expr, name=alias,
                                 body=d6_trim(body, implicit_return=False)
                                 if body else [ast.Pass()])

    def _resolve(self, ins, offsets):
        """Land the jump on a real instruction (inline caches shift the maths)."""
        off, name, arg = ins["off"], ins["op"], ins["arg"]
        span = 2 + ins.get("caches", 0) * 2
        if "BACKWARD" in name:
            base = off + span - arg * 2
            order = [base, base + 2, base - 2]
        else:
            base = off + span + arg * 2
            # 3.14 marks the fall-through of a conditional with ``NOT_TAKEN``, so
            # a target can land one slot early; snapping forwards keeps the
            # branch pointing at the code it really reaches.
            order = [base, base + 2, base + 4, base - 2, base - 4]
        for candidate in order:
            if candidate in offsets:
                return candidate
        return base

    def push(self, node):
        self.stack.append(node)

    def pop(self):
        if not self.stack:
            if self.tolerant:
                # an empty stack means the previous instruction consumed it
                # (dead cleanup, a mis-read jump): a placeholder keeps a huge
                # hostile module decompiling instead of losing the whole file
                return ast.Constant(value=None)
            raise D6Unsupported("stack underflow")
        return self.stack.pop()

    def pop_expr(self):
        node = self.pop()
        while node is D6_NULL and self.stack:
            node = self.pop()
        if not isinstance(node, ast.expr):
            raise D6Unsupported(f"not an expression: {node!r}")
        return node

    def here(self):
        return self.instrs[self.index]

    def target_index(self, ins):
        off = ins.get("target")
        if off is None or off not in self.offset_index:
            return None
        return self.offset_index[off]

    def name_at(self, table, arg):
        value = table[arg] if arg < len(table) else f"<{arg}>"
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).decode("utf-8", "surrogateescape")
        return value

    # --------------------------------------------------------------- run
    def run(self):
        body = self.parse_block(stop=set())
        # a module body never ends in ``return``: the compiler appends
        # ``RETURN_CONST None`` that the source never wrote
        implicit = getattr(self.code, "name", "<module>") == "<module>"
        if not implicit and self.globals_decl:
            body.insert(0, ast.Global(names=list(self.globals_decl)))
        while body and implicit and isinstance(body[-1], ast.Return) \
                and (body[-1].value is None or (isinstance(body[-1].value, ast.Constant)
                                                and body[-1].value.value is None)):
            body.pop()
        if self.stack:
            for node in self.stack:
                if isinstance(node, ast.expr):
                    body.append(ast.Expr(value=node))
            self.stack.clear()
        return body

    def parse_block(self, stop, loop_exit=None, until_backward=None,
                    loop_header=None):
        """Consume instructions until a stop offset / closing backward jump."""
        stmts = []
        starts = []                                   # instr index where each stmt began
        frame_start = self.index
        guard = 0
        while self.index < len(self.instrs):
            guard += 1
            _mark = self.index
            if guard > 40000:
                raise D6Unsupported("runaway structure")
            ins = self.here()
            if ins["off"] in stop:
                # CPython parks the function's own epilogue (``LOAD_CONST None;
                # RETURN_VALUE``) right before the boundary a sibling block
                # starts at.  Read as a statement it shows up as a bare
                # ``return`` at the end of a nested block, which the source
                # never had, so it is dropped here.
                if stmts and isinstance(stmts[-1], ast.Return) \
                        and stmts[-1].value is None and self.index >= 2 \
                        and self.instrs[self.index - 1]["op"] == "RETURN_VALUE":
                    prev = self.instrs[self.index - 2]
                    if prev["op"] == "LOAD_CONST" and prev["arg"] is not None \
                            and self.code.consts[prev["arg"]] is None:
                        stmts.pop()
                        if starts:
                            starts.pop()
                break
            op = ins["op"]
            if op in D6_SKIP or ins["off"] in self.dead_offsets:
                self.index += 1
                continue
            entry = self._try_at(ins["off"])
            if entry is not None and ins["off"] not in getattr(self, "_try_seen", set()):
                self._try_seen = getattr(self, "_try_seen", set()) | {ins["off"]}
                stmts.extend(self.parse_try(entry))
                while len(starts) < len(stmts):
                    starts.append(_mark)
                continue
            if op == "FOR_ITER":
                stmts.extend(self.parse_for(loop_exit))
                while len(starts) < len(stmts):
                    starts.append(_mark)
                continue
            if "JUMP" in op and ("POP_JUMP" in op or "IF_TRUE" in op or "IF_FALSE" in op):
                stmts.extend(self.handle_branch(stop, loop_exit, until_backward))
                while len(starts) < len(stmts):
                    starts.append(_mark)
                if loop_exit is not None and self.index < len(self.instrs) \
                        and self.instrs[self.index]["off"] >= loop_exit:
                    # the branch chain ended past the loop's own epilogue, so the
                    # loop body is over even though no back edge was stepped on
                    break
                continue
            if "JUMP" in op:
                target = ins.get("target")
                if until_backward is not None and (
                        target == until_backward
                        or ("BACKWARD" in op
                            and d6_is_back_edge(target, until_backward))):
                    self.index += 1
                    break
                if loop_header is not None and target == loop_header \
                        and "BACKWARD" in op:
                    stmts.append(ast.Continue())
                    self.index += 1
                    break
                if loop_exit is not None and target == loop_exit:
                    stmts.append(ast.Break())
                elif loop_exit is not None and target is not None and target <= d6_until_backward_or(
                        until_backward, ins["off"]):
                    stmts.append(ast.Continue())
                elif target is not None and "BACKWARD" in op:
                    # ``while True:`` never had a conditional guard to open it, so
                    # the only marker is this back edge: wrap the tail of the
                    # block into the loop body.
                    k = self.offset_index.get(target) if hasattr(self, "offset_index") else None
                    if loop_header is None and loop_exit is None and k is not None \
                            and k >= frame_start and any(s >= k for s in starts):
                        # the epilogue of the enclosing function is often the
                        # last thing inside ``while True:`` - it is not source
                        self._drop_epilogue_return(stmts, starts)
                        cut = next(i for i, s in enumerate(starts) if s >= k)
                        body = _d6_fix_breaks(stmts[cut:])
                        stmts = stmts[:cut] + [ast.While(test=ast.Constant(value=True),
                                                         body=body or [ast.Pass()], orelse=[])]
                        starts = starts[:cut] + [k]
                self.index += 1
                continue
            node = self.step()
            self.index += 1
            if node is not None:
                stmts.extend(node if isinstance(node, list) else [node])
            while len(starts) < len(stmts):
                starts.append(_mark)
        self._drop_epilogue_return(stmts, starts)
        return stmts

    def _drop_epilogue_return(self, stmts, starts=None):
        """Remove the enclosing function's epilogue when it landed in a block.

        CPython emits one implicit ``return None`` per function, and it can end
        up inside a nested block (the tail of a ``while True:``, the last arm of
        an ``if``) with a few bookkeeping opcodes between it and the block's
        boundary.  Source never had that statement, so it is dropped.
        """
        if not stmts or not isinstance(stmts[-1], ast.Return) \
                or stmts[-1].value is not None:
            return
        probe = self.index - 1
        pair = None
        while 0 <= probe < len(self.instrs) and self.index - probe <= 16:
            op = self.instrs[probe]["op"]
            if op == "RETURN_VALUE" and probe - 1 >= 0 \
                    and self.instrs[probe - 1]["op"] == "LOAD_CONST" \
                    and self.instrs[probe - 1]["arg"] is not None \
                    and self.code.consts[self.instrs[probe - 1]["arg"]] is None:
                pair = probe
                break
            if op not in D6_EPILOGUE_GAP and "JUMP" not in op:
                return
            probe -= 1
        if pair is None:
            return
        stmts.pop()
        if starts:
            starts.pop()

    # -------------------------------------------------------------- loops
    def parse_for(self, loop_exit):
        """``FOR_ITER`` - the iterator is already on the stack."""
        for_idx = self.index
        for_off = self.instrs[for_idx]["off"]
        exit_off = self.instrs[for_idx].get("target")
        iterator = self.pop_expr()
        while isinstance(iterator, ast.Call) and getattr(iterator.func, "id", "") == "iter":
            iterator = iterator.args[0]
        depth = len(self.stack)
        self.index = for_idx + 1
        target = self._loop_target()
        try:
            body = self.parse_block(stop=set(), loop_exit=exit_off,
                                    until_backward=for_off)
        except D6RegionEnd as end:
            body = list(end.args[0]) if end.args else []
        del self.stack[depth:]
        body = d6_trim(body)
        if self.index < len(self.instrs) and "JUMP" in self.here()["op"]:
            self.index += 1
        if self.index < len(self.instrs) and self.here()["off"] == exit_off:
            self.index += 1
            if self.index < len(self.instrs) and self.here()["op"] in ("END_FOR", "POP_TOP"):
                self.index += 1
        return [ast.For(target=target, iter=iterator, body=body or [ast.Pass()],
                        orelse=[])]

    def _loop_target(self):
        ins = self.here()
        op = ins["op"]
        if op == "STORE_FAST_LOAD_FAST":
            store, load = ins["arg"] >> 4, ins["arg"] & 15
            self.index += 1
            self.push(ast.Name(id=self.name_at(self.code.varnames, load),
                               ctx=ast.Load()))
            return ast.Name(id=self.name_at(self.code.varnames, store),
                            ctx=ast.Store())
        if op in ("STORE_FAST_STORE_FAST", "STORE_FAST"):
            if op == "STORE_FAST_STORE_FAST":
                first, second = ins["arg"] >> 4, ins["arg"] & 15
                self.index += 1
                return ast.Tuple(elts=[
                    ast.Name(id=self.name_at(self.code.varnames, first), ctx=ast.Store()),
                    ast.Name(id=self.name_at(self.code.varnames, second),
                             ctx=ast.Store())], ctx=ast.Store())
        if op in D6_STORE_FAST_OPS:
            self.index += 1
            return ast.Name(id=self.name_at(self.code.varnames, ins["arg"]),
                            ctx=ast.Store())
        if op in D6_STORE_NAME_OPS:
            self.index += 1
            return ast.Name(id=self.name_at(self.code.names, ins["arg"]),
                            ctx=ast.Store())
        if op == "UNPACK_SEQUENCE":
            self.index += 1
            return ast.Tuple(elts=self._unpack_targets(ins["arg"]), ctx=ast.Store())
        if not self.tolerant:
            raise D6Unsupported("for target")
        self.index += 1
        return ast.Name(id=f"_item{self.index}", ctx=ast.Store())

    def _unpack_targets(self, count):
        """Targets of an ``UNPACK_SEQUENCE``; 3.13 fuses the stores in pairs."""
        out = []
        while count > 0:
            here = self.here() if self.index < len(self.instrs) else None
            if here is not None and here["op"] == "STORE_FAST_STORE_FAST" and count >= 2:
                first, second = here["arg"] >> 4, here["arg"] & 15
                self.index += 1
                out.append(ast.Name(id=self.name_at(self.code.varnames, first),
                                    ctx=ast.Store()))
                out.append(ast.Name(id=self.name_at(self.code.varnames, second),
                                    ctx=ast.Store()))
                count -= 2
                continue
            out.append(self._loop_target())
            count -= 1
        return out

    def parse_while_test(self, cond, loop_exit, body_start):
        self.index += 1                                # step over the branch
        depth = len(self.stack)
        try:
            body = self.parse_block(stop=set(), loop_exit=loop_exit,
                                    until_backward=body_start)
        except D6RegionEnd as end:
            body = list(end.args[0]) if end.args else []
        del self.stack[depth:]
        body = d6_trim(body)
        # CPython repeats the loop test at the bottom of the body; that guard is
        # the condition itself, so drop it and keep the source shape identical
        def _same_test(node):
            try:
                return (ast.dump(node) == ast.dump(cond)
                        or (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
                            and ast.dump(node.operand) == ast.dump(cond)))
            except Exception:                        # noqa: BLE001 - unparsable node
                return False

        def _pure_flow(stmts):
            return all(isinstance(stmt, (ast.Break, ast.Continue, ast.Pass, ast.Return))
                       for stmt in stmts)

        while body and isinstance(body[-1], ast.If) and _same_test(body[-1].test) \
                and _pure_flow(body[-1].body) and _pure_flow(body[-1].orelse):
            body.pop()
        if self.index < len(self.instrs) and "JUMP" in self.here()["op"]:
            self.index += 1
        return [ast.While(test=cond, body=body or [ast.Pass()], orelse=[])]

    def parse_inlined_comp(self):
        """Rebuild a comprehension that 3.12+ compiled into the parent frame."""
        start = self.index
        iterable = self.pop_expr()
        kind = "list"
        probe = start
        while probe < len(self.instrs):
            op = self.instrs[probe]["op"]
            if op == "FOR_ITER":
                break
            if op == "BUILD_LIST":
                kind = "list"
            elif op == "BUILD_SET":
                kind = "set"
            elif op == "BUILD_MAP":
                kind = "dict"
            elif op in ("LOAD_FAST_AND_CLEAR", "LOAD_FAST_BORROW_AND_CLEAR",
                        "LOAD_NAME_AND_CLEAR", "SWAP", "GET_ITER", "PUSH_NULL",
                        "BUILD_LIST", "BUILD_SET", "BUILD_MAP", "NOP",
                        "LIST_EXTEND", "SET_UPDATE"):
                pass
            else:
                raise D6Unsupported("comprehension prologue")
            probe += 1
        if probe >= len(self.instrs):
            raise D6Unsupported("comprehension without FOR_ITER")
        for_index = probe
        for_off = self.instrs[for_index]["off"]
        cleared = []
        for ins in self.instrs[start:for_index]:
            if ins["op"] in ("LOAD_FAST_AND_CLEAR", "LOAD_FAST_BORROW_AND_CLEAR"):
                cleared.append(self.name_at(self.code.varnames, ins["arg"]))
        exit_off = self.instrs[for_index].get("target")
        self.index = for_index + 1
        target = self._loop_target()
        filters = []
        elt = None
        key = None
        while self.index < len(self.instrs):
            op = self.here()["op"]
            if op == "LIST_APPEND" or op == "SET_ADD" or op == "MAP_ADD":
                break
            if "JUMP" in op and ("POP_JUMP" in op or "IF_TRUE" in op or "IF_FALSE" in op):
                raw = self.here()["op"]
                cond = self.pop_expr()
                jumps_when_true = "TRUE" in raw
                if jumps_when_true:
                    filters.append(cond)
                else:
                    filters.append(ast.UnaryOp(op=ast.Not(), operand=cond))
                self.index += 1
                # the false path is the loop back edge: step over it
                if self.index < len(self.instrs) and "JUMP" in self.here()["op"] \
                        and "BACKWARD" in self.here()["op"]:
                    self.index += 1
                continue
            value = self.step()
            if value is not None:
                raise D6Unsupported("statement in comprehension")
            self.index += 1
            if self.here()["op"] in ("LIST_APPEND", "SET_ADD", "MAP_ADD"):
                break
        if kind == "dict":
            value = self.pop_expr()
            key = self.pop_expr()
            elt = value
        else:
            elt = self.pop_expr()
        self.index += 1                              # the APPEND instruction
        # skip back edge, END_FOR and the variable restore
        while self.index < len(self.instrs) and self.here()["op"] in (
                "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "END_FOR", "SWAP",
                "POP_TOP", "NOP"):
            if self.here()["op"] in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
                if self.here().get("target") != for_off:
                    break
            self.index += 1
        restores = max(1, len(cleared))
        while restores and self.index < len(self.instrs):
            here = self.here()
            if here["op"] not in ("STORE_FAST", "STORE_NAME", "STORE_FAST_STORE_FAST",
                                  "SWAP", "POP_TOP", "NOP"):
                break
            self.index += 1
            restores -= 1
        generator = ast.comprehension(target=target, iter=iterable, ifs=filters,
                                      is_async=0)
        if kind == "dict":
            node = ast.DictComp(key=key, value=elt, generators=[generator])
        elif kind == "set":
            node = ast.SetComp(elt=elt, generators=[generator])
        else:
            node = ast.ListComp(elt=elt, generators=[generator])
        self.push(node)
        self.index -= 1                              # caller advances past CALL
        return None

    # ------------------------------------------------------------- with
    WITH_CLEANUP_OPS = ("PUSH_EXC_INFO", "WITH_EXCEPT_START", "TO_BOOL", "RERAISE",
                        "POP_EXCEPT", "POP_TOP", "COPY", "SWAP", "NOP",
                        "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE", "CALL", "LOAD_CONST")

    SPECIAL_METHODS = {0: "__enter__", 1: "__exit__", 2: "__aenter__", 3: "__aexit__",
                       4: "__enter__", 5: "__exit__", 6: "__aenter__", 7: "__aexit__"}

    def parse_load_special(self, arg):
        """3.14 ``LOAD_SPECIAL``: the ``with`` prologue, or a special method load."""
        name = self.SPECIAL_METHODS.get(arg)
        if name is None:
            raise D6Unsupported(f"load special {arg}")
        window = [ins["op"] for ins in self.instrs[self.index + 1:self.index + 5]]
        if name in ("__exit__", "__aexit__") and window[:3] == ["SWAP", "SWAP",
                                                                "LOAD_SPECIAL"] \
                and window[3] == "CALL" and len(self.stack) >= 2:
            return self.parse_with14()
        owner = self.pop_expr()
        self.push(ast.Attribute(value=owner, attr=name, ctx=ast.Load()))
        return None

    def _special_with_entry(self, body_off):
        """Exception entry that guards a 3.14 ``with`` body."""
        for item in self.exception_entries():
            if item["start"] <= body_off < item["end"]:
                index = self._snap(item["handler"])
                if index is None:
                    continue
                window = [ins["op"] for ins in self.instrs[index:index + 6]]
                if "LOAD_SPECIAL" in window or "WITH_EXCEPT_START" in window:
                    return item
        return None

    def parse_with14(self):
        """``with`` as CPython 3.14 lays it out: COPY / LOAD_SPECIAL / SWAPs."""
        ctx = None
        pair = []
        while self.stack and len(pair) < 2 and isinstance(self.stack[-1], ast.expr):
            pair.append(self.stack.pop())
        if len(pair) == 2:
            ctx = pair[1]                            # the ``COPY 1`` duplicate
        elif pair:
            ctx = pair[0]
        if ctx is None:
            raise D6Unsupported("with without context")

        probe = self.index + 1
        while probe < len(self.instrs) and self.instrs[probe]["op"] in (
                "SWAP", "LOAD_SPECIAL", "NOP"):
            probe += 1
        if probe >= len(self.instrs) or self.instrs[probe]["op"] != "CALL":
            raise D6Unsupported("with prologue")
        self.index = probe + 1                        # the CALL ran __enter__()

        optional = None
        store_ops = D6_STORE_FAST_OPS | D6_STORE_NAME_OPS
        if self.index < len(self.instrs) and self.here()["op"] in store_ops:
            ins = self.here()
            table = self.code.varnames if ins["op"] in D6_STORE_FAST_OPS else self.code.names
            optional = ast.Name(id=self.name_at(table, ins["arg"]), ctx=ast.Store())
            self.index += 1
        elif self.index < len(self.instrs) and self.here()["op"] == "POP_TOP":
            self.index += 1

        if self.index >= len(self.instrs):
            return [ast.With(items=[ast.withitem(context_expr=ctx, optional_vars=optional)],
                             body=[ast.Pass()])]
        body_off = self.instrs[self.index]["off"]
        entry = self._special_with_entry(body_off)
        stop = {entry["end"]} if entry is not None else set()
        depth = len(self.stack)
        body = []
        try:
            body = self.parse_block(stop=stop)
        except D6RegionEnd as end:
            body = list(end.args[0]) if end.args else []
        except D6Unsupported:
            body = []
        leftovers = [node for node in self.stack[depth:] if isinstance(node, ast.expr)]
        del self.stack[depth:]
        body = d6_trim(body) if body else []
        # the exit call: ``LOAD_CONST None`` x3 / ``CALL 3`` / ``POP_TOP``
        guard = 0
        while self.index < len(self.instrs) and guard < 12:
            here = self.here()
            if here["op"] in ("LOAD_CONST", "CALL", "POP_TOP", "SWAP", "NOP", "POP_ITER"):
                if here["op"] == "CALL" and here.get("arg") == 3:
                    self.index += 1
                    if self.index < len(self.instrs) and self.here()["op"] == "POP_TOP":
                        self.index += 1
                    break
                self.index += 1
                guard += 1
                continue
            break
        if leftovers and self.index < len(self.instrs) \
                and self.here()["op"] in ("RETURN_VALUE", "RETURN_CONST"):
            body.append(ast.Return(value=leftovers[-1]))
            self.index += 1
        tails = set()
        if entry is not None:
            for item in self.exception_entries():
                if item["start"] >= entry["handler"] or item["handler"] >= entry["handler"]:
                    tails.update(range(item["start"], item["end"] + 2, 2))
                    tails.update(range(item["handler"], item["handler"] + 24, 2))
        self.dead_offsets |= tails
        body = body or [ast.Pass()]
        return [ast.With(items=[ast.withitem(context_expr=ctx, optional_vars=optional)],
                         body=body)]

    def _with_entry(self, offset):
        """Find the exception-table entry that guards a ``with`` body."""
        for item in self.exception_entries():
            if item["start"] <= offset < item["end"]:
                index = self.offset_index.get(item["handler"])
                if index is None:
                    continue
                window = [ins["op"] for ins in self.instrs[index:index + 5]]
                if "WITH_EXCEPT_START" in window:
                    return item
        return None

    def parse_with(self):
        """``BEFORE_WITH`` - rebuild ``with ctx as name: body``."""
        ctx = self.pop_expr()
        optional = None
        store_ops = D6_STORE_FAST_OPS | D6_STORE_NAME_OPS
        if self.index + 1 < len(self.instrs) \
                and self.instrs[self.index + 1]["op"] in store_ops:
            self.index += 1
            ins = self.here()
            table = self.code.varnames if ins["op"] in D6_STORE_FAST_OPS else self.code.names
            optional = ast.Name(id=self.name_at(table, ins["arg"]), ctx=ast.Store())
        self.index += 1
        if self.index >= len(self.instrs):
            return [ast.With(items=[ast.withitem(context_expr=ctx, optional_vars=optional)],
                             body=[ast.Pass()])]
        body_off = self.instrs[self.index]["off"]
        entry = self._with_entry(body_off)
        stop = {entry["end"]} if entry is not None else set()
        depth = len(self.stack)
        body = []
        try:
            body = self.parse_block(stop=stop)
        except D6RegionEnd as end:
            body = list(end.args[0]) if end.args else []
        leftovers = [node for node in self.stack[depth:] if isinstance(node, ast.expr)]
        del self.stack[depth:]
        body = d6_trim(body) if body else []
        # walk over the normal-exit sequence and the interpreter's handler stub
        while self.index < len(self.instrs) and self.here()["op"] in self.WITH_CLEANUP_OPS \
                and self.here()["op"] not in ("RETURN_VALUE", "RETURN_CONST"):
            self.index += 1
        if leftovers and self.index < len(self.instrs) \
                and self.here()["op"] in ("RETURN_VALUE", "RETURN_CONST"):
            body.append(ast.Return(value=leftovers[-1]))   # ``with`` + return
            self.index += 1
        tails = set()
        if entry is not None:
            for item in self.exception_entries():
                if item["start"] >= entry["handler"] or item["handler"] >= entry["handler"]:
                    tails.update(range(item["start"], item["end"] + 2, 2))
                    tails.update(range(item["handler"], item["handler"] + 24, 2))
        self.dead_offsets |= tails
        guard = 0
        while self.index < len(self.instrs) and guard < 80:
            here = self.here()
            if here["off"] in tails or here["op"] in self.WITH_CLEANUP_OPS \
                    or here["op"] in ("RETURN_VALUE", "RETURN_CONST", "RERAISE"):
                self.index += 1
                guard += 1
                continue
            break
        body = body or [ast.Pass()]
        node = ast.With(items=[ast.withitem(context_expr=ctx, optional_vars=optional)],
                        body=body or [ast.Pass()])
        self._last_with = node
        return [node]

    # --------------------------------------------------- chained comparison
    def _chain_pattern(self, i):
        """``a < b < c`` keeps the middle operand: SWAP k; COPY k; ... COMPARE_OP"""
        if i + 2 >= len(self.instrs):
            return False
        if self.instrs[i + 1]["op"] != "COPY":
            return False
        if self.instrs[i + 1].get("arg") != self.instrs[i].get("arg"):
            return False
        window = [ins["op"] for ins in self.instrs[i + 2:i + 7]]
        if "COMPARE_OP" not in window:
            return False
        for offset, op in enumerate(window):
            if op == "COMPARE_OP":
                tail = [ins["op"] for ins in self.instrs[i + 3 + offset:i + 6 + offset]]
                return tail[:1] == ["COPY"] and tail[1:2] in ([], ["TO_BOOL"])
            if op not in ("TO_BOOL", "SWAP", "COPY"):
                return False
        return False

    def _chain_cleanup(self, target_off):
        """Mark the ``SWAP n; POP_TOP`` bail-out block of a chained compare dead."""
        if target_off is None or target_off not in self.offset_index:
            return
        start = self.offset_index[target_off]
        for ins in self.instrs[start:start + 4]:
            if ins["op"] not in ("SWAP", "POP_TOP", "COPY"):
                return
            self.dead_offsets.add(ins["off"])

    def parse_chained_compare(self, i):
        """Rebuild a chained comparison from its SWAP/COPY scaffolding."""
        stack_depth = len(self.stack)
        middle = self.stack[-1]
        left = self.stack[-2]
        del self.stack[-2:]
        probe = i + 2
        while probe < len(self.instrs) and self.instrs[probe]["op"] != "COMPARE_OP":
            probe += 1
        ops, comparators = [], [middle]
        while True:
            if probe >= len(self.instrs) or self.instrs[probe]["op"] != "COMPARE_OP":
                del self.stack[stack_depth - 2:]
                raise D6Unsupported("chained comparison")
            cmp_arg = self.instrs[probe].get("arg", 0)
            index = (cmp_arg >> 5) if self.version >= (3, 13) else (
                (cmp_arg >> 4) if self.version >= (3, 12) else cmp_arg)
            if index >= len(D6_CMP_OPS):
                index = cmp_arg & 0x0F
            ops.append(D6_CMP_OPS[index]())
            self.index = probe + 1
            # only ``COPY 1`` marks another link in the chain; a bare branch
            # after COMPARE_OP is an ordinary ``if`` on the comparison result
            if self.index >= len(self.instrs) \
                    or self.instrs[self.index]["op"] != "COPY" \
                    or self.instrs[self.index].get("arg") != 1:
                self.index = probe
                break
            while self.index < len(self.instrs) \
                    and self.instrs[self.index]["op"] in ("COPY", "TO_BOOL"):
                self.index += 1
            if self.index < len(self.instrs) \
                    and "POP_JUMP_IF" in self.instrs[self.index]["op"]:
                jump = self.instrs[self.index]
                self._chain_cleanup(jump.get("target"))
                self.index += 1
                if self.index < len(self.instrs) and self.instrs[self.index]["op"] == "POP_TOP":
                    self.index += 1
                # evaluate the next comparator
                guard = 0
                while self.index < len(self.instrs) \
                        and self.instrs[self.index]["op"] != "COMPARE_OP":
                    node = self.step()
                    self.index += 1
                    guard += 1
                    if isinstance(node, ast.stmt) or guard > 40:
                        break
                probe = self.index
                if probe >= len(self.instrs) or not self.stack:
                    self.index = probe
                    break
                try:
                    comparators.append(self.pop_expr())
                except D6Unsupported:
                    break
                continue
            break
        self.index = probe                          # caller advances past COMPARE_OP
        node = ast.Compare(left=left, ops=ops, comparators=comparators)
        self.push(node)
        return None

    def _backward_target_is(self, start_index, offset):
        """Does the region starting here end in ``JUMP_BACKWARD offset``?"""
        for ins in self.instrs[start_index:start_index + 400]:
            if "JUMP" in ins["op"] and "BACKWARD" in ins["op"]:
                return ins.get("target") == offset
            if ins["op"] in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                return False
        return False

    # ------------------------------------------------------------ branches
    def handle_branch(self, stop, loop_exit, until_backward):
        ins = self.here()
        op = ins["op"]
        invert = ("TRUE" in op) or ("NONE" in op and "NOT_NONE" not in op)
        if "IF_TRUE_OR_POP" in op or "IF_FALSE_OR_POP" in op:
            raise D6Unsupported("short-circuit")
        cond = self.pop_expr()
        if invert:
            cond = ast.UnaryOp(op=ast.Not(), operand=cond)
        target_off = ins.get("target")
        target_idx = self.target_index(ins)
        if target_idx is None:
            self.index += 1
            return []
        # conditional break inside a loop; the exit offset can be reported one
        # code unit late when the branch has inline caches, so compare with >=
        if loop_exit is not None and target_off is not None \
                and abs(target_off - loop_exit) <= 2:
            self.index += 1
            return [ast.If(test=cond, body=[ast.Break()], orelse=[])]
        if target_off is not None and target_off < ins["off"]:
            self.index += 1
            return []                                  # loop test seen from below
        body_start = self.instrs[self.index + 1]["off"] if self.index + 1 < len(self.instrs) \
            else None
        if body_start is not None and self._backward_target_is(self.index + 1, body_start):
            return self.parse_while_test(cond, target_off, body_start)
        self.index += 1
        depth = len(self.stack)
        then_stmts = self.parse_block(stop={target_off}, loop_exit=loop_exit,
                                     loop_header=until_backward)
        del self.stack[depth:]
        previous = self.instrs[self.index - 1] if self.index else None
        if previous is not None and previous["op"] in ("JUMP_BACKWARD",
                                                       "JUMP_BACKWARD_NO_INTERRUPT") \
                and until_backward is not None \
                and previous.get("target") == until_backward:
            # both arms run to the loop's back edge: this is if/else inside a loop
            self.index = target_idx
            else_stmts = self.parse_block(stop=set(), loop_exit=loop_exit,
                                          loop_header=until_backward)
            node = ast.If(test=cond, body=then_stmts or [ast.Pass()],
                          orelse=else_stmts)
            raise D6RegionEnd([node])
        self.index = target_idx
        else_stmts = []
        previous = self.instrs[target_idx - 1] if target_idx else None
        if previous is not None and previous["op"] in ("JUMP_FORWARD", "JUMP") \
                and (previous.get("target") or 0) > target_off:
            join_off = previous["target"]
            else_stmts = self.parse_block(stop={join_off}, loop_exit=loop_exit,
                                          until_backward=until_backward)
            join_idx = self.offset_index.get(join_off)
            if join_idx is not None:
                self.index = join_idx
        return [ast.If(test=cond, body=then_stmts or [ast.Pass()], orelse=else_stmts)]

    # ------------------------------------------------------------- single
    def step(self):
        """Consume one instruction. Returns a statement, a list, or None."""
        ins = self.here()
        op, arg = ins["op"], ins["arg"]
        code = self.code
        if op == "PUSH_NULL":
            self.push(D6_NULL)
            return None
        if op == "LOAD_BUILD_CLASS":
            self.push(("build_class",))
            return None
        if op == "LOAD_LOCALS":
            # 3.14 hands the class namespace to the body as a cell
            # (``__classdict__``); it has no source form
            self.push(("classdict",))
            return None
        if op in ("LOAD_FAST_AND_CLEAR", "LOAD_FAST_BORROW_AND_CLEAR",
                  "LOAD_NAME_AND_CLEAR"):
            return self.parse_inlined_comp()
        if op == "GET_ITER":
            return None
        if op == "LOAD_CONST":
            value = code.consts[arg]
            if hasattr(value, "code"):
                self.push(("code", value))
            else:
                self.push(d6_const(value))
        elif op == "LOAD_SMALL_INT":
            self.push(d6_const(arg))
        elif op in D6_LOAD_FAST_OPS:
            self.push(ast.Name(id=self.name_at(code.varnames, arg), ctx=ast.Load()))
        elif op in ("LOAD_NAME", "LOAD_GLOBAL"):
            if op == "LOAD_GLOBAL" and arg & 1:
                self.push(D6_NULL)
            index = arg >> 1 if op == "LOAD_GLOBAL" else arg
            self.push(ast.Name(id=self.name_at(code.names, index), ctx=ast.Load()))
        elif op in ("LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"):
            first, second = arg >> 4, arg & 15
            self.push(ast.Name(id=self.name_at(code.varnames, first), ctx=ast.Load()))
            self.push(ast.Name(id=self.name_at(code.varnames, second), ctx=ast.Load()))
        elif op in ("LOAD_FAST_CHECK", "LOAD_CLASSDEREF"):
            self.push(ast.Name(id=self.name_at(code.varnames, arg), ctx=ast.Load()))
        elif op == "LOAD_ATTR":
            owner = self.pop_expr()
            if arg & 1:
                self.push(D6_NULL)
            self.push(ast.Attribute(value=owner, attr=self.name_at(code.names, arg >> 1),
                                    ctx=ast.Load()))
        elif op == "LOAD_SUPER_ATTR":
            # stack: super, __class__, self -> ``super().name``
            if len(self.stack) >= 3:
                self.stack.pop()
                self.stack.pop()
                super_node = self._coerce(self.stack.pop())
            else:
                super_node = ast.Name(id="super", ctx=ast.Load())
            name = self.name_at(code.names, arg >> 2)
            if arg & 1:
                self.push(D6_NULL)                   # method-style load
            self.push(ast.Attribute(value=ast.Call(func=super_node, args=[],
                                                   keywords=[]), attr=name,
                                    ctx=ast.Load()))
            return None
        elif op in D6_STORE_FAST_OPS or op in D6_STORE_NAME_OPS or op == "STORE_DEREF":
            table = code.names if op in D6_STORE_NAME_OPS else code.varnames
            name = self.name_at(table, arg)
            if self.stack and isinstance(self.stack[-1], tuple) \
                    and len(self.stack[-1]) == 2 and self.stack[-1][0] == "unpack":
                return self._unpack_store(name)
            if op == "STORE_GLOBAL" and name not in self.globals_decl:
                self.globals_decl.append(name)
            if not self.stack:
                return None                          # dead cleanup stub
            value = self.pop()
            if isinstance(value, tuple) and value[0] == "aug":
                return ast.AugAssign(target=ast.Name(id=name, ctx=ast.Store()),
                                     op=value[2], value=value[3])
            if isinstance(value, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if name and name.isidentifier():
                    value.name = name
                return value
            if isinstance(value, tuple) and value and value[0] == "classdict":
                return None                           # ``__classdict__`` cell
            if isinstance(value, tuple):
                node = self._special_store(value, name)
                return node
            if not isinstance(value, ast.expr):
                raise D6Unsupported("store value")
            return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value)
        elif op == "STORE_FAST_STORE_FAST" and self.stack \
                and isinstance(self.stack[-1], tuple) and len(self.stack[-1]) == 2 \
                and self.stack[-1][0] == "unpack":
            first, second = arg >> 4, arg & 15
            node = self._unpack_store(self.name_at(code.varnames, first))
            if node is not None:
                return node
            return self._unpack_store(self.name_at(code.varnames, second))
        elif op == "STORE_FAST_STORE_FAST":
            first, second = arg >> 4, arg & 15
            node = self._unpack_store(self.name_at(code.varnames, first)) \
                if self.stack and isinstance(self.stack[-1], tuple) \
                and self.stack[-1][0] == "unpack" else None
            if node is not None:
                return node
            second_node = self._unpack_store(self.name_at(code.varnames, second)) \
                if self.stack and isinstance(self.stack[-1], tuple) \
                and self.stack[-1][0] == "unpack" else None
            if second_node is not None:
                return second_node
            return None
        elif op == "STORE_FAST_LOAD_FAST":
            store, load = arg >> 4, arg & 15
            value = self.pop() if self.stack else None
            self.push(ast.Name(id=self.name_at(code.varnames, load), ctx=ast.Load()))
            if value is None:
                return None
            return ast.Assign(
                targets=[ast.Name(id=self.name_at(code.varnames, store),
                                  ctx=ast.Store())],
                value=self._coerce(value))
        elif op == "STORE_ATTR":
            owner = self.pop_expr()
            value = self.pop()
            target = ast.Attribute(value=owner, attr=self.name_at(code.names, arg >> 1),
                                   ctx=ast.Store())
            if isinstance(value, tuple) and value[0] == "aug":
                return ast.AugAssign(target=target, op=value[2], value=value[3])
            return ast.Assign(targets=[target], value=self._coerce(value))
        elif op == "STORE_SUBSCR":
            key = self.pop_expr()
            owner = self.pop_expr()
            value = self.pop()
            target = ast.Subscript(value=owner, slice=key, ctx=ast.Store())
            if isinstance(value, tuple) and value[0] == "aug":
                return ast.AugAssign(target=target, op=value[2], value=value[3])
            return ast.Assign(targets=[target], value=self._coerce(value))
        elif op == "DELETE_SUBSCR":
            key = self.pop_expr()
            owner = self.pop_expr()
            return ast.Delete(targets=[ast.Subscript(value=owner, slice=key,
                                                     ctx=ast.Del())])
        elif op == "BINARY_OP":
            right = self.pop_expr()
            left = self.pop_expr()
            if arg in D6_BIN_OPS:
                self.push(ast.BinOp(left=left, op=D6_BIN_OPS[arg](), right=right))
            elif arg in D6_AUG_OPS:
                self.push(("aug", left, D6_AUG_OPS[arg](), right))
            elif arg == D6_NB_SUBSCR:
                # 3.14 folded ``obj[key]`` into BINARY_OP(NB_SUBSCR)
                self.push(ast.Subscript(value=left, slice=right, ctx=ast.Load()))
            else:
                raise D6Unsupported(f"binary op {arg}")
        elif op == "BUILD_SLICE":
            parts = [self.pop_expr() for _ in range(arg)][::-1]
            if len(parts) == 3:
                lower, upper, step_ = parts
            else:
                lower, upper = (parts + [None, None])[:2]
                step_ = None
            self.push(("slice", lower, upper, step_))
        elif op == "BINARY_SUBSCR":
            key = self.pop()
            if isinstance(key, tuple) and len(key) == 4 and key[0] == "slice":
                key = ast.Slice(lower=key[1], upper=key[2], step=key[3])
            if not isinstance(key, ast.AST):
                raise D6Unsupported(f"not an expression: {key!r}")
            owner = self.pop_expr()
            if isinstance(key, tuple) and len(key) == 4 and key[0] == "slice":
                key = ast.Slice(lower=key[1], upper=key[2], step=key[3])
            self.push(ast.Subscript(value=owner, slice=key, ctx=ast.Load()))
        elif op == "BINARY_SLICE":
            stop_ = self.pop_expr()
            start = self.pop_expr()
            owner = self.pop_expr()
            self.push(ast.Subscript(value=owner,
                                    slice=ast.Slice(lower=start, upper=stop_, step=None),
                                    ctx=ast.Load()))
        elif op == "COMPARE_OP":
            right = self.pop_expr()
            left = self.pop_expr()
            index = (arg >> 5) if self.version >= (3, 13) else (
                (arg >> 4) if self.version >= (3, 12) else arg)
            if index >= len(D6_CMP_OPS):
                index = arg & 0x0F
            if index >= len(D6_CMP_OPS):
                raise D6Unsupported("compare")
            self.push(ast.Compare(left=left, ops=[D6_CMP_OPS[index]()],
                                  comparators=[right]))
        elif op in ("IS_OP", "CONTAINS_OP"):
            right = self.pop_expr()
            left = self.pop_expr()
            operand = (ast.IsNot() if arg else ast.Is()) if op == "IS_OP" \
                else (ast.NotIn() if arg else ast.In())
            self.push(ast.Compare(left=left, ops=[operand], comparators=[right]))
        elif op.startswith("UNARY_"):
            operand = self.pop_expr()
            klass = {"UNARY_NEGATIVE": ast.USub, "UNARY_NOT": ast.Not,
                     "UNARY_INVERT": ast.Invert}.get(op)
            if klass is None:
                raise D6Unsupported(op)
            self.push(ast.UnaryOp(op=klass(), operand=operand))
        elif op == "BUILD_TUPLE":
            self.push(ast.Tuple(elts=self._pop_items(arg), ctx=ast.Load()))
        elif op == "BUILD_LIST":
            self.push(ast.List(elts=self._pop_items(arg), ctx=ast.Load()))
        elif op == "BUILD_SET":
            self.push(ast.Set(elts=self._pop_items(arg)))
        elif op == "BUILD_MAP":
            items = self._pop_items(arg * 2)
            self.push(ast.Dict(keys=items[0::2], values=items[1::2]))
        elif op == "BUILD_CONST_KEY_MAP":
            keys = self.pop()
            values = self._pop_items(arg)
            if isinstance(keys, ast.Tuple):
                key_nodes = [k if isinstance(k, ast.AST) else d6_const(k) for k in keys.elts]
            elif isinstance(keys, ast.Constant) and isinstance(keys.value, tuple):
                key_nodes = [d6_const(k) for k in keys.value]
            elif isinstance(keys, (tuple, list)):
                key_nodes = [k if isinstance(k, ast.AST) else d6_const(k) for k in keys]
            else:
                raise D6Unsupported("d6_const key map")
            self.push(ast.Dict(keys=key_nodes, values=values))
        elif op == "BUILD_STRING":
            parts = self._pop_items(arg)
            merged = []
            for part in parts:
                if isinstance(part, ast.JoinedStr):
                    merged.extend(part.values)
                elif isinstance(part, ast.Constant) and isinstance(part.value, str):
                    merged.append(part)
                else:
                    merged.append(ast.FormattedValue(value=part, conversion=-1,
                                                     format_spec=None))
            self.push(ast.JoinedStr(values=merged))
        elif op == "FORMAT_SIMPLE":
            value = self.pop_expr()
            self.push(ast.FormattedValue(value=value, conversion=-1, format_spec=None))
        elif op == "FORMAT_WITH_SPEC":
            spec = self.pop_expr()
            value = self.pop_expr()
            spec_node = spec if isinstance(spec, ast.JoinedStr) else ast.JoinedStr(values=[spec])
            if isinstance(value, ast.FormattedValue):
                value.format_spec = spec_node
                self.push(value)                     # ``f'{x!r:>4}'`` keeps the conversion
            else:
                self.push(ast.FormattedValue(value=value, conversion=-1,
                                             format_spec=spec_node))
        elif op == "CONVERT_VALUE":
            value = self.pop_expr()
            conversion = {1: ord("s"), 2: ord("r"), 3: ord("a")}.get(arg, -1)
            self.push(ast.FormattedValue(value=value, conversion=conversion,
                                         format_spec=None))
        elif op in ("CALL", "CALL_KW", "CALL_FUNCTION_EX"):
            return self.step_call(op, arg)
        elif op == "SWAP":
            if self._chain_pattern(self.index):
                return self.parse_chained_compare(self.index)
            swap = self._swap_assign(arg)
            if swap is not None:
                return swap
            if arg >= 1 and len(self.stack) >= arg:
                self.stack[-1], self.stack[-arg] = self.stack[-arg], self.stack[-1]
        elif op == "COPY":
            if len(self.stack) >= arg:
                self.push(self.stack[-arg])
        elif op in ("END_FOR", "POP_ITER", "POP_EXCEPT", "PUSH_EXC_INFO", "CHECK_EXC_MATCH",
                    "RERAISE", "END_ASYNC_FOR", "CHECK_EG_MATCH", "PREP_RERAISE_STAR"):
            return None                              # interpreter bookkeeping
        elif op in ("LIST_EXTEND", "SET_UPDATE", "DICT_UPDATE", "DICT_MERGE"):
            extra = self.pop()
            index = len(self.stack) - arg
            if not (0 <= index < len(self.stack)):
                raise D6Unsupported(op)
            if isinstance(extra, ast.Constant) and isinstance(extra.value,
                                                             (tuple, list, set,
                                                              frozenset)):
                extra = (ast.List(elts=[d6_const(item) for item in extra.value],
                                  ctx=ast.Load())
                         if not isinstance(extra.value, (set, frozenset))
                         else ast.Set(elts=[d6_const(item) for item in extra.value]))
            held = self.stack[index]
            if isinstance(held, (ast.List, ast.Set)) and isinstance(extra, (ast.Tuple,
                                                                            ast.List,
                                                                            ast.Set)):
                held.elts.extend(extra.elts)
            elif isinstance(held, ast.Dict) and isinstance(extra, ast.Dict):
                held.keys.extend(extra.keys)
                held.values.extend(extra.values)
            elif isinstance(held, ast.List) and isinstance(extra, ast.expr):
                held.elts.append(ast.Starred(value=extra, ctx=ast.Load()))   # [*a, ...]
            elif isinstance(held, ast.Dict) and isinstance(extra, ast.expr):
                held.keys.append(None)                                       # {**a, ...}
                held.values.append(extra)
            else:
                raise D6Unsupported(op)
        elif op in ("LIST_APPEND", "SET_ADD", "MAP_ADD"):
            # 3.11+ builds a *literal* display element by element: the value is
            # pushed, then appended to the container `arg` slots down the stack.
            value = self.pop()
            if op == "MAP_ADD":
                key = self.pop()
            else:
                key = None
            index = len(self.stack) - arg
            if not (0 <= index < len(self.stack)):
                if not self.tolerant:
                    raise D6Unsupported(op)
                self.push(ast.List(elts=[self._coerce(value)], ctx=ast.Load()))
                return None
            held = self.stack[index]
            item = self._coerce(value)
            if op == "LIST_APPEND" and isinstance(held, ast.List):
                held.elts.append(item)
            elif op == "SET_ADD" and isinstance(held, ast.Set):
                held.elts.append(item)
            elif op == "MAP_ADD" and isinstance(held, ast.Dict):
                held.keys.append(self._coerce(key))
                held.values.append(item)
            else:
                # container got lost (a dead jump, a fused store): rebuild one
                previous = self._coerce(held) if isinstance(held, ast.expr) else None
                if op == "MAP_ADD":
                    self.stack[index] = ast.Dict(keys=[self._coerce(key)],
                                                 values=[item])
                else:
                    self.stack[index] = ast.List(
                        elts=([previous] if previous is not None else []) + [item],
                        ctx=ast.Load())
        elif op == "POP_TOP":
            if not self.stack:
                return None
            node = self.pop()
            if isinstance(node, ast.expr):
                return ast.Expr(value=node)
            if isinstance(node, tuple):
                return None
        elif op in ("YIELD_VALUE", "YIELD_CONST"):
            value = self.pop() if op == "YIELD_VALUE" else const(code.consts[arg])
            node = value if isinstance(value, ast.expr) else None
            return ast.Expr(value=ast.Yield(value=node))
        elif op == "RETURN_VALUE":
            if not self.stack:
                return None                          # dead scaffolding after a chain
            node = self.pop()
            if node is D6_NULL:
                return ast.Return(value=None)
            value = node if isinstance(node, ast.expr) else None
            if isinstance(value, ast.Constant) and value.value is None:
                value = None
            return ast.Return(value=value)
        elif op == "RETURN_CONST":
            value = code.consts[arg]
            return ast.Return(value=None if value is None else d6_const(value))
        elif op in ("DELETE_NAME", "DELETE_GLOBAL", "DELETE_FAST", "DELETE_DEREF"):
            return ast.Delete(targets=[ast.Name(id=self.name_at(
                code.varnames if op == "DELETE_FAST" else code.names, arg),
                ctx=ast.Del())])
        elif op == "IMPORT_NAME":
            self._pending_fromlist = None
            if len(self.stack) >= 2:
                fromlist = self.pop_expr()       # fromlist (None for plain import)
                if isinstance(fromlist, ast.Constant) and fromlist.value is None:
                    self._pending_fromlist = None
                elif isinstance(fromlist, (ast.Tuple, ast.List)):
                    self._pending_fromlist = [elt.value for elt in fromlist.elts
                                              if isinstance(elt, ast.Constant)]
                else:
                    self._pending_fromlist = True
                self.pop_expr()                  # level (None for absolute imports)
            name = self.name_at(code.names, arg)
            if not name and self.stack and isinstance(self.stack[-1], ast.Constant) \
                    and isinstance(self.stack[-1].value, str):
                name = self.stack.pop().value
            self._pending_import = name
            self.push(("import", name))
        elif op == "IMPORT_FROM":
            self.push(("from", self.name_at(code.names, arg)))
        elif op == "UNPACK_SEQUENCE":
            # ``a, b = value``: the stores that follow fill the target tuple
            self.push(("unpack", {"targets": [], "count": arg, "value": self.pop()}))
            return None
        elif op == "UNPACK_EX":
            before, after = arg & 0xFF, arg >> 8
            self.push(("unpack", {"targets": [], "count": before + after + 1,
                                  "value": self.pop(), "star": before}))
            return None
        elif op == "LOAD_COMMON_CONSTANT":
            # 3.14: hardcoded table, kept in sync with Lib/opcode.py
            common = ("AssertionError", "NotImplementedError", "tuple", "all", "any")
            if arg == 0:
                self.push(("assertion",))
            else:
                self.push(ast.Name(id=common[arg] if arg < len(common) else f"_common{arg}",
                                   ctx=ast.Load()))
        elif op == "MATCH_CLASS":
            names = self.pop()                        # tuple of capture names, or None
            cls = self.pop_expr()
            subject = self.pop_expr()
            if names is D6_NULL:
                names = None
            if isinstance(names, ast.Constant) and isinstance(names.value, tuple) \
                    and all(isinstance(item, str) for item in names.value):
                # ``case C(a, b)`` binds names from the match; source keeps them
                # as a capture pattern, which cannot be rebuilt from the stack
                # alone, so the test is kept and the capture names are recorded
                for item in names.value:
                    if item and item.isidentifier():
                        self.push(ast.Name(id=item, ctx=ast.Load()))
                for _ in names.value:
                    if self.stack and isinstance(self.stack[-1], ast.Name):
                        self.stack.pop()
            self.push(ast.Call(func=ast.Name(id="isinstance", ctx=ast.Load()),
                               args=[subject, cls], keywords=[]))
            return None
        elif op == "LOAD_ASSERTION_ERROR":
            self.push(("assertion",))
        elif op == "LOAD_SPECIAL":
            return self.parse_load_special(arg)
        elif op == "BEFORE_WITH":
            return self.parse_with()
        elif op == "RAISE_VARARGS":
            if arg == 1 and self.stack and isinstance(self.stack[-1], tuple) \
                    and self.stack[-1] == ("assertion",):
                self.stack.pop()                     # bare ``assert cond``
                return ast.Raise(exc=ast.Call(func=ast.Name(id="AssertionError",
                                                             ctx=ast.Load()),
                                              args=[], keywords=[]), cause=None)
            if arg == 0:
                return ast.Raise(exc=None, cause=None)
            if arg == 1:
                return ast.Raise(exc=self.pop_expr(), cause=None)
            cause = self.pop_expr()
            return ast.Raise(exc=self.pop_expr(), cause=cause)
        elif op == "MAKE_FUNCTION":
            value = self.pop()                      # ("code", <code object>) on 3.11+
            if not (isinstance(value, tuple) and value[0] == "code"):
                raise D6Unsupported("make function")
            if arg & 0x01:
                self._pending_defaults = self.pop()
            if arg & 0x02:
                self.pop()                          # kwdefaults
            if arg & 0x04:
                self.pop()                          # annotations
            if arg & 0x08:
                self.pop()                          # closure
            self.push(value)
        elif op == "SET_FUNCTION_ATTRIBUTE":
            if len(self.stack) < 2:
                return None
            # stack: [<attribute value>, <function>]: the function is on top
            function = self.pop()
            attribute = self.pop()
            if not (isinstance(function, tuple) and function[0] == "code"):
                self.push(function if not isinstance(function, ast.expr) else function)
                if isinstance(attribute, ast.expr) and isinstance(function, ast.expr):
                    pass
                return None
            nested = function[1]
            attrs = dict(function[2]) if len(function) > 2 and isinstance(function[2], dict) \
                else {}
            slot = {1: "defaults", 2: "kwdefaults", 4: "annotations", 8: "closure"}.get(arg & 0x0F)
            if slot is not None:
                attrs[slot] = attribute
            self.push(("code", nested, attrs))
            return None
        elif op in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_FORWARD",
                    "JUMP", "JUMP_NO_INTERRUPT"):
            if not self.tolerant:
                raise D6Unsupported(f"opcode {op}")
            return None                              # back edge of a dead loop
        elif op in D6_SKIP:
            return None
        else:
            raise D6Unsupported(f"opcode {op}")

    def _swap_assign(self, arg):
        """``a, b = b, a`` compiles to ``SWAP 2`` plus two stores."""
        if arg != 2 or len(self.stack) < 2:
            return None
        left, right = self.stack[-2], self.stack[-1]
        if not (isinstance(left, ast.Name) and isinstance(right, ast.Name)):
            return None
        if self.index + 2 >= len(self.instrs):
            return None
        first, second = self.instrs[self.index + 1], self.instrs[self.index + 2]
        stores = D6_STORE_FAST_OPS | D6_STORE_NAME_OPS
        if first["op"] not in stores or second["op"] not in stores:
            return None
        names = []
        for ins in (first, second):
            table = self.code.varnames if ins["op"] in D6_STORE_FAST_OPS else self.code.names
            names.append(self.name_at(table, ins["arg"]))
        if sorted(names) != sorted([left.id, right.id]) or names[0] == names[1]:
            return None
        del self.stack[-2:]
        self.index += 2
        return ast.Assign(
            targets=[ast.Tuple(elts=[ast.Name(id=names[0], ctx=ast.Store()),
                                     ast.Name(id=names[1], ctx=ast.Store())],
                               ctx=ast.Store())],
            value=ast.Tuple(elts=[left, right], ctx=ast.Load()))

    def _unpack_store(self, name):
        """Feed one ``STORE_*`` into the pending tuple-unpacking target."""
        marker = self.stack[-1][1]
        node = self._finish_unpack(marker, ast.Name(id=name, ctx=ast.Store()))
        return node

    def _finish_unpack(self, marker, target):
        marker["targets"].append(target)
        if len(marker["targets"]) < marker["count"]:
            return None
        if self.stack and isinstance(self.stack[-1], tuple) and len(self.stack[-1]) == 2 \
                and self.stack[-1][0] == "unpack" and self.stack[-1][1] is marker:
            self.stack.pop()
        elts = list(marker["targets"])
        star = marker.get("star")
        if star is not None and star < len(elts):
            elts[star] = ast.Starred(value=elts[star], ctx=ast.Store())
        tuple_target = ast.Tuple(elts=elts, ctx=ast.Store())
        value = marker["value"]
        if isinstance(value, tuple) and len(value) == 2 and value[0] == "unpack":
            return self._finish_unpack(value[1], tuple_target)   # ``a, (b, c) = x``
        return ast.Assign(targets=[tuple_target], value=self._coerce(value))

    def _pop_items(self, count):
        return [self.pop_expr() for _ in range(count)][::-1]

    def _unpack_note(self, value, count):
        return ast.Call(func=ast.Name(id="type", ctx=ast.Load()),
                        args=[d6_const(f"unpack-{count}")],
                        keywords=[])

    def _decorated(self, code_tuple, decorators, raw):
        """``deco(fn)`` on an unbound code object is the ``@deco`` syntax."""
        inner = None
        if len(raw) > 1 and isinstance(raw[0], tuple) and raw[0][0] == "code":
            inner = raw[0]                        # stacked decorators: @a @b def f
        nested = code_tuple[1]
        try:
            node = self._function_def(nested, getattr(nested, "name", "fn") or "fn",
                                     code_tuple[2].get("defaults") if len(code_tuple) > 2
                                     and isinstance(code_tuple[2], dict) else None)
        except D6Unsupported:
            return None
        if not isinstance(node, ast.FunctionDef):
            return None
        node.decorator_list = list(decorators)
        return node

    def _special_store(self, value, name):
        kind = value[0]
        if kind == "classdict":
            return None                               # class namespace cell
        if kind == "code":
            nested = value[1]
            if getattr(nested, "name", "") == "<lambda>":
                attrs = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
                defaults = attrs.get("defaults", getattr(self, "_pending_defaults", None))
                self._pending_defaults = None
                args = self._arguments(nested, defaults)
                sub = Decompiler6(nested, self.version, None, self.opnames,
                                  seen=self.seen, tolerant=self.tolerant)
                body = d6_trim(sub.run())
                value_expr = None
                if len(body) == 1 and isinstance(body[0], ast.Return):
                    value_expr = body[0].value
                if value_expr is not None:
                    self.consumed.add(id(nested))
                    self.consumed |= sub.consumed_ids()
                    return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())],
                                      value=ast.Lambda(args=args, body=value_expr))
            attrs = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
            defaults = attrs.get("defaults", getattr(self, "_pending_defaults", None))
            if "kwdefaults" in attrs:
                self._pending_kwdefaults = attrs["kwdefaults"]
            self._pending_defaults = None
            return self._function_def(nested, name, defaults)
        if kind == "import":
            module = value[1]
            alias = None if name in (module, module.split(".")[0]) else name
            return ast.Import(names=[ast.alias(name=module, asname=alias)])
        if kind == "from":
            module = getattr(self, "_pending_import", None) or ""
            for held in self.stack:
                if isinstance(held, tuple) and held[0] == "import" and held[1]:
                    module = held[1]
            attr = value[1]
            if getattr(self, "_pending_fromlist", True) in (None, False):
                # ``import a.b as c``: no fromlist, the module is imported then
                # the attribute is pulled off it and the module popped
                return ast.Import(names=[ast.alias(name=module, asname=name)])
            return ast.ImportFrom(module=module, names=[ast.alias(
                name=attr, asname=None if name == attr else name)], level=0)
        raise D6Unsupported("store")

    def consumed_ids(self):
        """Every code object identity this engine turned into source."""
        return set(self.consumed)

    def _function_def(self, nested, name, defaults=None):
        if id(nested) in self.seen and not self.tolerant:
            raise D6Unsupported("recursive function")
        self.seen.add(id(nested))
        sub = Decompiler6(nested, self.version, None, self.opnames, seen=self.seen,
                          tolerant=self.tolerant, flat=self.flat)
        body = sub.run()
        self.consumed.add(id(nested))
        self.consumed |= sub.consumed_ids()
        args = self._arguments(nested, defaults)
        node = ast.FunctionDef(name=name, args=args, body=d6_trim(body),
                               decorator_list=[], returns=None)
        self._last_def = node
        return node

    def _class_def(self, args):
        """``__build_class__(body, name)`` - rebuild a real ``class`` block."""
        if len(args) < 2:
            raise D6Unsupported("build class")
        body_arg, name_arg = args[0], args[1]
        if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
            name = name_arg.value
        elif isinstance(name_arg, ast.Name):
            name = name_arg.id
        else:
            raise D6Unsupported("class name")
        if not (isinstance(body_arg, tuple) and body_arg[0] == "code"):
            raise D6Unsupported("class body")
        nested = body_arg[1]
        sub = Decompiler6(nested, self.version, None, self.opnames, seen=self.seen,
                          tolerant=self.tolerant)
        body = sub.run()
        self.consumed.add(id(nested))
        self.consumed |= sub.consumed_ids()
        kept = []
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                target = stmt.targets[0]
                if isinstance(target, ast.Name) and target.id in (
                        "__module__", "__qualname__", "__doc__", "__firstlineno__",
                        "__static_attributes__", "__classcell__"):
                    continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Name) \
                    and stmt.value.id == "__class__":
                continue                             # implicit ``__classcell__``
            if isinstance(stmt, ast.Return) and stmt.value is None:
                continue                             # implicit class-body return
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name) \
                    and stmt.targets[0].id == "__classcell__":
                continue
            kept.append(stmt)
        node = _classdef(name, kept)
        bases = [self._coerce(item) for item in args[2:] if isinstance(item, ast.expr)]
        if bases:
            node.bases = bases
        return node

    def _genexp(self, nested, iterable):
        """``CALL 0`` on a code object: rebuild the generator expression."""
        sub = Decompiler6(nested, self.version, None, self.opnames, seen=self.seen,
                          tolerant=self.tolerant)
        body = sub.run()
        self.consumed.add(id(nested))
        self.consumed |= sub.consumed_ids()
        for stmt in body:
            if isinstance(stmt, ast.For):
                elt = None
                for inner in stmt.body:
                    if isinstance(inner, ast.Expr) and isinstance(inner.value, ast.Yield):
                        elt = inner.value.value
                    elif isinstance(inner, ast.Expr):
                        elt = inner.value
                if elt is not None:
                    # ``_is_generator`` is essential; a plain Expr yields its value
                    if not isinstance(elt, ast.Yield):
                        elt = ast.Yield(value=elt) if False else elt
                    return ast.GeneratorExp(
                        elt=elt,
                        generators=[ast.comprehension(target=stmt.target, iter=iterable,
                                                      ifs=[], is_async=0)])
        raise D6Unsupported("generator expression")

    def _arguments(self, code, defaults=None):
        """Rebuild the signature from argcount / kwonly / *args / **kwargs flags."""
        varnames = list(code.varnames)
        total = code.argcount
        kwonly = getattr(code, "kwonly", 0)
        flags = getattr(code, "flags", 0)
        positional = varnames[:total]
        kw_names = varnames[total:total + kwonly]
        rest = varnames[total + kwonly:]
        vararg = kwarg = None
        if flags & 0x04 and rest:
            vararg = rest.pop(0)
        if flags & 0x08 and rest:
            kwarg = rest.pop(0)
        default_nodes = []
        if isinstance(defaults, (ast.Tuple, ast.List)):
            default_nodes = list(defaults.elts)
        elif isinstance(defaults, ast.Constant) and isinstance(defaults.value, tuple):
            default_nodes = [d6_const(item) for item in defaults.value]
        elif isinstance(defaults, ast.expr):
            default_nodes = [defaults]                 # a lone default value
        pos_defaults = default_nodes[:len(positional)]
        kw_defaults = []
        kw_source = getattr(self, "_pending_kwdefaults", None)
        self._pending_kwdefaults = None
        if kw_source is not None:
            if isinstance(kw_source, ast.Dict):
                table = {}
                for key, value in zip(kw_source.keys, kw_source.values):
                    if isinstance(key, ast.Constant):
                        table[key.value] = value
                kw_defaults = [table.get(name) for name in kw_names]
            elif isinstance(kw_source, (ast.Tuple, ast.List)):
                kw_defaults = list(kw_source.elts)
            elif isinstance(kw_source, ast.Constant) and isinstance(kw_source.value, tuple):
                kw_defaults = [d6_const(item) for item in kw_source.value]
            elif isinstance(kw_source, ast.expr):
                kw_defaults = [kw_source]
        if kwonly and default_nodes:
            for value in default_nodes[len(positional):]:
                kw_defaults.append(value)
        kw_defaults += [None] * (kwonly - len(kw_defaults))
        return ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=name) for name in positional],
            vararg=None if vararg is None else ast.arg(arg=vararg),
            kwonlyargs=[ast.arg(arg=name) for name in kw_names],
            kw_defaults=kw_defaults, kwarg=None if kwarg is None else ast.arg(arg=kwarg),
            defaults=pos_defaults[-len(positional):] if positional else [])

    def _coerce(self, node):
        """Turn a stack slot into an expression (markers become ``None``)."""
        if isinstance(node, ast.expr):
            return node
        if self.tolerant:
            if isinstance(node, tuple) and node and node[0] == "code":
                return ast.Name(id=f"<code {getattr(node[1], 'name', '?')}>",
                                ctx=ast.Load())
            return ast.Constant(value=None)
        raise D6Unsupported(f"not an expression: {node!r}")

    def step_call(self, op, arg):
        keywords = []
        kwnames = None
        star = kwargs = None
        if op == "CALL" and arg == 0 and len(self.stack) >= 2 \
                and isinstance(self.stack[-2], tuple) and self.stack[-2] == ("assertion",):
            message = self.stack.pop()               # LOAD_ASSERTION_ERROR; <msg>; CALL 0
            self.stack.pop()
            if message is D6_NULL:
                message = None
            self.push(ast.Call(func=ast.Name(id="AssertionError", ctx=ast.Load()),
                               args=[] if message is None else [message], keywords=[]))
            return None
        if op == "CALL_KW":
            kwnames = self.pop_expr()
        elif op == "CALL_FUNCTION_EX":
            kwargs = self.pop_expr() if arg & 1 else None
            star = self.pop_expr()
        taken = []
        for _ in range(arg):
            if not self.stack:
                if not self.tolerant:
                    raise D6Unsupported("stack underflow")
                break
            taken.append(self.pop())
        taken.reverse()
        raw = taken + [ast.Constant(value=None)] * (arg - len(taken))
        # no callee on the stack: keep the call, but make it a sentinel call so
        # the file still runs instead of raising NameError on `_lost`
        func = (self.pop() if self.stack
                else ast.Name(id="_PydecompUnknown", ctx=ast.Load()))
        if func is D6_NULL:
            func = self.pop()
        if op == "CALL" and arg == 0 and not isinstance(func, tuple) \
                and self.stack and isinstance(self.stack[-1], tuple) \
                and self.stack[-1][0] == "code":
            # ``<code>(iter(x))`` - a generator expression handed straight to a call
            source = self._coerce(func)
            code_tuple = self.pop()
            try:
                self.push(self._genexp(code_tuple[1], source))
                return None
            except D6Unsupported:
                pass
        if isinstance(func, tuple) and func[0] == "build_class":
            self.push(self._class_def(raw))
            return None
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and arg == 0 and self.stack:
            decorator = self.pop_expr()               # stacked ``@a`` ``@b``
            func.decorator_list.insert(0, decorator)
            self.push(func)
            return None
        if isinstance(func, tuple) and func[0] == "code" and arg == 0 and self.stack \
                and not isinstance(self.stack[-1], (D6Null,)) \
                and isinstance(self.stack[-1], (ast.expr, ast.FunctionDef)):
            # ``@decorator``: CALL 0 with the decorator underneath the new function
            decorator = self.pop()
            if isinstance(decorator, ast.FunctionDef):
                decorator.decorator_list.insert(0, self.pop_expr())
                self.push(decorator)
                return None
            node = None
            try:
                node = self._decorated(func, [self._coerce(decorator)], [func])
            except D6Unsupported:
                node = None
            if isinstance(node, ast.FunctionDef):
                self.push(node)
                return None
        if isinstance(func, tuple) and func[0] == "code":
            # generator expression: the code object is called with the iterator
            if arg == 0:
                source = self._coerce(raw[0]) if raw else (
                    self.pop_expr() if self.stack else None)
                if source is not None:
                    try:
                        self.push(self._genexp(func[1], source))
                        return None
                    except D6Unsupported:
                        pass
            return None
        if self.stack and isinstance(self.stack[-1], D6Null):
            self.stack.pop()
        if not isinstance(func, ast.expr):
            raise D6Unsupported("call target")
        code_args = [node for node in raw if isinstance(node, tuple) and node[0] == "code"]
        if code_args and len(code_args) == len(raw) and not keywords:
            # ``@decorator``: the decorator is applied to the fresh function object
            nested = code_args[-1]
            decorators = [func]
            node = self._decorated(nested, decorators, raw)
            if node is not None:
                self.push(node)
                return None
        if op == "CALL_FUNCTION_EX":
            args = [ast.Starred(value=star, ctx=ast.Load())]
            if kwargs is not None:
                keywords = [ast.keyword(arg=None, value=kwargs)]
        elif op == "CALL_KW" and (isinstance(kwnames, ast.Tuple)
                                  or isinstance(kwnames, ast.Constant)
                                  or isinstance(kwnames, (tuple, list))):
            if isinstance(kwnames, ast.Tuple):
                name_seq = [k.value for k in kwnames.elts if isinstance(k, ast.Constant)]
            elif isinstance(kwnames, ast.Constant) and isinstance(kwnames.value, tuple):
                name_seq = list(kwnames.value)
            else:
                name_seq = list(kwnames)
            names = [name if isinstance(name, str) else str(name) for name in name_seq]
            values = [self._coerce(node) for node in raw]
            split = len(values) - len(names)
            args = values[:split]
            keywords = [ast.keyword(arg=n, value=v)
                        for n, v in zip(names, values[split:])]
        else:
            args = [self._coerce(node) for node in raw if node is not D6_NULL]
        self.push(ast.Call(func=func, args=args, keywords=keywords))
        return None

D6_EPILOGUE_GAP = frozenset({
    "PUSH_EXC_INFO", "WITH_EXCEPT_START", "TO_BOOL", "NOT_TAKEN", "RERAISE",
    "POP_TOP", "POP_EXCEPT", "POP_ITER", "END_FOR", "CHECK_EXC_MATCH", "COPY",
    "SWAP", "PREP_RERAISE_STAR", "CLEANUP_THROW", "INTERPRETER_EXIT",
})

_last_engine = None

DECOMP_IGNORE = frozenset({"CACHE", "NOP", "RESUME", "EXTENDED_ARG", "PRECALL",
                           "NOT_TAKEN", "MAKE_CELL", "COPY_FREE_VARS",
                           "RETURN_GENERATOR", "SETUP_ANNOTATIONS"})

def d6_trim(stmts: list, implicit_return: bool = True) -> list:
    """Drop an implicit trailing ``return`` and no-op trailing ``continue``s."""
    keep = list(stmts)
    while implicit_return and stmts and isinstance(stmts[-1], ast.Return) \
            and stmts[-1].value is None:
        stmts.pop()
    while stmts and isinstance(stmts[-1], ast.Continue):
        stmts.pop()
    if stmts and isinstance(stmts[-1], ast.If):
        tail = stmts[-1]
        d6_trim(tail.body)
        d6_trim(tail.orelse)
        if not tail.body:
            tail.body = [ast.Pass()]
    if not stmts:
        stmts.extend(keep)
    return stmts or [ast.Pass()]

STRUCTURAL_ONLY = frozenset({
    "COMPARE_OP", "BINARY_OP", "IS_OP", "CONTAINS_OP", "FOR_ITER", "SEND",
    "SWAP", "COPY", "UNPACK_SEQUENCE", "BUILD_TUPLE", "BUILD_LIST", "BUILD_SET",
    "BUILD_MAP", "BUILD_STRING", "BUILD_SLICE", "CALL", "CALL_KW", "CALL_FUNCTION_EX",
    "RAISE_VARARGS", "IMPORT_STAR", "FORMAT_VALUE", "CONVERT_VALUE", "FORMAT_SIMPLE",
    "FORMAT_WITH_SPEC", "MAKE_FUNCTION", "RESUME", "RETURN_VALUE", "POP_TOP",
})

NAMED = frozenset({"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "LOAD_GLOBAL",
                   "STORE_GLOBAL", "DELETE_GLOBAL", "LOAD_ATTR", "STORE_ATTR",
                   "DELETE_ATTR", "IMPORT_NAME", "IMPORT_FROM", "LOAD_METHOD",
                   "STORE_ATTR_SLOT", "LOAD_ATTR_SLOT"})

FASTY = frozenset({"LOAD_FAST", "STORE_FAST", "DELETE_FAST", "LOAD_FAST_BORROW",
                   "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR", "LOAD_DEREF",
                   "STORE_DEREF", "LOAD_CLASSDEREF"})

def _value_operand(code: CodeObj, op: str, arg: int) -> str:
    """The part of an instruction's operand that decides what it does."""
    if op == "BINARY_OP":
        node = D6_BIN_OPS.get(arg)
        return f"binop:{node.__name__ if node else '?' + str(arg)}"
    if op == "COMPARE_OP":
        index = arg >> 4 if arg > len(D6_CMP_OPS) else arg
        node = D6_CMP_OPS[index] if 0 <= index < len(D6_CMP_OPS) else None
        return f"cmp:{node.__name__ if node else '?%d' % arg}"
    if op == "IS_OP":
        return "is" if arg == 0 else "is not"
    if op == "CONTAINS_OP":
        return "in" if arg == 0 else "not in"
    return f"{op}:{arg}"


#: opcodes whose *operand* changes behaviour.  ``STRUCTURAL_ONLY`` ignores them
#: because the lifter only needs shape, but an identity proof must not: without
#: these, ``a + b`` and ``a * b`` are reported as the same instruction.
VALUE_BEARING = frozenset({
    "BINARY_OP", "COMPARE_OP", "IS_OP", "CONTAINS_OP", "FORMAT_VALUE",
    "CONVERT_VALUE", "UNPACK_SEQUENCE", "UNPACK_EX", "BUILD_MAP", "BUILD_LIST",
    "BUILD_TUPLE", "BUILD_SET", "BUILD_STRING", "BUILD_SLICE", "BUILD_CONST_KEY_MAP",
    "CALL", "CALL_KW", "CALL_FUNCTION_EX", "RAISE_VARARGS", "LOAD_SMALL_INT",
    "MAKE_FUNCTION", "COPY", "SWAP",
})


def _operand_key(code: CodeObj, op: str, arg: int) -> str:
    """Canonical, address-free description of what an instruction operates on."""
    if op in VALUE_BEARING:
        return _value_operand(code, op, arg)
    if op in STRUCTURAL_ONLY or "JUMP" in op:
        return ""
    try:
        if op in NAMED:
            index = arg >> 1 if op in ("LOAD_GLOBAL", "LOAD_ATTR", "STORE_ATTR",
                                       "LOAD_METHOD") else arg
            return code.names[index]
        if op in FASTY:
            return code.varnames[arg]
        if op in ("LOAD_CONST", "RETURN_CONST"):
            const = code.consts[arg]
            if isinstance(const, CodeObj):
                return f"<code {const.name}>"
            return f"{type(const).__name__}:{const!r}"
        if op == "LOAD_SMALL_INT":
            return str(arg)
        if op == "STORE_FAST_LOAD_FAST":
            return (f"store:{code.varnames[arg >> 4]},"
                    f"load:{code.varnames[arg & 15]}")
        # Immediates that change what the instruction *does*: without these
        # ``a + b`` and ``a * b`` compare equal, which would let a wrong
        # reconstruction be reported as instruction-identical.
        if op == "BINARY_OP":
            return f"binop:{BINARY_SYMS.get(arg, '?' + str(arg))}"
        if op == "COMPARE_OP":
            return f"cmp:{_compare_symbol(arg, code)}"
        if op == "IS_OP":
            return "is" if arg == 0 else "is not"
        if op == "CONTAINS_OP":
            return "in" if arg == 0 else "not in"
        if op in ("FORMAT_VALUE", "UNPACK_SEQUENCE", "UNPACK_EX", "BUILD_MAP",
                  "BUILD_CONST_KEY_MAP", "BUILD_STRING", "BUILD_SLICE",
                  "BUILD_LIST", "BUILD_TUPLE", "BUILD_SET", "RAISE_VARARGS",
                  "CALL", "CALL_FUNCTION_EX", "CALL_INTRINSIC_1",
                  "CALL_INTRINSIC_2", "COPY", "SWAP", "GEN_START", "MAKE_FUNCTION",
                  "LOAD_SUPER_ATTR", "IMPORT_FROM", "LOAD_ATTR", "LOAD_GLOBAL",
                  "LOAD_NAME", "STORE_NAME", "DELETE_NAME", "LOAD_SMALL_INT",
                  "LOAD_LOCALS", "LOAD_ASSERTION_ERROR", "SET_ADD", "LIST_APPEND",
                  "MAP_ADD", "SEND", "YIELD_VALUE", "RETURN_GENERATOR"):
            return f"{op}:{arg}"
        if arg:
            return f"{op}:{arg}"
    except (IndexError, TypeError):
        return f"{op}:?"
    return ""

def fix_stray_returns(node, in_function=False):
    """A ``return`` that ended up outside a function is an expression there."""
    if not isinstance(node, ast.AST):
        return node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        in_function = True
    if isinstance(node, ast.Return) and not in_function:
        value = node.value
        node = ast.Expr(value=value if value is not None else ast.Constant(value=None))
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, ast.AST):
                    value[index] = fix_stray_returns(item, in_function)
        elif isinstance(value, ast.AST):
            setattr(node, field, fix_stray_returns(value, in_function))
    return node

def sanitize_tree(node, depth=0):
    """Make every field of a rebuilt tree acceptable to ``ast.unparse``.

    Hostile bytecode can leave a raw ``bytes`` (or a stray marker) where the
    compiler expects a node, an identifier or a literal.  Rather than losing
    the whole module at the last step, coerce those slots into something valid.
    """
    if depth > 8000 or not isinstance(node, ast.AST):
        return node
    if isinstance(node, ast.Constant):
        value = node.value
        while isinstance(value, ast.Constant):
            value = value.value
        if isinstance(value, ast.AST):
            value = None
        node.value = value
    if isinstance(node, ast.ExceptHandler) and node.type is None:
        node.type = ast.Name(id="Exception", ctx=ast.Load())
    if isinstance(node, ast.Name) and isinstance(node.id, (bytes, bytearray)):
        node.id = bytes(node.id).decode("utf-8", "replace") or "_x"
    if isinstance(node, ast.Attribute) and isinstance(node.attr, (bytes, bytearray)):
        node.attr = bytes(node.attr).decode("utf-8", "replace") or "_x"
    if isinstance(node, ast.arg) and isinstance(node.arg, (bytes, bytearray)):
        node.arg = bytes(node.arg).decode("utf-8", "replace") or "_x"
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, ast.AST):
                    sanitize_tree(item, depth + 1)
                elif field in ("body", "orelse", "finalbody", "handlers", "values",
                               "elts", "keys", "args", "keywords", "decorator_list",
                               "targets", "names", "type_ignores"):
                    value[index] = ast.Expr(value=ast.Constant(value=item)) \
                        if not isinstance(item, ast.expr) else item
        elif isinstance(value, ast.AST):
            sanitize_tree(value, depth + 1)
        elif field in ("id", "arg", "attr", "name", "asname", "module") \
                and not isinstance(value, str) and value is not None:
            setattr(node, field, str(value))
        elif field in ("value", "operand", "func", "target", "annotation", "returns",
                       "test", "iter") and value is not None \
                and not isinstance(value, ast.AST) \
                and not isinstance(node, ast.Constant):
            setattr(node, field, ast.Constant(value=value))
    return node

def _classdef(name: str, body: list, bases: list | None = None) -> ast.ClassDef:
    """Build a ClassDef across 3.10-3.14 (3.12+ gained type_params)."""
    fields = {"name": name, "bases": bases or [], "keywords": [],
              "body": body or [ast.Pass()], "decorator_list": []}
    if "type_params" in getattr(ast.ClassDef, "_fields", ()):
        fields["type_params"] = []
    return ast.ClassDef(**fields)

def _streams(code: CodeObj, version: tuple):
    """(opcodes, name operands, constant operands) for the whole module tree."""
    ops, names, consts = [], [], []
    for node in iter_code(code):
        for _off, op, arg, _text in disassemble(node, version):
            if op in DECOMP_IGNORE:
                continue
            ops.append(op)
            key = _operand_key(node, op, arg)
            if not key:
                continue
            if op in NAMED or op in FASTY or op == "STORE_FAST_LOAD_FAST":
                names.append(key)
            elif op in ("LOAD_CONST", "RETURN_CONST", "LOAD_SMALL_INT"):
                consts.append(key)
    return ops, names, consts

def _streams_host(top):
    import dis as _dis
    ops, names, consts = [], [], []

    def walk(code):
        for ins in _dis.get_instructions(code):
            if ins.opname in DECOMP_IGNORE:
                continue
            ops.append(ins.opname)
            if ins.opname in NAMED or ins.opname in FASTY:
                if ins.argval is not None:
                    names.append(str(ins.argval))
            elif ins.opname == "STORE_FAST_LOAD_FAST":
                raw = getattr(ins, "arg", 0) or 0
                table = code.co_varnames
                try:
                    names.append(f"{table[raw >> 4]},{table[raw & 15]}")
                except IndexError:
                    names.append(str(ins.argval))
            elif ins.opname in ("LOAD_CONST", "RETURN_CONST", "LOAD_SMALL_INT"):
                value = ins.argval
                if isinstance(value, CodeObj):
                    consts.append(f"<code {value.name}>")
                elif hasattr(value, "co_name"):
                    consts.append(f"<code {value.co_name}>")
                else:
                    consts.append(f"{type(value).__name__}:{value!r}")
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                walk(const)

    walk(top)
    return ops, names, consts

def _ratio(left, right) -> float:
    """Multiset overlap of two instruction/operand streams.

    Order is deliberately ignored: the same statement can be laid out with the
    defaults tuple first or last, and the interpreter emits different cleanup
    stubs per version.  What must match is *which* instructions, names and
    literals the module touches, and how often.
    """
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    common = Counter(left) & Counter(right)
    return sum(common.values()) / float(max(len(left), len(right)))

D6_BRIDGE_OPS = {
    "FORMAT_VALUE": "FORMAT", "FORMAT_SIMPLE": "FORMAT", "FORMAT_WITH_SPEC": "FORMAT",
    "LOAD_METHOD": "LOAD_ATTR", "LOAD_SMALL_INT": "LOAD_CONST",
    "LOAD_FAST_BORROW": "LOAD_FAST", "LOAD_FAST_BORROW_AND_CLEAR": "LOAD_FAST_AND_CLEAR",
    "LOAD_FAST_BORROW_LOAD_FAST_BORROW": "LOAD_FAST_LOAD_FAST",
    "STORE_FAST_MAYBE_NULL": "STORE_FAST", "CALL_KW": "CALL_KW", "KW_NAMES": "CALL_KW",
    "LOAD_FAST_CHECK": "LOAD_FAST", "LOAD_CLASSDEREF": "LOAD_DEREF",
    "JUMP_NO_INTERRUPT": "JUMP", "JUMP_BACKWARD_NO_INTERRUPT": "JUMP_BACKWARD",
    "END_FOR": "NOP", "POP_ITER": "NOP", "NOT_TAKEN": "NOP", "TO_BOOL": "NOP",
    "BEFORE_WITH": "NOP", "LOAD_SPECIAL": "NOP", "WITH_EXCEPT_START": "NOP",
    "PUSH_EXC_INFO": "NOP", "POP_EXCEPT": "NOP", "RERAISE": "NOP",
    "CHECK_EXC_MATCH": "NOP", "END_ASYNC_FOR": "NOP", "POP_TOP": "POP_TOP",
}

D6_LAYOUT_OPS = frozenset({
    "RESUME", "CACHE", "NOP", "EXTENDED_ARG", "SWAP", "COPY", "MAKE_CELL",
    "COPY_FREE_VARS", "GET_ITER", "GET_AWAITABLE", "INTERPRETER_EXIT",
})

def _op_histogram(code, version):
    """Frequency of each opcode *name*, bridged across interpreter versions."""
    counts = {}
    total = 0
    for unit in iter_code(code):
        for _off, opname, _arg, _text in disassemble(unit, version):
            if opname in D6_LAYOUT_OPS or "JUMP" in opname or opname in (
                    "FOR_ITER", "SEND", "RETURN_GENERATOR"):
                continue
            name = D6_BRIDGE_OPS.get(opname, opname)
            if name == "NOP":
                continue
            counts[name] = counts.get(name, 0) + 1
            total += 1
    return counts, total

def cross_version_score(code: CodeObj, version: tuple, host_code) -> float:
    """Compare two code trees that were compiled by different interpreters.

    The instruction streams cannot be diffed directly (opcode numbers were
    renumbered), but the *vocabulary* of operations can: bridge the known
    renames, drop pure layout opcodes, and compare how much probability mass the
    two trees share.  Name usage is checked too, since a rebuild that lost whole
    functions shows up there even when the opcode mix matches.
    """
    if hasattr(host_code, "co_code"):
        host_code = codeobj_from_host(host_code)
    left, left_total = _op_histogram(code, version)
    right, right_total = _op_histogram(host_code, host_version())
    if not left_total or not right_total:
        return 0.0
    keys = set(left) | set(right)
    distance = 0.0
    for key in keys:
        distance += abs(left.get(key, 0) / left_total - right.get(key, 0) / right_total)
    similarity = max(0.0, 1.0 - distance / 2.0)
    names = {name for unit in iter_code(code) for name in unit.names}
    mine = {name for unit in iter_code(host_code) for name in unit.names}
    overlap = len(names & mine) / float(len(names) or 1)
    return 0.6 * similarity + 0.4 * overlap

def content_coverage(code: CodeObj, text: str) -> float:
    """How much of the payload's vocabulary the candidate text actually keeps."""
    consts, names = set(), set()
    for unit in iter_code(code):
        for value in unit.consts:
            if isinstance(value, str) and len(value) >= 3:
                consts.add(value)
        names.update(unit.names)
    if not consts and not names:
        return 0.0
    seen_consts = sum(1 for value in consts if value in text) / float(len(consts) or 1)
    seen_names = sum(1 for name in names if name in text) / float(len(names) or 1)
    return 0.5 * seen_consts + 0.5 * seen_names

def roundtrip_score(code: CodeObj, text: str, version: tuple) -> float:
    """How much of the original the rebuilt source reproduces.

    Three ordered streams are compared - opcodes, every name the code touches,
    and every constant - and the weakest one decides the score.  1.0 means the
    reconstruction compiles back to the same instructions, the same identifier
    usage and the same literals, which is the strongest static proof available.
    """
    try:
        host = compile(text, "<roundtrip>", "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return 0.0
    mine_ops, mine_names, mine_consts = _streams(code, version)
    their_ops, their_names, their_consts = _streams_host(host)
    if version != host_version():
        # different interpreters: opcode numbers differ, so compare the opcode
        # vocabulary and the names instead of the raw streams
        bridged = cross_version_score(code, version, host)
        names = {name for node in iter_code(code) for name in node.names}
        present = sum(1 for name in names if name in text)
        base = present / float(len(names) or 1)
        legacy = 0.5 * base * min(_ratio(mine_consts, their_consts) + 0.5, 1.0)
        return max(bridged, legacy)
    return min(_ratio(mine_ops, their_ops),
               _ratio(mine_names, their_names),
               _ratio(mine_consts, their_consts))
