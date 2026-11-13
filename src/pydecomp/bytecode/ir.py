"""pydecomp - the SSA intermediate representation.

Every decompiler in this space walks the stack: push, pop, print a line.  That
works until control flow joins, because a stack walk has no way to say *which*
x an `x` is when two paths met.  SSA fixes that by construction - every value is
defined exactly once, and a join gets a phi node that names both inputs.

The IR below is the contract between the builder (bytecode → IR) and the emitter
(IR → AST).  It is deliberately small: a value, an instruction, a block, a
function.  Nothing in it is version-specific, which is the point - the builder
translates opcode *names*, so 3.8 and 3.15 arrive here as the same shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SSAValue:
    """A value defined exactly once, somewhere in this function."""

    id: int
    #: "const" | "arg" | "local" | "expr" | "phi" | "call_result" | "unknown"
    source: str
    #: "str" | "int" | "bytes" | "code_object" | "unknown"
    type_hint: str = "unknown"
    #: for a const, the value itself
    const: Any = None
    #: for an expr, a tuple tree: ("binop", "+", left, right) and friends
    expr: Any = None
    #: for a phi, the ids it chooses between
    phi_inputs: tuple = ()
    #: the name this value came from, when it has one
    name: str = ""

    def __str__(self) -> str:                        # pragma: no cover - display
        return f"v{self.id}"


@dataclass
class IRInstr:
    """One IR instruction.  ``op`` is version-neutral, unlike a bytecode name."""

    op: str
    args: tuple = ()
    result: SSAValue | None = None
    #: bytecode offset this came from, so every line stays traceable to the file
    origin: int = 0


@dataclass
class BasicBlock:
    id: int
    instructions: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    #: bytecode offsets this block covers, inclusive
    start: int = 0
    end: int = 0
    #: which local versions enter the block, after phi insertion
    inputs: dict = field(default_factory=dict)

    def add(self, instr: IRInstr) -> None:
        self.instructions.append(instr)

    def __repr__(self) -> str:                       # pragma: no cover - display
        return f"<block {self.id} [{self.start}..{self.end}] -> {self.successors}>"


@dataclass
class FunctionIR:
    """One code object, lifted to SSA form."""

    name: str = "<module>"
    entry: int = 0
    blocks: dict = field(default_factory=dict)
    order: list = field(default_factory=list)        # block ids in bytecode order
    values: dict = field(default_factory=dict)       # id -> SSAValue
    version: tuple = (3, 13)
    #: local name -> the SSA value that leaves the function (for emission)
    exits: dict = field(default_factory=dict)

    # -- construction ------------------------------------------------------
    def block(self, bid: int, start: int = 0, end: int = 0) -> BasicBlock:
        block = self.blocks.get(bid)
        if block is None:
            block = BasicBlock(id=bid, start=start, end=end)
            self.blocks[bid] = block
            self.order.append(bid)
        return block

    def value(self, source: str, **kw) -> SSAValue:
        ident = len(self.values)
        hint = kw.pop("type_hint", "unknown")
        value = SSAValue(id=ident, source=source, type_hint=hint, **kw)
        self.values[ident] = value
        return value

    # -- inspection --------------------------------------------------------
    def successors(self, bid: int) -> list:
        return self.blocks[bid].successors

    def predecessors(self, bid: int) -> list:
        return self.blocks[bid].predecessors

    def reachable(self) -> set:
        seen, stack = set(), [self.entry]
        while stack:
            bid = stack.pop()
            if bid in seen or bid not in self.blocks:
                continue
            seen.add(bid)
            stack.extend(self.blocks[bid].successors)
        return seen

    def dominators(self) -> dict:
        """Cooper/Harvey/Kennedy dominator sets, iterated to a fixpoint."""
        reach = self.reachable()
        order = [bid for bid in self.order if bid in reach]
        dom = {bid: set(order) for bid in order}
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for bid in order:
                if bid == self.entry:
                    continue
                preds = [p for p in self.blocks[bid].predecessors if p in reach]
                if not preds:
                    continue
                shared = set(dom[preds[0]])
                for pred in preds[1:]:
                    shared &= dom[pred]
                new = shared | {bid}
                if new != dom[bid]:
                    dom[bid] = new
                    changed = True
        return dom

    def back_edges(self) -> list:
        """(tail, head) pairs where the head dominates the tail: the loops."""
        dom = self.dominators()
        edges = []
        for bid in self.blocks:
            for succ in self.blocks[bid].successors:
                # a back edge points at a block that dominates its own tail
                if succ in dom.get(bid, set()):
                    edges.append((bid, succ))
        return edges

    def stats(self) -> dict:                         # pragma: no cover - display
        return {"blocks": len(self.blocks), "values": len(self.values),
                "instructions": sum(len(b.instructions) for b in self.blocks.values()),
                "loops": len(self.back_edges())}
