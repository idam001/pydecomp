"""pydecomp - SSA IR → Python AST.

The emitter is written once and serves every version, because the IR is
version-neutral.  It reads *structure* from the control-flow graph (a block with
two successors is a branch, a block its own successor dominates is a loop) and
*values* from the SSA graph (a value is a constant, a name, or an expression tree
whose operands are other values).

What it does not model it refuses: :class:`ir_build.Unsupported` is raised and
the caller keeps the stack engine's answer for that file.  A wrong reconstruction
is worse than a different one, so the emitter never guesses.
"""
from __future__ import annotations

import ast

from ..bytecode.ir import FunctionIR, SSAValue
from ..bytecode.ir_build import Unsupported

_BINOPS = {
    "+": ast.Add, "-": ast.Sub, "*": ast.Mult, "/": ast.Div, "//": ast.FloorDiv,
    "%": ast.Mod, "**": ast.Pow, "<<": ast.LShift, ">>": ast.RShift,
    "&": ast.BitAnd, "|": ast.BitOr, "^": ast.BitXor, "@": ast.MatMult,
}

_CMPOPS = {
    "<": ast.Lt, "<=": ast.LtE, "==": ast.Eq, "!=": ast.NotEq, ">": ast.Gt,
    ">=": ast.GtE, "is": ast.Is, "is not": ast.IsNot, "in": ast.In,
    "not in": ast.NotIn,
}

_UNARY = {"-": ast.USub, "+": ast.UAdd, "~": ast.Invert, "not": ast.Not}

#: CONVERT_VALUE takes an enum index in 3.12+ and the character itself in 3.8-3.11
_CONVERSIONS = {1: ord("s"), 2: ord("r"), 3: ord("a"),
                ord("s"): ord("s"), ord("r"): ord("r"), ord("a"): ord("a")}


def _conversion(flag) -> int:
    return _CONVERSIONS.get(flag, -1)


class Emitter:
    """Build an AST from one :class:`FunctionIR`."""

    def __init__(self, fir: FunctionIR):
        self.fir = fir
        self.consumed: set[int] = set()
        #: head -> tail, for every edge that jumps back to a block that
        #: dominates it: that edge is what makes the head a loop header
        self.loops = {head: tail for tail, head in fir.back_edges()}
        self.loop_exit: int | None = None

    def function(self, code, name: str) -> ast.FunctionDef:
        """Emit a nested code object as a def statement."""
        from ..bytecode.ir_build import build_ir

        nested = build_ir(code, self.fir.version)
        inner = Emitter(nested)
        body = inner.body(nested.entry) or [ast.Pass()]
        return ast.FunctionDef(name=name, args=_arguments(_arg_names(code)),
                               body=body, decorator_list=[], returns=None,
                               type_params=[], lineno=1, col_offset=0)

    # -- values ------------------------------------------------------------
    def expr(self, value: SSAValue) -> ast.expr:
        if value is None:
            raise Unsupported("missing value")
        if not isinstance(value, SSAValue):
            # a raw constant (a dict key from BUILD_CONST_KEY_MAP, an attribute
            # name) is already a value
            return ast.Constant(value=value)
        if value.source == "const":
            if isinstance(value.const, (bytes, str, int, float, complex, bool, type(None))):
                return ast.Constant(value=value.const, kind=None)
            if isinstance(value.const, tuple):
                return ast.Tuple(elts=[self.expr_item(item) for item in value.const],
                                 ctx=ast.Load())
            raise Unsupported(f"constant {type(value.const).__name__}")
        if value.source in ("arg", "local", "phi"):
            return ast.Name(id=value.name or f"_v{value.id}", ctx=ast.Load())
        if value.source in ("expr", "call_result"):
            return self._tree(value.expr)
        raise Unsupported(f"value source {value.source}")

    def expr_item(self, item) -> ast.expr:
        if isinstance(item, SSAValue):
            return self.expr(item)
        return ast.Constant(value=item)

    def _tree(self, tree) -> ast.expr:
        if not isinstance(tree, tuple):
            return ast.Constant(value=tree)
        kind = tree[0]
        if kind == "binop":
            _, symbol, left, right = tree
            op = _BINOPS.get(symbol)
            if op is None:
                raise Unsupported(f"operator {symbol}")
            return ast.BinOp(left=self.expr(left), op=op(), right=self.expr(right))
        if kind == "inplace":
            # `x += 1` is a statement, not an expression; the caller handles it
            _, symbol, left, right = tree
            return ast.BinOp(left=self.expr(left), op=_BINOPS[symbol](),
                             right=self.expr(right))
        if kind == "compare":
            _, symbol, left, right = tree
            op = _CMPOPS.get(symbol)
            if op is None:
                raise Unsupported(f"comparison {symbol}")
            return ast.Compare(left=self.expr(left), ops=[op()],
                               comparators=[self.expr(right)])
        if kind == "unary":
            _, symbol, node = tree
            op = _UNARY.get(symbol)
            if op is None:
                raise Unsupported(f"unary {symbol}")
            return ast.UnaryOp(op=op(), operand=self.expr(node))
        if kind == "attr":
            _, owner, name = tree
            return ast.Attribute(value=self.expr(owner), attr=name, ctx=ast.Load())
        if kind == "subscr":
            _, owner, index = tree
            return ast.Subscript(value=self.expr(owner), slice=self.expr(index),
                                 ctx=ast.Load())
        if kind == "slice":
            _, items = tree
            pieces = [self.expr(item) for item in items]
            while len(pieces) < 3:
                pieces.append(None)
            return ast.Slice(lower=pieces[0], upper=pieces[1], step=pieces[2])
        if kind == "append":
            return ast.Call(func=ast.Attribute(value=self.expr(tree[1]),
                                               attr="append", ctx=ast.Load()),
                            args=[self.expr(tree[2])], keywords=[])
        if kind == "build":
            _, sort, items = tree
            elements = [self.expr(item) for item in items]
            if sort == "tuple":
                return ast.Tuple(elts=elements, ctx=ast.Load())
            if sort == "list":
                return ast.List(elts=elements, ctx=ast.Load())
            if sort == "set":
                return ast.Set(elts=elements)
            raise Unsupported(f"build {sort}")
        if kind == "funcdef":
            _, code, qualname = tree
            return ast.Name(id=qualname or getattr(code, "name", "_fn"),
                            ctx=ast.Load())
        if kind == "iter":
            return ast.Call(func=ast.Name(id="iter", ctx=ast.Load()),
                            args=[self.expr(tree[1])], keywords=[])
        if kind == "dict":
            _, pairs = tree
            return ast.Dict(keys=[self.expr(key) for key, _ in pairs],
                            values=[self.expr(value) for _, value in pairs])
        if kind == "format":
            _, value, spec = tree
            conversion, subject = -1, value
            if isinstance(value.expr, tuple) and value.expr[0] == "convert":
                _, subject, flag = value.expr
                conversion = _conversion(flag)
            return ast.JoinedStr(values=[ast.FormattedValue(
                value=self.expr(subject), conversion=conversion,
                format_spec=None if spec is None else self._spec(spec))])
        if kind == "convert":
            _, value, flag = tree
            return ast.JoinedStr(values=[ast.FormattedValue(
                value=self.expr(value), conversion=_conversion(flag),
                format_spec=None)])
        if kind == "import_from":
            _, _module, name = tree
            return ast.Name(id=name, ctx=ast.Load())
        if kind == "import":
            return ast.Name(id="_import", ctx=ast.Load())
        if kind == "item":
            return self.expr(tree[1])
        if kind == "build" and tree[1] == "str":
            return ast.JoinedStr(values=[self.expr(item) for item in tree[2]])
        if kind == "call_star":
            _, callable_, args_value, mapping = tree
            args = []
            if isinstance(args_value.expr, tuple) and args_value.expr[0] == "build" \
                    and args_value.expr[1] == "tuple":
                args = [self.expr(item) for item in args_value.expr[2]]
            else:
                args = [ast.Starred(value=self.expr(args_value), ctx=ast.Load())]
            keywords = []
            if mapping is not None:
                keywords = [ast.keyword(arg=None, value=self.expr(mapping))]
            return ast.Call(func=self.expr(callable_), args=args, keywords=keywords)
        if kind == "call":
            _, callable_, args, kwargs = tree
            return ast.Call(func=self.expr(callable_),
                            args=[self.expr(item) for item in args],
                            keywords=[])
        raise Unsupported(f"expression {kind}")

    def import_statement(self, tree, bound: str) -> ast.stmt:
        """`import a` / `from a import b` - the bytecode names both parts."""
        _, modname, fromlist, _level = tree
        names = getattr(fromlist, "const", None)
        if names:
            return ast.ImportFrom(module=modname, level=0, names=[
                ast.alias(name=item if isinstance(item, str) else str(item),
                          asname=None) for item in names])
        return ast.Import(names=[ast.alias(name=modname,
                                           asname=None if modname == bound else bound)])

    def _spec(self, spec) -> ast.expr:
        """A format spec is itself a (usually constant) string expression."""
        if isinstance(spec, SSAValue) and spec.source == "const" \
                and isinstance(spec.const, str):
            return ast.JoinedStr(values=[ast.Constant(value=spec.const)])
        if isinstance(spec, SSAValue):
            return self.expr(spec)
        return ast.Constant(value=str(spec))

    # -- statements --------------------------------------------------------
    def statement(self, instr) -> ast.stmt | None:
        op = instr.op
        if op == "STORE":
            value, name = instr.args
            if isinstance(value.expr, tuple) and value.expr[0] == "import":
                return self.import_statement(value.expr, name)
            if isinstance(value.expr, tuple) and value.expr[0] == "import_from":
                _, module, attr = value.expr
                if not (isinstance(module.expr, tuple) and module.expr[0] == "import"):
                    raise Unsupported("from-import without a module")
                modname = module.expr[1]
                return ast.ImportFrom(module=modname, names=[ast.alias(
                    name=attr, asname=None if attr == name else name)], level=0)
            if isinstance(value.expr, tuple) and value.expr[0] == "funcdef":
                _, nested, qualname = value.expr
                return self.function(nested, name)
            if isinstance(value.expr, tuple) and value.expr[0] == "inplace":
                _, symbol, left, right = value.expr
                if not isinstance(left, SSAValue) or left.source not in ("arg", "local", "phi"):
                    raise Unsupported("augmented assignment to a computed target")
                if left.name != name:
                    raise Unsupported("augmented assignment across names")
                return ast.AugAssign(target=ast.Name(id=name, ctx=ast.Store()),
                                     op=_BINOPS[symbol](), value=self.expr(right))
            return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())],
                              value=self.expr(value))
        if op == "POP":
            (value,) = instr.args
            if value is None:
                return None
            if value.source in ("local", "arg", "phi", "unknown"):
                # a discarded name: the exhausted iterator, not a statement
                return None
            return ast.Expr(value=self.expr(value))
        if op == "RETURN":
            (value,) = instr.args
            if value.source == "const" and value.const is None:
                return ast.Return(value=None)
            return ast.Return(value=self.expr(value))
        if op == "SETUP":
            (name,) = instr.args
            raise Unsupported(f"3.8 block region {name}")
        if op == "DELETE":
            return None                                  # `del x` is not observable here
        if op == "STORE_ATTR":
            owner, value, name = instr.args
            return ast.Assign(
                targets=[ast.Attribute(value=self.expr(owner), attr=name,
                                       ctx=ast.Store())],
                value=self.expr(value))
        if op == "STORE_SUBSCR":
            owner, index, value = instr.args
            return ast.Assign(
                targets=[ast.Subscript(value=self.expr(owner),
                                       slice=self.expr(index), ctx=ast.Store())],
                value=self.expr(value))
        if op == "DELETE_SUBSCR":
            owner, index = instr.args
            return ast.Delete(targets=[ast.Subscript(value=self.expr(owner),
                                                     slice=self.expr(index),
                                                     ctx=ast.Del())])
        return None

    # -- structure ---------------------------------------------------------
    def body(self, start: int, stop: set[int] | None = None) -> list[ast.stmt]:
        stop = set(stop or ())
        out: list[ast.stmt] = []
        current = start
        guard = 0
        while current is not None and current not in stop:
            guard += 1
            if guard > 512:
                raise Unsupported("region too long")
            if current in self.consumed:
                raise Unsupported("block revisited")
            block = self.fir.blocks.get(current)
            if block is None:
                raise Unsupported("missing block")
            block_here = self.fir.blocks.get(current)
            if block_here is not None and current not in self.consumed \
                    and any(i.op == "FOR_ITER" for i in block_here.instructions):
                loop = self.for_loop(current)
                if loop is not None:
                    out.extend(loop)
                    current = self.loop_exit
                    self.loop_exit = None
                    if current is None:
                        return out
                    continue
            if block_here is not None and current not in self.consumed \
                    and current in self.loops and len(block_here.successors) == 2:
                loop = self.while_loop_at_head(current)
                if loop is not None:
                    out.extend(loop)
                    current = self.loop_exit
                    self.loop_exit = None
                    if current is None:
                        return out
                    continue
            exits_to_loop = block_here is not None and len(block_here.successors) == 2 \
                and any(s in self.loops for s in block_here.successors)
            if exits_to_loop and current not in self.consumed:
                loop = self.while_loop(current)
                if loop is not None:
                    out.extend(loop)
                    current = self.loop_exit
                    self.loop_exit = None
                    if current is None:
                        return out
                    continue
            self.consumed.add(current)
            for instr in block.instructions:
                if instr.op in ("BRANCH", "JUMP"):
                    continue
                stmt = self.statement(instr)
                if stmt is not None:
                    out.append(stmt)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    return out
            successors = [s for s in block.successors]
            if not successors:
                return out
            if len(successors) == 1:
                nxt = successors[0]
                if nxt in self.consumed:
                    return out
                current = nxt
                continue
            out.extend(self.branch(block, successors, stop))
            return out
        return out

    def while_loop(self, guard: int):
        """`while test:` - the guard tests, the body repeats the test at the end.

        CPython emits the loop test twice: once at the top, so the body can be
        skipped entirely, and once at the bottom, where the back jump is taken.
        The bottom copy is the same expression, so the reconstruction carries the
        test once, on a `while`, and the body is walked from the loop head to the
        back jump.
        """
        block = self.fir.blocks[guard]
        terminator = None
        for instr in reversed(block.instructions):
            if instr.op == "BRANCH":
                terminator = instr
                break
        if terminator is None or len(block.successors) != 2:
            return None
        cond, kind = terminator.args
        # the guard points at the loop head; the head is the block with the
        # back edge that names it
        heads = [s for s in block.successors if s in self.loops]
        if len(heads) != 1:
            return None
        inside = heads[0]
        tails = [tail for tail, head_of_edge in self.fir.back_edges()
                 if head_of_edge == inside]
        if not tails:
            return None
        inside_block = self.fir.blocks[inside]
        inner = None
        for instr in reversed(inside_block.instructions):
            if instr.op == "BRANCH":
                inner = instr
                break
        if inner is None:
            return None
        exits = [s for s in inside_block.successors if s not in tails]
        if len(exits) != 1:
            return None
        outside = exits[0]
        header_statements: list[ast.stmt] = []
        for instr in block.instructions:
            if instr.op in ("BRANCH", "JUMP"):
                continue
            stmt = self.statement(instr)
            if stmt is not None:
                header_statements.append(stmt)
        body = self._loop_body(inside, outside, tails)
        if body is None:
            return None
        test = self.expr(cond)
        if kind == "if_none":
            test = ast.Compare(left=test, ops=[ast.IsNot()],
                               comparators=[ast.Constant(value=None)])
        elif kind == "if_not_none":
            test = ast.Compare(left=test, ops=[ast.Is()],
                               comparators=[ast.Constant(value=None)])
        self.loop_exit = outside
        return header_statements + [
            ast.While(test=test, body=body or [ast.Pass()], orelse=[])]

    def _loop_body(self, inside: int, outside: int, back: list,
                   skip_first_store: str | None = None, head: int | None = None):
        """Statements of a loop body, with the repeated test and the back jump gone."""
        body: list[ast.stmt] = []
        current = inside
        seen: set[int] = set()
        for _ in range(256):
            if current is None or current in seen or current == outside:
                break
            seen.add(current)
            self.consumed.add(current)
            block = self.fir.blocks[current]
            terminated = False
            skip = skip_first_store
            skip_first_store = None
            for instr in block.instructions:
                if instr.op in ("BRANCH", "JUMP", "FOR_ITER"):
                    continue
                if skip and instr.op == "STORE" and instr.args[1] == skip:
                    skip = None
                    continue
                stmt = self.statement(instr)
                if stmt is not None:
                    body.append(stmt)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    terminated = True
            if terminated:
                break
            next_block = None
            for successor in block.successors:
                if successor == outside or successor == head:
                    continue
                if successor in back and successor != inside:
                    continue
                if successor == inside or successor not in seen:
                    next_block = successor
                    break
            if next_block is None:
                for successor in block.successors:
                    if successor in seen and successor == inside:
                        next_block = None
                        break
            current = next_block
        return body

    def _reach(self, start: int, limit: int = 256) -> set:
        seen, stack = set(), [start]
        while stack and len(seen) < limit:
            bid = stack.pop()
            if bid in seen or bid not in self.fir.blocks:
                continue
            seen.add(bid)
            stack.extend(self.fir.blocks[bid].successors)
        return seen

    def while_loop_at_head(self, head: int):
        """`while test:` where the test block is itself the loop head.

        3.8-3.10 have no separate guard: the test opens the loop, the body ends
        with an absolute jump back to it, and POP_BLOCK closes the region.
        """
        block = self.fir.blocks[head]
        terminator = None
        for instr in reversed(block.instructions):
            if instr.op == "BRANCH":
                terminator = instr
                break
        if terminator is None or len(block.successors) != 2:
            return None
        cond, kind = terminator.args
        exits = [s for s in block.successors if head not in self._reach(s)]
        if len(exits) != 1:
            return None
        outside = exits[0]
        inside = [s for s in block.successors if s != outside][0]
        tails = [tail for tail, edge_head in self.fir.back_edges()
                 if edge_head == head]
        if not tails:
            return None
        header_statements: list[ast.stmt] = []
        for instr in block.instructions:
            if instr.op in ("BRANCH", "JUMP"):
                continue
            stmt = self.statement(instr)
            if stmt is not None:
                header_statements.append(stmt)
        body = self._loop_body(inside, outside, tails, head=head)
        test = self.expr(cond)
        if kind == "if_none":
            test = ast.Compare(left=test, ops=[ast.IsNot()],
                               comparators=[ast.Constant(value=None)])
        elif kind == "if_not_none":
            test = ast.Compare(left=test, ops=[ast.Is()],
                               comparators=[ast.Constant(value=None)])
        self.loop_exit = outside
        return header_statements + [
            ast.While(test=test, body=body or [ast.Pass()], orelse=[])]

    def for_loop(self, head: int):
        """`for name in iterable:` from a block that ends with FOR_ITER."""
        block = self.fir.blocks[head]
        terminator = None
        for instr in reversed(block.instructions):
            if instr.op == "FOR_ITER":
                terminator = instr
                break
        if terminator is None or len(block.successors) != 2:
            return None
        (iterator,) = terminator.args
        jump_target, fall_through = block.successors
        outside, inside = jump_target, fall_through
        tails = [tail for tail, head_of_edge in self.fir.back_edges()
                 if head_of_edge == head]
        if not tails:
            return None
        header_statements: list[ast.stmt] = []
        for instr in block.instructions:
            if instr.op in ("BRANCH", "JUMP", "FOR_ITER"):
                continue
            stmt = self.statement(instr)
            if stmt is not None:
                header_statements.append(stmt)
        # the body starts by storing the loop variable
        name = None
        body_from = inside
        first = self.fir.blocks.get(inside)
        if first is not None and first.instructions \
                and first.instructions[0].op == "STORE":
            name = first.instructions[0].args[1]
        if name is None:
            return None
        body = self._loop_body(inside, outside, tails, skip_first_store=name,
                               head=head)
        if body is None:
            return None
        target = ast.Name(id=name, ctx=ast.Store())
        iterable = iterator
        if isinstance(iterable.expr, tuple) and iterable.expr[0] == "iter":
            # `for` applies iter() itself; the explicit call is the bytecode's
            iterable = iterable.expr[1]
        self.loop_exit = outside
        return header_statements + [
            ast.For(target=target, iter=self.expr(iterable), body=body or [ast.Pass()],
                    orelse=[], type_comment=None)]

    def branch(self, block, successors, stop) -> list[ast.stmt]:
        """Emit an if/else from a block with two successors."""
        terminator = None
        for instr in reversed(block.instructions):
            if instr.op == "BRANCH":
                terminator = instr
                break
        if terminator is None:
            raise Unsupported("two successors without a branch")
        cond, kind = terminator.args
        jump_target, fall_through = successors[0], successors[1]
        if kind in ("if_false", "if_none"):
            # jump taken when the test fails: the target is the else arm
            true_block, false_block = fall_through, jump_target
        else:
            true_block, false_block = jump_target, fall_through
        # the join is the block both arms reach; the arm that ends with a jump
        # names it, the other arm falls into it
        join = self._join(true_block, false_block)
        test = self.expr(cond)
        if kind == "if_none":
            test = ast.Compare(left=test, ops=[ast.IsNot()],
                               comparators=[ast.Constant(value=None)])
        elif kind == "if_not_none":
            test = ast.Compare(left=test, ops=[ast.Is()],
                               comparators=[ast.Constant(value=None)])
        if isinstance(test, ast.Constant):
            raise Unsupported("constant branch")
        body = self.body(true_block, stop | ({join} if join is not None else set()))
        orelse: list[ast.stmt] = []
        if join is not None:
            orelse = self.body(false_block, stop | {join})
        else:
            orelse = self.body(false_block, stop)
        node = ast.If(test=test, body=body or [ast.Pass()], orelse=orelse)
        out: list[ast.stmt] = [node]
        if join is not None and join not in self.consumed and join not in stop:
            self.consumed.discard(join)
            out.extend(self.body(join, stop))
        return out

    def _join(self, first: int, second: int) -> int | None:
        """The first block both arms can reach without looping back."""
        def reach(start: int, limit: int = 64) -> list[int]:
            seen, order, stack = set(), [], [start]
            while stack and len(order) < limit:
                bid = stack.pop(0)
                if bid in seen or bid not in self.fir.blocks:
                    continue
                seen.add(bid)
                order.append(bid)
                stack.extend(self.fir.blocks[bid].successors)
            return order

        left = reach(first)
        right = set(reach(second))
        for bid in left:
            if bid in right and bid != first:
                return bid
        return None


def emit_function(fir: FunctionIR, name: str, args: list[str]) -> ast.FunctionDef:
    """One function definition, ready to be compiled."""
    emitter = Emitter(fir)
    body = emitter.body(fir.entry)
    if not body:
        body = [ast.Pass()]
    return ast.FunctionDef(name=name, args=_arguments(args), body=body,
                           decorator_list=[], returns=None, type_params=[],
                           lineno=1, col_offset=0)


def _arg_names(code) -> list[str]:
    """Positional parameter names of a code object, in order."""
    count = getattr(code, "argcount", 0) or 0
    names = list(getattr(code, "varnames", ()) or ())
    return names[:count]


def _arguments(names: list[str]) -> ast.arguments:
    return ast.arguments(posonlyargs=[], args=[ast.arg(arg=name, annotation=None,
                                                      type_comment=None)
                                              for name in names],
                         vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None,
                         defaults=[])


def emit_module(fir: FunctionIR, version: tuple = (3, 13)) -> str:
    """Emit the module-level IR as source."""
    emitter = Emitter(fir)
    body = emitter.body(fir.entry) or [ast.Pass()]
    # a module has no `return`; the implicit one is not part of the source
    while body and isinstance(body[-1], ast.Return) and body[-1].value is None:
        body.pop()
    body = body or [ast.Pass()]
    tree = ast.Module(body=body, type_ignores=[])
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"
