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

    def function(self, code, name: str, defaults=None, kwdefaults=None,
                 decorators=()) -> ast.FunctionDef:
        """Emit a nested code object as a def statement."""
        from ..bytecode.ir_build import build_ir

        nested = build_ir(code, self.fir.version)
        inner = Emitter(nested)
        body = inner.body(nested.entry) or [ast.Pass()]
        globals_ = sorted({instr.args[0]
                           for block in nested.blocks.values()
                           for instr in block.instructions
                           if instr.op == "GLOBAL"})
        if globals_:
            body.insert(0, ast.Global(names=globals_))
        args = self.function_arguments(code, defaults, kwdefaults)
        return ast.FunctionDef(name=name, args=args, body=body,
                               decorator_list=[self.expr(item) for item in decorators],
                               returns=None, type_params=[],
                               lineno=1, col_offset=0)

    def lambda_expression(self, code, defaults=None, kwdefaults=None) -> ast.Lambda:
        """Emit only the expression-shaped lambda subset; refuse statement bodies."""
        from ..bytecode.ir_build import build_ir

        nested = build_ir(code, self.fir.version)
        body = Emitter(nested).body(nested.entry)
        if len(body) != 1 or not isinstance(body[0], ast.Return):
            raise Unsupported("lambda body is not one return expression")
        expression = body[0].value or ast.Constant(value=None)
        return ast.Lambda(args=self.function_arguments(code, defaults, kwdefaults),
                          body=expression)

    def function_arguments(self, code, defaults=None, kwdefaults=None) -> ast.arguments:
        """Translate definition-time defaults and code-object parameter metadata."""
        positional = []
        if defaults is not None:
            if defaults.source == "const" and isinstance(defaults.const, tuple):
                items = defaults.const
            elif isinstance(defaults.expr, tuple) and defaults.expr[0] == "build" \
                    and defaults.expr[1] == "tuple":
                items = defaults.expr[2]
            else:
                raise Unsupported("computed positional defaults")
            if len(items) > getattr(code, "argcount", 0):
                raise Unsupported("more defaults than positional parameters")
            positional = [self.expr_item(item) for item in items]
        keyword = {}
        if kwdefaults is not None:
            if not (isinstance(kwdefaults.expr, tuple)
                    and kwdefaults.expr[0] == "dict"):
                raise Unsupported("computed keyword-only defaults")
            for key, value in kwdefaults.expr[1]:
                if isinstance(key, SSAValue) and key.source == "const":
                    key = key.const
                if not isinstance(key, str):
                    raise Unsupported("non-string keyword-only default")
                keyword[key] = self.expr_item(value)
        return _arguments_for_code(code, positional, keyword)

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
            if isinstance(value.const, frozenset):
                return ast.Set(elts=[self.expr_item(item) for item in value.const])
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
            _, code, qualname, _defaults, _kwdefaults, _decorators = tree
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
                            keywords=[ast.keyword(arg=name, value=self.expr(value))
                                      for name, value in kwargs])
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
                _, nested, qualname, defaults, kwdefaults, decorators = value.expr
                if getattr(nested, "name", "") == "<lambda>":
                    return ast.Assign(
                        targets=[ast.Name(id=name, ctx=ast.Store())],
                        value=self.lambda_expression(nested, defaults, kwdefaults))
                return self.function(nested, name, defaults, kwdefaults, decorators)
            if isinstance(value.expr, tuple) and value.expr[0] == "call":
                _, decorator, args, keywords = value.expr
                if len(args) == 1 and not keywords:
                    function = args[0]
                    if isinstance(function.expr, tuple) and function.expr[0] == "funcdef":
                        _, nested, qualname, defaults, kwdefaults, decorators = function.expr
                        if getattr(nested, "name", None) == name:
                            decorators = (decorator,) + tuple(decorators)
                            return self.function(nested, name, defaults,
                                                 kwdefaults, decorators)
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
        if op == "RAISE":
            exception, cause = instr.args
            return ast.Raise(exc=None if exception is None else self.expr(exception),
                             cause=None if cause is None else self.expr(cause))
        if op == "SETUP":
            (name,) = instr.args
            raise Unsupported(f"3.8 block region {name}")
        if op == "GLOBAL":
            # Hoisted by function(); at module scope a global declaration has
            # no runtime effect and does not change the instruction stream.
            return None
        if op == "DELETE":
            name, opcode = instr.args
            if opcode == "DELETE_SUBSCR":
                raise Unsupported("delete subscript was not normalized")
            return ast.Delete(targets=[ast.Name(id=name, ctx=ast.Del())])
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
    def _tuple_store_group(self, instructions, index):
        first = instructions[index]
        if first.op != "STORE":
            return None
        value, _name = first.args
        tree = getattr(value, "expr", None)
        if not isinstance(tree, tuple) or len(tree) != 3 or tree[0] != "item":
            return None
        source = tree[1]
        stores = []
        expected = 0
        for instr in instructions[index:]:
            if instr.op != "STORE":
                break
            item, name = instr.args
            item_tree = getattr(item, "expr", None)
            if (not isinstance(item_tree, tuple) or len(item_tree) != 3
                    or item_tree[0] != "item" or item_tree[1] is not source
                    or item_tree[2] != expected or not isinstance(name, str)):
                break
            stores.append(ast.Name(id=name, ctx=ast.Store()))
            expected += 1
        if len(stores) < 2:
            return None
        target = ast.Tuple(elts=stores, ctx=ast.Store())
        return ast.Assign(targets=[target], value=self.expr(source)), len(stores)

    def statements(self, instructions, skip_store: str | None = None) -> list[ast.stmt]:
        out = []
        skipped = False
        index = 0
        while index < len(instructions):
            instr = instructions[index]
            if (instr.op == "SWAP" and instr.args == (2,)
                    and index + 2 < len(instructions)
                    and instructions[index + 1].op == "STORE"
                    and instructions[index + 2].op == "STORE"):
                first, second = instructions[index + 1:index + 3]
                first_value, first_name = first.args
                second_value, second_name = second.args
                if isinstance(first_name, str) and isinstance(second_name, str):
                    targets = ast.Tuple(
                        elts=[ast.Name(id=first_name, ctx=ast.Store()),
                              ast.Name(id=second_name, ctx=ast.Store())],
                        ctx=ast.Store())
                    values = ast.Tuple(
                        elts=[self.expr(first_value), self.expr(second_value)],
                        ctx=ast.Load())
                    out.append(ast.Assign(targets=[targets], value=values))
                    index += 3
                    continue
            if instr.op in ("BRANCH", "JUMP", "FOR_ITER"):
                index += 1
                continue
            if (skip_store and not skipped and instr.op == "STORE"
                    and instr.args[1] == skip_store):
                skipped = True
                index += 1
                continue
            grouped = self._tuple_store_group(instructions, index)
            if grouped is not None:
                stmt, consumed = grouped
                out.append(stmt)
                index += consumed
                continue
            stmt = self.statement(instr)
            if stmt is not None:
                out.append(stmt)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    break
            index += 1
        return out

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
            for stmt in self.statements(block.instructions):
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
        body = self._loop_body(inside, outside, tails, head=inside)
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
            if any(instr.op == "FOR_ITER" for instr in block.instructions):
                nested = self.for_loop(current, skip_first_store)
                skip_first_store = None
                if nested is None:
                    return None
                body.extend(nested)
                current = self.loop_exit
                self.loop_exit = None
                continue
            if current != head and current in self.loops and len(block.successors) == 2:
                nested = self.while_loop_at_head(current)
                if nested is None:
                    return None
                body.extend(nested)
                current = self.loop_exit
                self.loop_exit = None
                continue
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

    def for_loop(self, head: int, skip_header_store: str | None = None):
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
        skip = skip_header_store
        for instr in block.instructions:
            if instr.op in ("BRANCH", "JUMP", "FOR_ITER"):
                continue
            if skip and instr.op == "STORE" and instr.args[1] == skip:
                skip = None
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

    def _assert_message(self, bid: int):
        block = self.fir.blocks.get(bid)
        if block is None:
            return False, None
        if (len(block.instructions) not in (1, 2)
                or block.instructions[-1].op != "RAISE"
                or (len(block.instructions) == 2
                    and block.instructions[0].op != "CALL")):
            return False, None
        raise_instr = block.instructions[-1]
        if raise_instr.args[1] is not None:
            return False, None
        exception = raise_instr.args[0]
        if len(block.instructions) == 1:
            if exception.source == "arg" and exception.name == "AssertionError":
                return True, None
            return False, None
        if block.instructions[0].result is not exception:
            return False, None
        tree = getattr(exception, "expr", None)
        if not isinstance(tree, tuple) or not tree or tree[0] != "call":
            return False, None
        _kind, callable_, args, keywords = tree
        if callable_.source != "arg" or callable_.name != "AssertionError" or keywords:
            return False, None
        if len(args) > 1:
            return False, None
        return True, args[0] if args else None

    def branch(self, block, successors, stop) -> list[ast.stmt]:
        """Emit an if/else, or recover a compiler-lowered assert."""
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
        is_assert, message = self._assert_message(false_block)
        if is_assert:
            self.consumed.add(false_block)
            self.consumed.discard(true_block)
            assertion = ast.Assert(
                test=test, msg=None if message is None else self.expr(message))
            return [assertion] + self.body(true_block, stop)
        if join is None:
            true_block_obj = self.fir.blocks[true_block]
            false_block_obj = self.fir.blocks[false_block]
            true_raises = bool(true_block_obj.instructions
                               and true_block_obj.instructions[-1].op == "RAISE")
            false_raises = bool(false_block_obj.instructions
                                and false_block_obj.instructions[-1].op == "RAISE")
            if true_raises != false_raises:
                raise_block = true_block if true_raises else false_block
                other_block = false_block if true_raises else true_block
                raise_body = self.body(raise_block, stop)
                other_body = self.body(other_block, stop)
                raise_test = (test if true_raises else
                              ast.UnaryOp(op=ast.Not(), operand=test))
                guard = ast.If(test=raise_test, body=raise_body or [ast.Pass()], orelse=[])
                return [guard] + other_body
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


def _arguments(names: list[str], defaults: list[ast.expr] | None = None) -> ast.arguments:
    return ast.arguments(posonlyargs=[], args=[ast.arg(arg=name, annotation=None,
                                                      type_comment=None)
                                              for name in names],
                         vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None,
                         defaults=list(defaults or []))


def _arguments_for_code(code, defaults: list[ast.expr],
                        kwdefaults: dict[str, ast.expr]) -> ast.arguments:
    """Rebuild all parameter categories from code-object argument metadata."""
    names = list(getattr(code, "varnames", ()) or ())
    positional_count = int(getattr(code, "argcount", 0) or 0)
    positional_only_count = int(getattr(code, "posonlyargcount",
                                         getattr(code, "posonly", 0)) or 0)
    keyword_only_count = int(getattr(code, "kwonlyargcount",
                                     getattr(code, "kwonly", 0)) or 0)
    positional_names = names[:positional_count]
    keyword_names = names[positional_count:positional_count + keyword_only_count]
    if len(positional_names) != positional_count or len(keyword_names) != keyword_only_count:
        raise Unsupported("incomplete argument names in code object")
    if len(defaults) > positional_count:
        raise Unsupported("more defaults than positional parameters")
    if set(kwdefaults) - set(keyword_names):
        raise Unsupported("keyword-only default name outside signature")
    make_arg = lambda name: ast.arg(arg=name, annotation=None, type_comment=None)
    index = positional_count + keyword_only_count
    vararg = None
    kwarg = None
    flags = int(getattr(code, "flags", 0) or 0)
    if flags & 0x04:                                  # CO_VARARGS
        if index >= len(names):
            raise Unsupported("missing *args name")
        vararg = make_arg(names[index])
        index += 1
    if flags & 0x08:                                  # CO_VARKEYWORDS
        if index >= len(names):
            raise Unsupported("missing **kwargs name")
        kwarg = make_arg(names[index])
    return ast.arguments(
        posonlyargs=[make_arg(name) for name in positional_names[:positional_only_count]],
        args=[make_arg(name) for name in positional_names[positional_only_count:]],
        vararg=vararg,
        kwonlyargs=[make_arg(name) for name in keyword_names],
        kw_defaults=[kwdefaults.get(name) for name in keyword_names],
        kwarg=kwarg,
        defaults=list(defaults))


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
