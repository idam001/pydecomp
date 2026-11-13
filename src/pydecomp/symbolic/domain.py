"""pydecomp - the symbolic domain.

Obfuscators do not write programs, they write arithmetic.  `a + b` arrives as
`(a ^ b) + 2 * (a & b)`, a loop bound as a polynomial that is divisible by three
for every input it will ever see, and a branch as a condition that is always
false.  Reading that back is not a matter of pattern-matching source text - it is
a matter of carrying values whose *meaning* is known and whose *form* can be
rewritten.

Two node kinds carry that:

* :class:`SymConst` - a value that is already decided;
* :class:`SymExpr` - an operation on values that are not.

and one carries the honest hole:

* :class:`SymUnknown` - a value that stays symbolic, with its name kept
  so the caller can say why instead of pretending.

Nothing here executes the sample.  A node is built from the sample's syntax, and
every rewrite is a structural substitution that the simplifier first *proves* on
its own templates.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass


class Sym:
    """Base class: a value in the symbolic domain."""

    #: True when the value is fully decided
    const = False

    def to_ast(self) -> ast.expr:                    # pragma: no cover - abstract
        raise NotImplementedError

    def key(self) -> str:
        """A stable structural identity, for deduplication and comparison."""
        return hashlib.sha1(repr(self).encode()).hexdigest()


@dataclass(frozen=True)
class SymConst(Sym):
    """A decided value."""

    value: object = None
    const = True

    def to_ast(self) -> ast.expr:
        if isinstance(self.value, (int, float, complex, str, bytes, bool, type(None))):
            return ast.Constant(value=self.value)
        if isinstance(self.value, tuple):
            return ast.Tuple(elts=[ast.Constant(value=item) for item in self.value],
                             ctx=ast.Load())
        return ast.Constant(value=repr(self.value))

    def __str__(self) -> str:
        return repr(self.value)


@dataclass(frozen=True)
class SymUnknown(Sym):
    """A value that is read but not decided, with the reason it is not."""

    name: str = ""
    reason: str = "read from the program"

    def to_ast(self) -> ast.expr:
        return ast.Name(id=self.name or "_unknown", ctx=ast.Load())

    def __str__(self) -> str:
        return self.name or "?"


#: operations the domain carries, and the AST node each one emits
BINARY_OPS = {"+": ast.Add, "-": ast.Sub, "*": ast.Mult, "//": ast.FloorDiv,
              "%": ast.Mod, "**": ast.Pow, "<<": ast.LShift, ">>": ast.RShift,
              "&": ast.BitAnd, "|": ast.BitOr, "^": ast.BitXor, "/": ast.Div,
              "@": ast.MatMult}

COMPARE_OPS = {"==": ast.Eq, "!=": ast.NotEq, "<": ast.Lt, "<=": ast.LtE,
               ">": ast.Gt, ">=": ast.GtE, "is": ast.Is, "is not": ast.IsNot,
               "in": ast.In, "not in": ast.NotIn}

UNARY_OPS = {"-": ast.USub, "+": ast.UAdd, "~": ast.Invert, "not": ast.Not}

#: the ops whose result is an integer when the operands are, i.e. the ones the
#: identity library is allowed to reason about
INTEGER_OPS = frozenset({"+", "-", "*", "//", "%", "**", "<<", ">>", "&", "|", "^",
                         "~", "neg"})


@dataclass(frozen=True)
class SymExpr(Sym):
    """An operation on symbolic values."""

    op: str = ""
    args: tuple = ()

    def to_ast(self) -> ast.expr:
        # "+" and "-" are both binary and unary: the arity decides which
        if self.op in ("+", "-") and len(self.args) == 1:
            kind = ast.UAdd if self.op == "+" else ast.USub
            return ast.UnaryOp(op=kind(), operand=self.args[0].to_ast())
        if self.op in BINARY_OPS:
            left, right = self.args
            return ast.BinOp(left=left.to_ast(), op=BINARY_OPS[self.op](),
                             right=right.to_ast())
        if self.op in COMPARE_OPS:
            left, right = self.args
            return ast.Compare(left=left.to_ast(), ops=[COMPARE_OPS[self.op]()],
                               comparators=[right.to_ast()])
        if self.op in UNARY_OPS:
            return ast.UnaryOp(op=UNARY_OPS[self.op](), operand=self.args[0].to_ast())
        if self.op == "neg":
            return ast.UnaryOp(op=ast.USub(), operand=self.args[0].to_ast())
        if self.op == "bool":
            kind, values = self.args
            return ast.BoolOp(op=ast.And() if kind == "and" else ast.Or(),
                              values=[item.to_ast() for item in values])
        raise ValueError(f"no emitter for {self.op}")

    def __str__(self) -> str:
        if len(self.args) == 1:
            return f"({self.op}{self.args[0]})"
        if self.op == "bool":
            kind, values = self.args
            joiner = f" {kind} "
            return "(" + joiner.join(str(item) for item in values) + ")"
        return f"({self.args[0]} {self.op} {self.args[1]})"


def const(value) -> SymConst:
    return SymConst(value=value)


TRUE = SymConst(value=True)
FALSE = SymConst(value=False)


def is_int(node: Sym) -> bool:
    return isinstance(node, SymConst) and isinstance(node.value, int) \
        and not isinstance(node.value, bool)


def bind_tree(node: Sym, env: dict) -> Sym:
    """Replace every unknown whose name is in *env* with its value."""
    if isinstance(node, SymUnknown):
        return env.get(node.name, node)
    if isinstance(node, SymExpr):
        if node.op == "bool":
            kind, values = node.args
            return SymExpr(op="bool", args=(kind, tuple(bind_tree(item, env)
                                                        for item in values)))
        return SymExpr(op=node.op, args=tuple(bind_tree(item, env) for item in node.args))
    return node


def unknowns(node: Sym) -> tuple[str, ...]:
    """Every unknown name this expression reads, in first-seen order."""
    seen: list[str] = []

    def walk(item: Sym) -> None:
        if isinstance(item, SymUnknown):
            if item.name not in seen:
                seen.append(item.name)
        elif isinstance(item, SymExpr):
            for piece in item.args:
                if isinstance(piece, Sym):
                    walk(piece)
                elif isinstance(piece, tuple):
                    for deeper in piece:
                        if isinstance(deeper, Sym):
                            walk(deeper)

    walk(node)
    return tuple(seen)


def from_ast(node) -> Sym:
    """Lift one AST expression into the domain.

    Anything the domain has no operation for - a call, a subscript, an
    attribute - becomes an :class:`SymUnknown` carrying its own source text, so
    the value stays addressable without pretending to know what it holds.
    """
    if isinstance(node, ast.Constant):
        return SymConst(value=node.value)
    if isinstance(node, ast.Name):
        return SymUnknown(name=node.id)
    if isinstance(node, ast.BinOp):
        symbol = _operator_symbol(node.op)
        if symbol is None:
            return SymUnknown(name=ast.unparse(node))
        return SymExpr(op=symbol, args=(from_ast(node.left), from_ast(node.right)))
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            operand = from_ast(node.operand)
            if is_int(operand):
                return SymConst(value=-operand.value)
            return SymExpr(op="neg", args=(operand,))
        symbol = {ast.Invert: "~", ast.Not: "not", ast.UAdd: "+"}.get(type(node.op))
        if symbol == "+":
            return from_ast(node.operand)
        if symbol is None:
            return SymUnknown(name=ast.unparse(node))
        return SymExpr(op=symbol, args=(from_ast(node.operand),))
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        symbol = _compare_symbol(node.ops[0])
        if symbol is None:
            return SymUnknown(name=ast.unparse(node))
        return SymExpr(op=symbol, args=(from_ast(node.left),
                                        from_ast(node.comparators[0])))
    if isinstance(node, ast.BoolOp):
        kind = "and" if isinstance(node.op, ast.And) else "or"
        return SymExpr(op="bool", args=(kind, tuple(from_ast(item) for item in node.values)))
    return SymUnknown(name=ast.unparse(node))


def _operator_symbol(node) -> str | None:
    for symbol, kind in BINARY_OPS.items():
        if isinstance(node, kind):
            return symbol
    return None


def _compare_symbol(node) -> str | None:
    for symbol, kind in COMPARE_OPS.items():
        if isinstance(node, kind):
            return symbol
    return None


def evaluate(node: Sym):
    """Evaluate a fully-decided node.  Raises on an unknown."""
    if isinstance(node, SymConst):
        return node.value
    if isinstance(node, SymUnknown):
        raise ValueError(f"{node.name} is not decided")
    op, args = node.op, node.args
    if op == "bool":
        kind, values = args
        results = [evaluate(item) for item in values]
        return all(results) if kind == "and" else any(results)
    if len(args) == 1:
        value = evaluate(args[0])
        return {"-": lambda v: -v, "neg": lambda v: -v, "+": lambda v: +v,
                "~": lambda v: ~v, "not": lambda v: not v}[op](value)
    values = [evaluate(item) for item in args]
    return _apply(op, values)


def _apply(op: str, values: list):
    left, right = values
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    if op == "*":
        return left * right
    if op == "//":
        return left // right
    if op == "%":
        return left % right
    if op == "**":
        return left ** right
    if op == "<<":
        return left << right
    if op == ">>":
        return left >> right
    if op == "&":
        return left & right
    if op == "|":
        return left | right
    if op == "^":
        return left ^ right
    if op == "/":
        return left / right
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "is":
        return left is right
    if op == "is not":
        return left is not right
    raise ValueError(f"no evaluator for {op}")
