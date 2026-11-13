"""pydecomp - symbolic execution over a recovered module.

This is the pass that turns arithmetic an obfuscator wrote back into the
arithmetic the author wrote, and it works on *syntax*, never on the sample:

* every arithmetic subexpression is lifted into the symbolic domain, rewritten
  with the proven identity library, and emitted back as source;
* a predicate that the library reduces to a constant decides its branch, and the
  branch that can never run is dropped;
* a predicate that is a polynomial in its unknowns is decided by residue: if
  ``P(x)`` agrees with a constant on every residue modulo *m*, it agrees on every
  integer, because the residue determines the value of a polynomial modulo *m*.
  That is what folds the polynomial guards (``(x * x + x) % 2 == 0``) that
  obfuscators generate without any per-obfuscator code.

Two rules keep it honest.  A rewrite is applied only to an expression whose
leaves are plain names and integers and which uses a bitwise operator - the shape
mixed-boolean arithmetic has and ordinary source almost never does - so an
object's overloaded operator is never silently re-associated.  And a branch is
removed only when the predicate is *proved*, never when the executor merely fails
to keep it.
"""
from __future__ import annotations

import ast
import itertools
from dataclasses import dataclass

from .domain import Sym, SymConst, SymExpr, SymUnknown, evaluate, from_ast, is_int
from .simplify import canonical, prove_true, simplify

#: operators that make an expression eligible for the arithmetic rewriter
_ARITHMETIC = (ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
               ast.Invert, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
               ast.Mod, ast.Pow)

#: the bitwise operators: at least one of these marks the expression as the kind
#: an obfuscator rewrote, rather than ordinary code the rewriter should not touch
_SIGNATURE = (ast.BitAnd, ast.BitOr, ast.BitXor, ast.Invert, ast.LShift, ast.RShift)


@dataclass
class Report:
    """What the pass did, so the caller can report it instead of implying it."""

    expressions: int = 0
    rewritten: int = 0
    branches: int = 0
    decided: int = 0
    polynomial: int = 0

    def notes(self) -> list[str]:
        out: list[str] = []
        if self.rewritten:
            out.append(f"collapsed {self.rewritten} mixed-arithmetic expression(s)")
        if self.decided:
            out.append(f"decided {self.decided} branch predicate(s) and dropped "
                       f"the arm that never runs")
        if self.polynomial:
            out.append(f"proved {self.polynomial} polynomial guard(s) over their "
                       f"residues")
        return out


# --------------------------------------------------------------------------
# eligibility: arithmetic, not somebody's overloaded operators
# --------------------------------------------------------------------------

def _signature(node) -> bool:
    return any(isinstance(inner, _SIGNATURE) for inner in ast.walk(node))


def _leaves_are_plain(node) -> bool:
    for inner in ast.walk(node):
        if isinstance(inner, (ast.Constant, ast.Name, ast.operator, ast.unaryop,
                              ast.expr_context)):
            continue
        if isinstance(inner, (ast.BinOp, ast.UnaryOp, ast.Compare)):
            continue
        return False
    for inner in ast.walk(node):
        if isinstance(inner, ast.Constant) and not isinstance(inner.value, int):
            return False
    return True


def eligible(node) -> bool:
    """Is this expression safe to re-associate as integer arithmetic?"""
    return _signature(node) and _leaves_are_plain(node)


# --------------------------------------------------------------------------
# polynomials and their residues
# --------------------------------------------------------------------------

_POLY_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Pow, ast.Mod, ast.FloorDiv)


def _is_polynomial(node) -> bool:
    """Only the operations whose residue class is closed under the rewrite."""
    for inner in ast.walk(node):
        if isinstance(inner, ast.BinOp):
            if not isinstance(inner.op, _POLY_BINOPS):
                return False
        elif isinstance(inner, ast.UnaryOp):
            if not isinstance(inner.op, (ast.USub, ast.UAdd)):
                return False
        elif isinstance(inner, ast.Constant):
            if not isinstance(inner.value, int):
                return False
        elif isinstance(inner, (ast.Name, ast.Load, ast.operator, ast.unaryop)):
            continue
        else:
            return False
    # an exponent can be a name only if it is bounded, and it is not: refuse
    for inner in ast.walk(node):
        if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Pow) \
                and isinstance(inner.right, ast.Name):
            return False
    return True


def _polynomial_names(node) -> list[str]:
    names: list[str] = []
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and inner.id not in names:
            names.append(inner.id)
    return names


def _evaluate_ast(node, env: dict[str, int]):
    """Evaluate a polynomial AST over the integers.  Never touches the sample."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        value = _evaluate_ast(node.operand, env)
        return -value if isinstance(node.op, ast.USub) else value
    if isinstance(node, ast.BinOp):
        left = _evaluate_ast(node.left, env)
        right = _evaluate_ast(node.right, env)
        for kind, apply in ((ast.Add, lambda a, b: a + b), (ast.Sub, lambda a, b: a - b),
                            (ast.Mult, lambda a, b: a * b),
                            (ast.FloorDiv, lambda a, b: a // b),
                            (ast.Mod, lambda a, b: a % b),
                            (ast.Pow, lambda a, b: a ** b)):
            if isinstance(node.op, kind):
                return apply(left, right)
    raise ValueError("not a polynomial")


def prove_polynomial_mod(test) -> bool | None:
    """Decide ``P(x, ...) % m <op> k`` by checking every residue modulo *m*.

    A polynomial with integer coefficients takes the same value modulo *m* for
    every integer in a residue class, so ``m`` samples per unknown cover the
    whole line.  The check is therefore a proof, not a poll of a few inputs.

    Returns True when the predicate holds for every residue, False when it holds
    for none of them - the dead arm - and None when it varies, which is the
    answer that leaves the branch alone.
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    left, right = test.left, test.comparators[0]
    body, other, modulus = None, None, None
    for candidate, opposite in ((left, right), (right, left)):
        if (isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Mod)
                and isinstance(candidate.right, ast.Constant)):
            body, other, modulus = candidate.left, opposite, candidate.right
            break
    if body is None or not isinstance(modulus.value, int) or modulus.value < 1:
        return None
    if not _is_polynomial(body) or not _is_polynomial(other):
        return None
    names = sorted(set(_polynomial_names(body)) | set(_polynomial_names(other)))
    if len(names) > 2:
        return None
    modulus_value = modulus.value
    residues = range(modulus_value)
    held, failed = 0, 0
    for values in itertools.product(residues, repeat=len(names)):
        env = dict(zip(names, values))
        try:
            mine = _evaluate_ast(body, env) % modulus_value
            theirs = _evaluate_ast(other, env)
        except Exception:                            # noqa: BLE001 - not a polynomial after all
            return None
        if _apply_compare(test.ops[0], mine, theirs):
            held += 1
        else:
            failed += 1
    if held and not failed:
        return True
    if failed and not held:
        return False
    return None


def _apply_compare(op, left, right) -> bool:
    for kind, apply in ((ast.Eq, lambda a, b: a == b), (ast.NotEq, lambda a, b: a != b),
                        (ast.Lt, lambda a, b: a < b), (ast.LtE, lambda a, b: a <= b),
                        (ast.Gt, lambda a, b: a > b), (ast.GtE, lambda a, b: a >= b)):
        if isinstance(op, kind):
            return apply(left, right)
    raise ValueError("not a comparison")


# --------------------------------------------------------------------------
# the pass
# --------------------------------------------------------------------------

class Executor(ast.NodeTransformer):
    """Rewrite arithmetic and drop the branches that never run."""

    def __init__(self, report: Report):
        self.report = report

    # -- expressions -----------------------------------------------------
    def visit_BinOp(self, node):                          # noqa: N802
        node = self.generic_visit(node)
        if not eligible(node):
            return node
        self.report.expressions += 1
        return self._rewrite(node)

    def visit_UnaryOp(self, node):                        # noqa: N802
        node = self.generic_visit(node)
        if not eligible(node):
            return node
        self.report.expressions += 1
        return self._rewrite(node)

    def visit_BoolOp(self, node):                         # noqa: N802
        node = self.generic_visit(node)
        values = [item for item in node.values]
        if len(values) == 1:
            return values[0]
        return node

    def _rewrite(self, node):
        original = from_ast(node)
        value = simplify(original)
        if isinstance(value, SymConst):
            self.report.rewritten += 1
            return ast.copy_location(ast.Constant(value=value.value), node)
        if isinstance(value, SymUnknown):
            self.report.rewritten += 1
            return ast.copy_location(ast.Name(id=value.name, ctx=ast.Load()), node)
        if not isinstance(value, SymExpr) or value == original:
            return node
        if canonical(value) == original:
            return node
        try:
            rebuilt = value.to_ast()
        except (ValueError, TypeError):
            return node
        self.report.rewritten += 1
        return ast.copy_location(rebuilt, node)

    # -- branches --------------------------------------------------------
    def visit_If(self, node):                             # noqa: N802
        node = self.generic_visit(node)
        self.report.branches += 1
        verdict = decide(node.test, self.report)
        if verdict is None:
            return node
        self.report.decided += 1
        body, orelse = node.body, node.orelse
        chosen = body if verdict else orelse
        if not chosen:
            # `if False: ...` and `if True: pass` both vanish; nothing to keep
            return ast.copy_location(ast.Pass(), node)
        return chosen if len(chosen) > 1 else chosen[0]

    def visit_While(self, node):                          # noqa: N802
        node = self.generic_visit(node)
        if decide(node.test, self.report) is False and not node.orelse:
            # a loop that can never run once is not a loop
            self.report.decided += 1
            return ast.copy_location(ast.Pass(), node)
        return node


def decide(test, report: Report | None = None) -> bool | None:
    """Decide a predicate, or return None and leave the branch alone."""
    verdict = prove_true(from_ast(test))
    if verdict is not None:
        return verdict
    polynomial = prove_polynomial_mod(test)
    if polynomial is not None:
        if report is not None:
            report.polynomial += 1
        return polynomial
    return None


def fold_constants(node) -> ast.expr:
    """Fold an expression that is entirely constant."""
    value = from_ast(node)
    if isinstance(value, SymConst):
        return ast.Constant(value=value.value)
    return node


def simplify_tree(tree: ast.Module) -> tuple[ast.Module, Report]:
    """Run the symbolic pass over a module."""
    report = Report()
    tree = Executor(report).visit(tree)
    ast.fix_missing_locations(tree)
    return tree, report


def run(tree) -> tuple:
    """Alias used by the polish pipeline; returns (tree, notes)."""
    tree, report = simplify_tree(tree)
    return tree, report.notes()


def describe() -> dict:
    from .simplify import IDENTITIES, REJECTED
    return {"engine": "symbolic", "identities": len(IDENTITIES),
            "rejected": len(REJECTED), "domain": "integers"}
