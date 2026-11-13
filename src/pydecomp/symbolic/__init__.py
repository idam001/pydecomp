"""pydecomp - the symbolic domain.

One place where the pipeline reasons about *values* instead of instructions.  The
domain (:mod:`.domain`) turns an expression into a small tree of integer
operations with the unknowns kept symbolic; the library (:mod:`.simplify`) holds
the identities that undo mixed boolean arithmetic, each one proved over a grid of
integers before it is installed; the executor (:mod:`.exec`) walks a recovered
module, collapses what the library can collapse, and drops the branches whose
predicate it can decide.

Nothing here runs the program being decompiled.  What is proved is the *rule*, by
evaluating the rule's own two templates; what is applied is a structural
substitution.
"""
from __future__ import annotations

from .domain import (BINARY_OPS, COMPARE_OPS, INTEGER_OPS, UNARY_OPS, Sym,
                     SymConst, SymExpr, SymUnknown, bind_tree, const, evaluate,
                     from_ast, is_int, unknowns)
from .exec import (Executor, Report, decide, describe, eligible, fold_constants,
                   prove_polynomial_mod, run, simplify_tree)
from .simplify import (GRID, IDENTITIES, REJECTED, _prove, canonical, prove_true,
                       simplify)

__all__ = [
    "BINARY_OPS", "COMPARE_OPS", "GRID", "IDENTITIES", "INTEGER_OPS", "REJECTED",
    "Executor", "Report", "Sym", "SymConst", "SymExpr", "SymUnknown", "UNARY_OPS",
    "bind_tree", "canonical", "const", "decide", "describe", "eligible",
    "evaluate", "fold_constants", "from_ast", "is_int", "prove_polynomial_mod",
    "prove_true", "run", "simplify", "simplify_tree", "unknowns",
]
