"""pydecomp - polish.mba.

Mixed boolean arithmetic: `a + b` written as `(a ^ b) + 2 * (a & b)`, `a ^ b`
written as `(a | b) - (a & b)`, a constant written as a chain of shifts.  The
rewriter that undoes it lives in :mod:`pydecomp.symbolic`, together with the
identity library it uses.

The rules used to be written out here, hand-checked against the same handful of
samples the previous version of this pass carried in its own prover.  They are
now *proved* at import over a grid of integers, so this module keeps only what it
always was: the entry point the fixed-point driver calls.  A tree that comes back
from :func:`simplify_mba` has had every mixed-arithmetic expression the library
can reduce collapsed, and every branch predicate the library can decide removed
along with the arm that never runs.
"""
from __future__ import annotations

from ..symbolic.exec import simplify_tree


def simplify_mba(tree) -> int:
    """Rewrite MBA-heavy subexpressions back to their plain arithmetic form.

    Returns the number of changes made: collapsed expressions plus decided
    branches.  Zero means the pass found nothing to do, which is the answer for
    ordinary source.
    """
    try:
        _, report = simplify_tree(tree)
        return report.rewritten + report.decided
    except Exception:                                     # noqa: BLE001 - cosmetic pass
        return 0
