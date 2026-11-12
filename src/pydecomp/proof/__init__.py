"""pydecomp.proof - proof-carrying recovery artifacts.

Every output this tool writes can be checked by a third party without trusting
the tool: the ``.proof.json`` beside it names the layers that were peeled, the
backend that decompiled the code, the tier each recovered unit reached, what
was inferred, and what was lost.

    from pydecomp.proof import Proof, build, write, tiers
"""
from __future__ import annotations

from ..proof.build import build, prefix_for
from ..proof.model import GUARANTEE, TIER_MEANING, TIER_ORDER, Layer, Proof
from ..proof.tiers import compare, grade
from ..proof.write import failure, paths_for, write

__all__ = ["GUARANTEE", "Layer", "Proof", "TIER_MEANING", "TIER_ORDER", "build",
           "compare", "failure", "grade", "paths_for", "prefix_for", "write"]
