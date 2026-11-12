"""pydecomp - learned priors.

The decoder registry is a fixed cast of characters: base64, zlib, lzma, b85, xor,
reverse, rot13 and the rest.  Any of them *could* be the first layer of an
unknown blob, so the search tries many.  This package answers a narrower and much
cheaper question first: given the bytes in hand, which decoder is most likely to
be the one that opens them?

That ranking is not a heuristic someone typed in.  It is a small linear model
over features of the blob (size, entropy, alphabet membership, container magic,
...) trained on the project's own corpus by ``tools/train_learn.py``, which
writes ``weights.py`` here.  Nothing is learned at run time, nothing is fetched,
and the ranking is only an *order*: every decoder is still tried, so a wrong
ranking costs time, never correctness.

    from pydecomp.learn import rank
    for name in rank(TRANSFORMS, blob): ...

If ``weights.py`` is missing (a checkout without the trainer having run) the
registry order is used and everything still works.
"""
from __future__ import annotations

from .features import FEATURE_NAMES, vector
from .model import rank, score, trained

__all__ = ["FEATURE_NAMES", "vector", "rank", "score", "trained"]
