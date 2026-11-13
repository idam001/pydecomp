"""The built-in backend tree, and the door for community decoders.

Five subtrees hold the techniques pydecomp ships:

    codecs/      base64 family, hex, escapes, the bases without stdlib codecs,
                 and the rearranged alphabets
    compress/    zlib, gzip, bz2, lzma, deflate without a header, zip and tar
    cipher/      XOR with keys we have to recover, shifts, rotations, RC4
    containers/  .pyc headers, marshal streams, junk on either end
    alphabet/    the same base64 with the alphabet moved around

A sixth "tree" is not a directory at all: anything registered through
``pydecomp.plugins.register_decoder`` - including decoders installed from other
packages via entry points - is wrapped as a backend, so a third-party technique
takes part in the same chain search as a built-in one.

    from pydecomp.plugins.backends import backends, describe, explore
"""
from __future__ import annotations

from .explore import Hit, Result, explore
from .registry import backends, by_name, describe
from .spec import Backend, Budget, Refusal

__all__ = ["Backend", "Budget", "Hit", "Refusal", "Result", "backends", "by_name",
           "describe", "explore"]
