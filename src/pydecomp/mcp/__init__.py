"""pydecomp.mcp - the agent surface.

    python -m pydecomp.mcp.server            # read-only stdio server

Tools: identify, peel, triage, decompile_pyc, deobfuscate.  Read-only unless
started with --allow-write; every tool ends up in the same engine the CLI uses,
so an agent gets the same answer and the same proof a person gets.
"""
from __future__ import annotations

from ..mcp.server import PROTOCOL, TOOLS, call, handle, serve

__all__ = ["PROTOCOL", "TOOLS", "call", "handle", "serve"]
