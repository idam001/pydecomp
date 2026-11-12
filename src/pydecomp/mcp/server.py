"""pydecomp - mcp server.

An agent should be able to call this tool the way a person does.  This is a
JSON-RPC 2.0 server over stdio with one tool per capability:

    initialize      protocol handshake
    tools/list      the capabilities, with their input schemas
    tools/call      run one

Read-only by default: ``deobfuscate`` returns the recovered text instead of
writing a file, and ``identify`` / ``peel`` / ``triage`` never touch the disk.
``--allow-write`` turns writing on for the calling agent.

Nothing is imported or executed on the sample's behalf; every tool goes through
:func:`pydecomp.engine.dig.dig` like the CLI does.
"""
from __future__ import annotations

import json
import os
import sys

from ..limits import __version__

PROTOCOL = "2024-11-05"

TOOLS = {
    "identify": {
        "description": "What is this file? implementation, protector, freezer, layers.",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {
            "path": {"type": "string", "description": "file to inspect"}}},
    },
    "peel": {
        "description": "List the transformations that stand between the file and its program.",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {
            "path": {"type": "string"}}},
    },
    "triage": {
        "description": "Fingerprint, indicators and behaviour of recovered code.",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {
            "path": {"type": "string"}}},
    },
    "decompile_pyc": {
        "description": "Decompile a .pyc / marshal stream; returns source and its proof tier.",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {
            "path": {"type": "string"}}},
    },
    "deobfuscate": {
        "description": "RecOVER source. Read-only unless the server runs with --allow-write.",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {
            "path": {"type": "string"},
            "out": {"type": "string", "description": "output folder (needs --allow-write)"}}},
    },
}


def _read(path: str) -> bytes:
    with open(os.path.expanduser(path), "rb") as handle:
        return handle.read()


def _prepare(path: str) -> None:
    """Point the engine at whatever sits beside the sample (a runtime lib, etc.).

    Without this an agent would get the loader where a person gets the program:
    the CLI does this in its run loop, so the server must too.
    """
    try:
        from ..protectors import pyarmor
        pyarmor.set_context(path)
    except Exception:                            # noqa: BLE001 - context is an optimisation
        pass


def _identify(path: str) -> dict:
    from ..bytecode.magic import identify_implementation
    from ..containers import match, unpack
    from ..protectors import identify as identify_protector
    data = _read(path)
    reader = match(data)
    return {"path": os.path.abspath(path), "bytes": len(data),
            "implementation": identify_implementation(data),
            "protector": identify_protector(data),
            "freezer": getattr(reader, "name", None),
            "sha256": __import__("hashlib").sha256(data).hexdigest()}


def _peel(path: str) -> dict:
    from ..engine.dig import dig
    _prepare(path)
    data = _read(path)
    artifact = dig(data, os.path.basename(path))
    return {"path": os.path.abspath(path), "kind": artifact.kind,
            "stalled": artifact.stalled, "layers": list(artifact.trace),
            "bytes": len(artifact.text)}


def _triage(path: str) -> dict:
    from ..engine.dig import dig
    from ..triage.report import analyse_recovered
    _prepare(path)
    data = _read(path)
    artifact = dig(data, os.path.basename(path))
    report = analyse_recovered(artifact.text, artifact.trace, raw=data)
    return {"fingerprint": report.get("fingerprint"),
            "iocs": report.get("ioc_counts", {}),
            "risks": report.get("risks", {}),
            "imports": report.get("imports", [])[:40]}


def _decompile_pyc(path: str) -> dict:
    from ..bytecode.magic import parse_pyc
    from ..engine.dig import dig
    from ..proof.tiers import compare
    _prepare(path)
    data = _read(path)
    version, code = parse_pyc(data)
    artifact = dig(data, os.path.basename(path))
    tier = compare(artifact.text, code, version)["tier"] if code else "syntactic"
    return {"version": list(version) if version else None, "kind": artifact.kind,
            "tier": tier, "text": artifact.text}


def _deobfuscate(path: str, out: str | None, allow_write: bool) -> dict:
    from ..engine.dig import dig
    from ..proof import build as build_proof
    _prepare(path)
    data = _read(path)
    artifact = dig(data, os.path.basename(path))
    proof = build_proof(artifact.text, name=os.path.basename(path),
                        digest=__import__("hashlib").sha256(data).hexdigest(),
                        size=len(data), kind=artifact.kind, trace=artifact.trace)
    result = {"kind": artifact.kind, "tier": proof.worst,
              "written": None, "text": artifact.text}
    if allow_write:
        from ..output.save import save
        written = save(artifact.text, path, out)
        from ..proof.write import write as write_proof
        write_proof(proof, written)
        result["written"] = written
        result.pop("text", None)
    elif out:
        result["note"] = "read-only server: start it with --allow-write to save files"
    return result


def call(name: str, arguments: dict, allow_write: bool = False) -> dict:
    """Run one tool.  Returns the MCP ``content`` payload."""
    path = (arguments or {}).get("path")
    if not path:
        raise ValueError("missing required argument: path")
    if name == "identify":
        payload = _identify(path)
    elif name == "peel":
        payload = _peel(path)
    elif name == "triage":
        payload = _triage(path)
    elif name == "decompile_pyc":
        payload = _decompile_pyc(path)
    elif name == "deobfuscate":
        payload = _deobfuscate(path, arguments.get("out"), allow_write)
    else:
        raise ValueError(f"unknown tool: {name}")
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=2)[:200000]}],
            "isError": False}


def handle(request: dict, allow_write: bool = False) -> dict | None:
    """One JSON-RPC message in, one out (or ``None`` for a notification)."""
    method = request.get("method")
    ident = request.get("id")
    params = request.get("params") or {}
    if ident is None and method and method.startswith("notifications/"):
        return None
    try:
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "pydecomp", "version": __version__}}
        elif method == "tools/list":
            result = {"tools": [{"name": name, **spec} for name, spec in TOOLS.items()]}
        elif method == "tools/call":
            result = call(params.get("name", ""), params.get("arguments") or {},
                          allow_write)
        elif method == "ping":
            result = {}
        else:
            return {"jsonrpc": "2.0", "id": ident,
                    "error": {"code": -32601, "message": f"unknown method {method}"}}
    except Exception as exc:                         # noqa: BLE001 - report, do not die
        return {"jsonrpc": "2.0", "id": ident,
                "error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"}}
    return {"jsonrpc": "2.0", "id": ident, "result": result}


def serve(instream=None, outstream=None, allow_write: bool = False) -> int:
    """Read messages until EOF.  Content-Length framing and line framing both work."""
    instream = instream or sys.stdin
    outstream = outstream or sys.stdout
    pending = 0
    while True:
        line = instream.readline()
        if not line:
            return 0
        if isinstance(line, str):
            line = line.encode("utf-8", "replace")
        stripped = line.strip()
        if not stripped:
            continue
        if stripped[:15].lower() == b"content-length:":
            try:
                pending = int(stripped.split(b":", 1)[1])
            except (ValueError, IndexError):
                pending = 0
            continue
        payload = stripped
        if pending:
            while len(payload) < pending:
                more = instream.readline()
                if not more:
                    break
                payload += more
            pending = 0
        try:
            request = json.loads(payload.decode("utf-8", "replace"))
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "parse error"}}
        else:
            if isinstance(request, list):
                replies = [r for r in (handle(item, allow_write) for item in request) if r]
                if not replies:
                    continue
                reply = replies
            else:
                reply = handle(request, allow_write)
                if reply is None:
                    continue
        outstream.write(json.dumps(reply) + "\n")
        outstream.flush()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    return serve(allow_write="--allow-write" in argv)
