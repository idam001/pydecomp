# MCP server (agents)

pydecomp speaks MCP over stdio, so an agent gets the same answers a person does:

```console
$ python -m pydecomp.mcp                 # read-only
$ python -m pydecomp.mcp --allow-write   # may save recovered files
$ pydecomp --mcp                         # same thing from the CLI
```

## Tools

| tool | returns |
|---|---|
| `identify` | implementation, protector, freezer, sha256, size |
| `peel` | the layers between the file and its program, and whether the payload is sealed |
| `triage` | fingerprint, indicators, behaviour, imports |
| `decompile_pyc` | the source **and its proof tier** |
| `deobfuscate` | recovered text (read-only) or a written file with `--allow-write` |

Read-only is the default because an agent should be able to look without
touching the disk. `deobfuscate` with an `out` folder but no `--allow-write`
returns the text and a note saying so.

## Handshake

```console
$ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"identify","arguments":{"path":"worker.py"}}}' \
  | python -m pydecomp.mcp
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05", …}}
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"protector\": \"pyarmor\", …}"}]}}
```

Both line framing and `Content-Length` framing are accepted; notifications get no
reply; an unknown method returns JSON-RPC `-32601` instead of dying.

## Registering it

The server is a plain stdio program, so any MCP client can point at it:

```json
{"mcpServers": {"pydecomp": {"command": "python", "args": ["-m", "pydecomp.mcp"]}}}
```

Every tool goes through `engine.dig`, and every tool that can recover code
attaches a proof — an agent can therefore gate its own actions on `tier ==
"semantic"` instead of trusting a blob of text.
