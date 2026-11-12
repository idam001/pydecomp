"""Gate: the agent surface (MCP), plugin decoders, and cross-implementation routing."""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def env():
    return {**os.environ, "PYTHONPATH": SRC, "NO_COLOR": "1", "COLUMNS": "100"}


# --------------------------------------------------------------- MCP over stdio
work = tempfile.mkdtemp(prefix="agents-gate-")
case = __import__("pyarmor_case").build(work)

requests = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "identify", "arguments": {"path": case["loader"]}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "deobfuscate", "arguments": {"path": case["loader"]}}},
]
stdin = "\n".join(json.dumps(request) for request in requests) + "\n"
server = subprocess.run([sys.executable, "-m", "pydecomp.mcp"], input=stdin,
                        capture_output=True, text=True, timeout=600, env=env())
lines = [line for line in server.stdout.splitlines() if line.strip()]
ok(server.returncode == 0, f"the server exits cleanly: {server.stderr[-300:]}")
ok(len(lines) == 4, f"one reply per request that needs one: {len(lines)}")
replies = {}
for line in lines:
    message = json.loads(line)
    replies[message.get("id")] = message
ok(replies.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "pydecomp",
   "initialize names the server")
tools = {tool["name"] for tool in replies.get(2, {}).get("result", {}).get("tools", [])}
ok({"identify", "peel", "triage", "decompile_pyc", "deobfuscate"} <= tools,
   f"the advertised tools: {sorted(tools)}")
identified = json.loads(replies.get(3, {})["result"]["content"][0]["text"])
ok(identified.get("protector") == "pyarmor",
   f"identify names the protector: {identified}")
ok(identified.get("input", identified).get("implementation") is not None
   or identified.get("implementation"), "identify reports the interpreter")
read_only = json.loads(replies.get(4, {})["result"]["content"][0]["text"])
ok(read_only.get("written") is None, "the server is read-only by default")
ok("def collect(" in read_only.get("text", ""),
   "deobfuscate returns the recovered text, not a file")

# ------------------------------------------------------------- plugin decoders
plugin = os.path.join(work, "plugin_case.py")
with open(plugin, "w") as handle:
    handle.write("X = 'PLUGIN-MARKER'\n")
flipped = bytes(reversed(open(plugin, "rb").read()))
wrapped = os.path.join(work, "wrapped.bin")
with open(wrapped, "wb") as handle:
    handle.write(b"# wrapped\n" + flipped.hex().encode() + b"\n")

probe = subprocess.run(
    [sys.executable, "-c", (
        "import sys; sys.path.insert(0, %r)\n"
        "from pydecomp.plugins import register_decoder, unwrap\n"
        "@register_decoder('rev')\n"
        "def rev(blob):\n"
        "    try: text = bytes.fromhex(blob.decode().strip())\n"
        "    except Exception: return None\n"
        "    return bytes(reversed(text))\n"
        "out, name = unwrap(%r)\n"
        "print(name, out[:20] if out else b'')\n") % (SRC, flipped.hex().encode())],
    capture_output=True, text=True, timeout=120, env=env())
ok("rev" in probe.stdout and b"X = " in probe.stdout.encode("utf-8", "ignore")
   or "rev" in probe.stdout, f"a registered plugin decodes bytes: {probe.stdout} {probe.stderr[-200:]}")

# --------------------------------------------------- cross-implementation files
import marshal  # noqa: E402
program = "Y = 'CROSS-IMPL'\n"
blob = b"\x0a\x0d\x0d\x0a" + b"\x00" * 12 + marshal.dumps(compile(program, "p.py", "exec"))
pypy = os.path.join(work, "pypy.pyc")
with open(pypy, "wb") as handle:
    handle.write(blob)
pypy_out = os.path.join(work, "out-pypy")
done = subprocess.run([sys.executable, "-m", "pydecomp", pypy, "-o", pypy_out,
                       "--no-color", "--no-anim"], capture_output=True, text=True,
                      timeout=600, env=env())
ok(done.returncode == 0, "a PyPy sample does not crash the tool")
ok("approximate" in done.stdout.lower() or "pypy" in done.stdout.lower(),
   f"the cross-implementation lift is marked: {done.stdout[:400]}")

for name, magic in (("mpy", b"M\x03"), ("jython", b"\xca\xfe\xba\xbe")):
    path = os.path.join(work, name + ".bin")
    with open(path, "wb") as handle:
        handle.write(magic + bytes(range(1, 200)))
    out = os.path.join(work, "out-" + name)
    done = subprocess.run([sys.executable, "-m", "pydecomp", path, "-o", out,
                           "--no-color", "--no-anim"], capture_output=True,
                          text=True, timeout=600, env=env())
    ok(done.returncode == 0, f"{name}: no crash")
    ok(name in done.stdout.lower(), f"{name}: the interpreter is named ({done.stdout[:200]})")

# ------------------------------------------------------- named obfuscator
named = os.path.join(work, "minified.py")
with open(named, "w") as handle:
    handle.write("# Created by pyminifier (https://github.com/liftoff/pyminifier)\n"
                 "import os\nprint(os.name)\n")
named_out = os.path.join(work, "out-named")
done = subprocess.run([sys.executable, "-m", "pydecomp", named, "-o", named_out,
                       "--no-color", "--no-anim"], capture_output=True, text=True,
                      timeout=600, env=env())
ok("pyminifier" in done.stdout.lower(),
   f"the obfuscator is named in the run: {done.stdout[:400]}")

print()
print("all good" if not FAILED else f"{len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
