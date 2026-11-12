"""Gate: PyArmor 8/9 static unpack, end to end, through the CLI.

The case is a real APK-style layout: the loader beside a
``pyarmor_runtime_000000/`` directory.  The tool must find the runtime by
itself, derive the key, decrypt the payload, lift it, and prove the result.
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import pyarmor_case  # noqa: E402

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def run(*args):
    return subprocess.run([sys.executable, "-m", "pydecomp", *args],
                          capture_output=True, text=True, timeout=600,
                          env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src"),
                               "NO_COLOR": "1", "COLUMNS": "100"})


def sources(folder):
    return [name for name in os.listdir(folder)
            if name.endswith(".py")] if os.path.isdir(folder) else []


work = tempfile.mkdtemp(prefix="pyarmor-gate-")
case = pyarmor_case.build(work)

# 1. the runtime is beside the sample: nothing is asked of the operator
out = os.path.join(work, "out")
done = run(case["loader"], "-o", out, "--no-color", "--no-anim")
ok(done.returncode == 0, f"the loader is analysed: {done.stderr[-400:]}")
ok("pyarmor_runtime" in done.stdout,
   f"the runtime library is named in the run: {done.stdout[:400]}")

recovered = sources(out)
ok(recovered, f"a recovered file exists: {os.listdir(out) if os.path.isdir(out) else []}")
body = open(os.path.join(out, recovered[0]), encoding="utf-8").read() if recovered else ""
ok(case["marker"] in body, "the marker inside the encrypted payload was recovered")
ok("def collect(" in body and "def ship(" in body,
   f"the recovered program is the payload's own code: {body[:300]}")
ok("PYARMOR-FIXTURE" in body, "a payload constant came through")
ok("__pyarmor__(" not in body or "def collect(" in body,
   "the output is the payload, not the bootstrap")
ok("static unpack:" in done.stdout,
   f"the run reports the static unpack stage: {done.stdout[:600]}")

# 2. no runtime beside a copy: it still recovers nothing false, and says why
bare = tempfile.mkdtemp(prefix="pyarmor-bare-")
loader_only = os.path.join(bare, "worker.py")
with open(loader_only, "w", encoding="utf-8") as handle:
    handle.write(pyarmor_case.make_loader(case["blob"]))
bare_out = os.path.join(bare, "out")
bare_done = run(loader_only, "-o", bare_out, "--no-color", "--no-anim")
ok(bare_done.returncode == 0, "a keyless run does not crash")
bare_body = ""
bare_files = sources(bare_out)
if bare_files:
    bare_body = open(os.path.join(bare_out, bare_files[0]), encoding="utf-8").read()
ok(case["marker"] not in bare_body,
   "without the runtime the payload is NOT invented into the output")
ok("runtime" in bare_done.stdout.lower(),
   "the keyless run explains what it would need")

# 3. a supplied key works without any runtime file at all
key_out = os.path.join(bare, "keyed")
keyed = run(loader_only, "-o", key_out, "--pyarmor-key", case["key"].hex(),
            "--no-color", "--no-anim")
key_body = ""
if sources(key_out):
    key_body = open(os.path.join(key_out, sources(key_out)[0]), encoding="utf-8").read()
ok(case["marker"] in key_body, f"--pyarmor-key recovers the payload: {keyed.stdout[-300:]}")

# 4. a wrong key is not accepted
wrong_out = os.path.join(bare, "wrong")
run(loader_only, "-o", wrong_out, "--pyarmor-key", "00" * 16, "--no-color", "--no-anim")
wrong_body = ""
if sources(wrong_out):
    wrong_body = open(os.path.join(wrong_out, sources(wrong_out)[0]),
                      encoding="utf-8").read()
ok(case["marker"] not in wrong_body, "a wrong key produces no payload")

# 5. the proof of the unpacked payload is tier 1
import json  # noqa: E402
if recovered:
    proof = json.load(open(os.path.join(out, recovered[0][:-3] + ".proof.json")))
    ok(proof["tiers"]["semantic"], f"the unpacked payload is proven: {proof['tiers']}")
    ok(any("marshal" in str(layer.get("backend", "")) for layer in proof["layers"]),
       "the proof records the marshal layer")

print()
print("all good" if not FAILED else f"{len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
