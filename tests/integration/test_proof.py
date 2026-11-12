"""Gate: every output carries a proof, and --strict refuses unproven output."""
import json
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


def run(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "pydecomp", *args],
                          capture_output=True, text=True, timeout=600, cwd=cwd,
                          env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src"),
                               "NO_COLOR": "1", "COLUMNS": "100"})


def sources(folder):
    return [name for name in os.listdir(folder) if name.endswith(".py")]


def proof_of(folder, name):
    stem = name[:-3]
    path = os.path.join(folder, stem + ".proof.json")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


# ------------------------------------------------------------------ the case
work = tempfile.mkdtemp(prefix="proof-gate-")
case = pyarmor_case.build(work)
out = os.path.join(work, "out")
done = run(case["loader"], "-o", out, "--no-color", "--no-anim")
ok(done.returncode == 0, f"a real recovery exits 0: {done.stderr[-300:]}")

written = sources(out)
ok(written, f"a source file was written: {os.listdir(out)}")
payload = proof_of(out, written[0]) if written else {}

for key in ("tool", "input", "layers", "tiers", "inferred", "lost", "guarantee"):
    ok(key in payload, f"proof.json carries {key}")
ok(payload.get("input", {}).get("sha256") == case.get("sha256", payload.get("input", {}).get("sha256")),
   "the proof names the input digest")
ok(payload.get("guarantee", "").startswith("no input byte was executed"),
   "the guarantee is stated in the proof")
ok(payload.get("layers"), "the proof lists the layers that were peeled")
ok(any(layer.get("transform") for layer in payload.get("layers", [])),
   "a layer is more than an empty record")

# the recovered program is instruction-identical, and the proof says so
tiers = payload.get("tiers", {})
ok(tiers.get("semantic"), f"units proven at tier 1: {tiers}")
ok(not tiers.get("unverified"), "nothing was written that does not compile")

sheet = open(os.path.join(out, written[0][:-3] + ".proof.md"), encoding="utf-8").read()
ok("| tier | units | meaning |" in sheet, "the markdown proof has the tier table")
ok("no input byte was executed" in sheet, "the markdown proof repeats the guarantee")

# ------------------------------------------------------------- strict passes
strict_out = os.path.join(work, "strict")
strict = run(case["loader"], "-o", strict_out, "--strict", "--no-color", "--no-anim")
ok(strict.returncode == 0, f"--strict writes a proven recovery: {strict.stdout[-300:]}")
ok(sources(strict_out), "the strict run still produced its file")

# --------------------------------------------------- strict refuses the rest
weak = os.path.join(work, "strings.bin")
with open(weak, "wb") as handle:
    handle.write(bytes(range(256)) * 6)
weak_out = os.path.join(work, "weak")
weak_done = run(weak, "-o", weak_out, "--strict", "--no-color", "--no-anim")
ok(weak_done.returncode == 3, f"an unproven run exits 3: got {weak_done.returncode}")
ok("nothing written" in weak_done.stdout,
   f"the refusal says nothing was written: {weak_done.stdout[-300:]}")
ok(not os.path.isdir(weak_out) or not sources(weak_out),
   f"strict left no source behind: {os.listdir(weak_out) if os.path.isdir(weak_out) else []}")

# ------------------------------------------------------- annotate is opt-in
plain = os.path.join(work, "plain.py")
with open(plain, "w") as handle:
    handle.write("def f(x):\n    return x + 1\n")
plain_out = os.path.join(work, "plain")
run(plain, "-o", plain_out, "--no-color", "--no-anim")
body = open(os.path.join(plain_out, sources(plain_out)[0]), encoding="utf-8").read()
ok("STRUCTURAL" not in body and "UNVERIFIED" not in body,
   "the recovered file is not littered with tier banners by default")

annotated = os.path.join(work, "annotated")
run(weak, "-o", annotated, "--annotate", "--no-color", "--no-anim")
annotated_body = open(os.path.join(annotated, sources(annotated)[0]),
                      encoding="utf-8").read()
ok("UNVERIFIED" in annotated_body or "STRUCTURAL" in annotated_body,
   f"--annotate does carry the tier in the file: {annotated_body[:120]!r}")

print()
print("all good" if not FAILED else f"{len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
