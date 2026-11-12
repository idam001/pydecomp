"""Gate: an adversarial packer must never be answered with a fake success.

Three shapes that used to fool the tool, each generated on the fly so the gate
needs no binary fixtures:

1. **version gate with a decoy branch** — ``exec(payload) if sys.version[:4] ==
   '3.13' else 'print("install python 3.13")'``.  The evaluator used to answer
   as 3.14, take the decoy, and report a one-line warning as the recovered
   program.  Correct behaviour: recover the real payload.
2. **sealed payload** — the exec'd module carries a large opaque blob, so what
   we can lift is the packer's loader, not the script.  Correct behaviour: say
   so, name the output ``_loader``, never claim verification — and still hand
   back the intelligence the payload's own name table gives up (``_intel.txt``).
3. **nothing to unpack** — a file that already reads as source.  Correct
   behaviour: save a copy and say "no layer recognised", not "verified".
"""
import base64
import json
import marshal
import os
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUNDLE = os.path.join(ROOT, "dist", "pydecomp.py")
FAILED = []

PAYLOAD = '''MARKER = "recovered-payload-9c3f"

def work(value):
    return MARKER + str(value)
'''


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def run(sample, out, *extra):
    return subprocess.run([sys.executable, BUNDLE, sample, "-o", out, "--no-color",
                           "--no-anim", "--reports", *extra],
                          capture_output=True, text=True, timeout=600,
                          env={**os.environ, "COLUMNS": "100", "NO_COLOR": "1"})


def version_gate_sample(path):
    blob = base64.b64encode(zlib.compress(marshal.dumps(compile(PAYLOAD, "<payload>", "exec")))).decode()
    here = f"{sys.version_info[0]}.{sys.version_info[1]}"
    source = (
        "import sys\n"
        "try:\n"
        f"    exec(__import__('marshal').loads(__import__('zlib').decompress("
        f"__import__('base64').b64decode('{blob}')))) if str(sys.version[0:4]) == '{here}' "
        f"else 'print(\"you need python {here}\")'\n"
        "except Exception as exc:\n"
        "    print(exc)\n"
    )
    with open(path, "w") as handle:
        handle.write(source)
    return path


def sealed_sample(path):
    filler = os.urandom(12288)
    inner = ("SEALED = " + repr(filler) + "\n"
             "def reveal():\n"
             "    return len(SEALED)\n")
    blob = base64.b64encode(zlib.compress(marshal.dumps(compile(inner, "<sealed>", "exec")))).decode()
    source = (
        "import base64, marshal, zlib\n"
        f"exec(marshal.loads(zlib.decompress(base64.b64decode('{blob}'))))\n"
    )
    with open(path, "w") as handle:
        handle.write(source)
    return path


def main():
    work = tempfile.mkdtemp()

    # 1. the decoy branch must not win
    sample = version_gate_sample(os.path.join(work, "gated.py"))
    out = os.path.join(work, "gated_out")
    done = run(sample, out)
    ok(done.returncode == 0, "gated sample runs")
    produced = [n for n in os.listdir(out)] if os.path.isdir(out) else []
    recovered = [n for n in produced if n.endswith(".py")]
    ok(len(recovered) == 1, "gated sample produced one file")
    if recovered:
        text = open(os.path.join(out, recovered[0]), encoding="utf-8",
                    errors="surrogateescape").read()
        ok("recovered-payload-9c3f" in text, "the real payload was recovered")
        ok("you need python" not in text, "the decoy branch was not taken")
        ok("def work" in text, "the payload's function survived")
        ok("NOT VERIFIED" not in done.stdout, "a real payload is not flagged as sealed")

    # 2. a sealed payload must be reported, not dressed up
    sealed = sealed_sample(os.path.join(work, "sealed.py"))
    out2 = os.path.join(work, "sealed_out")
    done2 = run(sealed, out2)
    ok(done2.returncode == 0, "sealed sample runs")
    ok("still encrypted" in done2.stdout, "the sealed payload is called out")
    ok("NOT VERIFIED" in done2.stdout, "fidelity refuses to verify a loader")
    files2 = os.listdir(out2) if os.path.isdir(out2) else []
    ok(any(name.endswith(".py") and "_loader" in name for name in files2),
       "the loader is not named like a recovery")
    ok(not any(name.endswith("_deob.py") for name in files2),
       "no file claims to be the deobfuscated script")
    reports = [n for n in files2 if n.endswith(".report.json")]
    if reports:
        data = json.load(open(os.path.join(out2, reports[0]), encoding="utf-8"))
        recovered = data.get("recovered") or {}
        ok(recovered.get("complete") is False, "the report says the recovery is incomplete")
        ok((data.get("fidelity") or {}).get("kept") == "unverified",
           "the report marks the fidelity as unverified")

    # 2b. a sealed payload still yields intelligence, and it says so plainly
    intel_files = [n for n in files2 if n.endswith("_intel.txt")]
    ok(len(intel_files) == 1, "sealed sample wrote exactly one intel file")
    if intel_files:
        intel_text = open(os.path.join(out2, intel_files[0]), encoding="utf-8").read()
        ok("Nothing here is recovered code" in intel_text,
           "the intel file never claims to be a recovery")
        ok("reveal" in intel_text, "the payload's own names reached the intel file")
        ok(len(intel_text) < 40_000 and "SEALED = b" not in intel_text,
           "the intel file carries no ciphertext")
    if intel_files:
        ok("## sealed blobs" in intel_text,
           "the intel file classifies the sealed blob instead of just counting it")
    if reports:
        data = json.load(open(os.path.join(out2, reports[0]), encoding="utf-8"))
        ok(bool(data.get("intel")), "the report records the intel summary")
        ok(bool(data.get("sealed_kinds")), "the report records the sealed blob kinds")

    # 3. nothing to unpack is not a recovery
    plain = os.path.join(work, "plain.py")
    with open(plain, "w") as handle:
        handle.write("def add(a, b):\n    return a + b\n")
    out3 = os.path.join(work, "plain_out")
    done3 = run(plain, out3)
    ok(done3.returncode == 0, "plain sample runs")
    ok("no layer recognised" in done3.stdout, "a plain file is not called a recovery")
    ok("still the recovered program" not in done3.stdout,
       "a byte-identical copy is never called verified")
    files3 = os.listdir(out3) if os.path.isdir(out3) else []
    ok(any(name.endswith(".py") and "_copy" in name for name in files3),
       "the untouched file is saved as a copy")

    # 4. cleaning must never delete live code from a plain program
    plain_branch = os.path.join(work, "branchy.py")
    with open(plain_branch, "w") as handle:
        handle.write(
            "def run(words):\n"
            "    out = []\n"
            "    for word in words:\n"
            "        if isinstance(word, str):\n"
            "            out.append(word)\n"
            "        elif word == 34:\n"
            "            out.append('seen-thirty-four')\n"
            "    return out\n")
    out4 = os.path.join(work, "branchy_out")
    done4 = run(plain_branch, out4)
    ok(done4.returncode == 0, "branchy sample runs")
    files4 = os.listdir(out4) if os.path.isdir(out4) else []
    body4 = ""
    for name4 in files4:
        if name4.endswith(".py"):
            body4 = open(os.path.join(out4, name4), encoding="utf-8").read()
    ok("seen-thirty-four" in body4,
       "a free name compared to a literal is not treated as an opaque predicate")
    ok("word == 34" in body4, "the live elif survived cleaning")

    # 5. a key computed at run time is enumerated, not declared impossible
    runtime_key = os.path.join(work, "runtime_key.py")
    secret = 'print("runtime-key-recovered-77aa")'
    with open(runtime_key, "w") as handle:
        handle.write("import os\n"
                     "_k = len(os.urandom(16))\n"
                     f"_d = {bytes(byte ^ 16 for byte in secret.encode())!r}\n"
                     "exec(bytes(c ^ _k for c in _d).decode())\n")
    out5 = os.path.join(work, "runtime_key_out")
    done5 = run(runtime_key, out5)
    ok(done5.returncode == 0, "runtime-key sample runs")
    ok("run-time key" in done5.stdout, "the enumeration is reported, not hidden")
    body5 = "".join(open(os.path.join(out5, name5), encoding="utf-8").read()
                    for name5 in (os.listdir(out5) if os.path.isdir(out5) else [])
                    if name5.endswith(".py"))
    ok("runtime-key-recovered-77aa" in body5, "the run-time key was enumerated and opened")
    ok("copy — nothing unpacked" not in done5.stdout,
       "an enumerated payload is a recovery, not a copy")

    # 6. a payload inside a native blob is carved out
    native = os.path.join(work, "packed.so")
    inner = compile('print("carved-native-4b1c")', "<payload>", "exec")
    with open(native, "wb") as handle:
        handle.write(os.urandom(1024) + zlib.compress(marshal.dumps(inner))
                     + os.urandom(128))
    out6 = os.path.join(work, "native_out")
    done6 = run(native, out6)
    ok(done6.returncode == 0, "native blob runs")
    ok("carved a" in done6.stdout, "the carve stage reports what it found")
    body6 = "".join(open(os.path.join(out6, name6), encoding="utf-8").read()
                    for name6 in (os.listdir(out6) if os.path.isdir(out6) else [])
                    if name6.endswith(".py"))
    ok("carved-native-4b1c" in body6, "the carved payload was recovered")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print(f"\n{31} checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
