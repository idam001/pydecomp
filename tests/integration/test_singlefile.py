"""Gate: the one file you download behaves like the checkout (phone/Air-gapped box)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUNDLE = os.path.join(ROOT, "dist", "pydecomp.py")
FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")


def run(*args):
    return subprocess.run([sys.executable, BUNDLE, *args], capture_output=True,
                          text=True, env={**os.environ, "NO_COLOR": "1"})


SAMPLE = '''import base64
SECRET = "w4t9-hidden-token"
def payload():
    return base64.b64decode("cHJpbnQoJ2hpJyk=").decode()
def main():
    print(payload())
main()
'''


def main():
    ok(os.path.isfile(BUNDLE), "bundle exists — run tools/build_single.py")
    if not os.path.isfile(BUNDLE):
        return 1

    # 1. it is one file, and it says what it is
    version = run("--version")
    ok(version.returncode == 0, "bundle runs standalone")
    ok("pydecomp" in version.stdout.lower(), "bundle reports its name")

    # 2. the health check must work when the sidecar has no __file__
    selftest = run("--selftest")
    ok(selftest.returncode == 0, f"--selftest exits 0 (got {selftest.returncode})")
    ok("Traceback" not in selftest.stderr, "--selftest does not crash")
    ok("native" in selftest.stdout.lower(), "--selftest reports the native layer")

    # 3. a real recovery, from a different working directory, with no package beside it
    work = tempfile.mkdtemp()
    sample = os.path.join(work, "sample.py")
    with open(sample, "w") as handle:
        handle.write(SAMPLE)
    out = os.path.join(work, "out")
    done = subprocess.run([sys.executable, BUNDLE, sample, "-o", out, "--reports",
                           "--yara", "--diff", "--no-color", "--no-anim"],
                          capture_output=True, text=True, cwd=work,
                          env={**os.environ, "NO_COLOR": "1"})
    ok(done.returncode == 0, "bundle deobfuscates a sample")
    produced = [name for name in os.listdir(out)] if os.path.isdir(out) else []
    recovered = [name for name in produced if name.endswith("_deob.py")]
    ok(len(recovered) == 1, "one recovered file written")
    if recovered:
        text = open(os.path.join(out, recovered[0]), encoding="utf-8",
                    errors="surrogateescape").read()
        body = text.split("\n", 1)[1]
        compile(body, recovered[0], "exec")
        ok("def payload" in body, "recovered program keeps its functions")
        ok("Deobfuscated by" in text, "the stamp is present")
        report_path = os.path.join(out, recovered[0].replace(".py", ".report.json"))
        report = json.load(open(report_path, encoding="utf-8"))
        ok("fidelity" in report, "report carries the fidelity verdict")
        ok((report.get("fidelity") or {}).get("kept") == "cleaned",
           "recovered output is the cleaned program, not a rollback")

    # 4. downloading it twice gives the same bytes — no build drift
    first = hashlib.sha256(open(BUNDLE, "rb").read()).hexdigest()
    check = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_single.py"),
                            "--check"], capture_output=True, text=True)
    ok(check.returncode == 0, "bundle matches the checkout (build --check)")
    ok(first == hashlib.sha256(open(BUNDLE, "rb").read()).hexdigest(),
       "bundle unchanged by the check")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print("\n10 checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
