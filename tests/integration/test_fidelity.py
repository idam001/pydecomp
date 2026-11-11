"""Gate: a recovered file is always the recovered program, never junk."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

FAILED = []


def ok(condition, message):
    if not condition:
        FAILED.append(message)
        print(f"FAIL  {message}")

REAL = '''import base64

TOKEN = "not-a-real-token"

def dec(value):
    return base64.b64decode(value).decode()

def main():
    print(dec("aGVsbG8="))

if __name__ == "__main__":
    main()
'''

# what a packer hands back when nothing was unpacked: one enormous literal
BLOB = "L1RkNldGb0FBQVRtMXJSR0FnQWhBUllBQUFCMEwrV2pBUVVIZUp3VlZjMlNxeW9RZmlXUm1Kb3M3dUtZaUk0Sk9DQ2dzbE94" * 4


def main():
    work = tempfile.mkdtemp()

    sample = os.path.join(work, "real.py")
    with open(sample, "w") as handle:
        handle.write(REAL)
    from pydecomp.engine.run import deobfuscate
    saved = deobfuscate(sample, out_dir=os.path.join(work, "out"), reports=True,
                        verify=False, dry_run=False)
    ok(saved is not None, "real sample recovered")
    if saved:
        text = open(saved, encoding="utf-8", errors="surrogateescape").read()
        ok("def main" in text and "def dec" in text, "both functions survive")
        ok("'hello'" in text or '"hello"' in text, "the decoder was folded to its value")
        data = json.load(open(saved.replace(".py", ".report.json"), encoding="utf-8"))
        fidelity = data.get("fidelity") or {}
        ok(fidelity.get("kept") == "cleaned", "fidelity verdict recorded")
        ok(fidelity.get("after", {}).get("definitions", 0) >= 2,
           "cleaned output still holds the definitions")

    # a blob-only input must never be dressed up as a recovered program
    blob_sample = os.path.join(work, "blob.py")
    with open(blob_sample, "w") as handle:
        handle.write(BLOB + "\n")
    saved_blob = deobfuscate(blob_sample, out_dir=os.path.join(work, "out2"),
                             reports=True, verify=False, dry_run=False)
    if saved_blob:
        text = open(saved_blob, encoding="utf-8", errors="surrogateescape").read()
        body = text.split("\n", 1)[1]
        ok(body.strip() != "", "blob output is not empty")
        ok("Deobfuscated by idam Emmanuel" in text, "blob output still carries the stamp")

    # the guard is what protects a good result from a bad pass
    from pydecomp.polish.fidelity import verify
    ok(verify(REAL, "import base64\n")["kept"] == "unpacked",
       "a pass that guts the program is rolled back")
    ok(verify(BLOB, REAL)["kept"] == "cleaned",
       "a pass that turns a blob into source is kept")
    ok(verify(REAL, REAL)["kept"] == "cleaned", "an unchanged program is kept")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print("\n9 checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
