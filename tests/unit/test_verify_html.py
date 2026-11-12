"""A proof must be checkable by a stranger, and the report must open offline."""
from __future__ import annotations

import glob
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.output import html as html_report  # noqa: E402
from pydecomp.proof.verify import render, summary, verify  # noqa: E402

PROGRAM = '''\
def add(a, b):
    return a + b
'''


def _proof_of(written: str) -> str:
    return glob.glob(os.path.join(os.path.dirname(written), "*.proof.json"))[0]


def _recover(folder: str) -> str:
    from pydecomp.engine.run import deobfuscate
    source = os.path.join(folder, "sample.py")
    with open(source, "w") as handle:
        handle.write(PROGRAM)
    out = os.path.join(folder, "out")
    return deobfuscate(source, out, clean=False, reports=False, html_report=True)


def test_verify_reproduces_a_real_proof():
    folder = tempfile.mkdtemp(prefix="verify-")
    written = _recover(folder)
    proof = _proof_of(written)
    result = verify(proof)
    assert result["ok"], result
    assert any(item["check"] == "tiers reproduce" and item["ok"]
               for item in result["checks"]), result["checks"]
    assert "verified" in summary(result)
    assert "ok   schema" in render(result)


def test_verify_notices_a_changed_output():
    folder = tempfile.mkdtemp(prefix="verify-tamper-")
    written = _recover(folder)
    proof = _proof_of(written)
    with open(written, "a", encoding="utf-8") as handle:
        handle.write("\nprint('smuggled')\n")
    result = verify(proof)
    assert not result["ok"]
    failed = [item["check"] for item in result["checks"] if not item["ok"]]
    assert "output sha256" in failed, failed
    assert "DRIFT" in summary(result)


def test_verify_survives_a_missing_input():
    folder = tempfile.mkdtemp(prefix="verify-missing-")
    written = _recover(folder)
    proof_path = _proof_of(written)
    payload = json.load(open(proof_path))
    payload["input"]["path"] = os.path.join(folder, "gone.py")
    with open(proof_path, "w") as handle:
        json.dump(payload, handle)
    result = verify(proof_path)
    assert not result["ok"] and "not on disk" in result["message"]


def test_verify_rejects_a_broken_proof_file():
    folder = tempfile.mkdtemp(prefix="verify-bad-")
    path = os.path.join(folder, "broken.proof.json")
    with open(path, "w") as handle:
        handle.write("{not json")
    result = verify(path)
    assert not result["ok"] and "unreadable" in result["message"]


def test_html_report_is_self_contained():
    folder = tempfile.mkdtemp(prefix="html-")
    written = _recover(folder)
    proof = json.load(open(_proof_of(written)))
    document = html_report.render("sample.py", PROGRAM, proof, {"iocs": {}})
    assert document.startswith("<!doctype html>")
    for token in ("def add(a, b):", "no input byte was executed",
                  "semantic", "recovered source", "verdict"):
        assert token in document, token
    # nothing may be fetched when the report is opened
    assert "http://" not in document.split("</style>")[1]
    assert "https://" not in document.split("</style>")[1]
    assert "<script" not in document.lower()


def test_html_write_lands_beside_the_source():
    folder = tempfile.mkdtemp(prefix="html-write-")
    written = _recover(folder)
    path = glob.glob(os.path.join(os.path.dirname(written), "*.report.html"))[0]
    assert os.path.exists(path), os.listdir(os.path.dirname(written))
    assert "pydecomp" in open(path, encoding="utf-8").read()


if __name__ == "__main__":
    failures = 0
    for name, function in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            function()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print("all good" if not failures else f"{failures} failed")
    sys.exit(1 if failures else 0)
