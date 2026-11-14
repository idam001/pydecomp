"""The proof is the product: it has to be right, and it has to be checkable."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pydecomp.bytecode.codeobj import codeobj_from_host  # noqa: E402
from pydecomp.proof import build, failure, grade, write  # noqa: E402
from pydecomp.proof.tiers import TIER_RANK, compare, host_version  # noqa: E402

PROGRAM = """\
def add(a, b):
    return a + b


def total(rows):
    out = 0
    for row in rows:
        out += row
    return out
"""


def _code(text: str):
    return codeobj_from_host(compile(text, "<t>", "exec"))


def test_self_comparison_is_perfect():
    text = PROGRAM
    result = compare(text, _code(text))
    assert result["tier"] == "perfect"
    assert result["tier_0_units"]
    assert result["perfect_match"].split("/")[0] == result["perfect_match"].split("/")[1].split()[0]


def test_renamed_local_is_structural():
    """Same instructions, same constants, different operand spellings."""
    renamed = PROGRAM.replace("out", "acc").replace("row", "item")
    assert compare(renamed, _code(PROGRAM))["tier"] in ("structural", "syntactic")
    graded = compare(renamed, _code(PROGRAM))
    assert graded["units"], graded


def test_changed_constant_is_not_semantic():
    changed = PROGRAM.replace("return a + b", "return a * b")
    assert compare(changed, _code(PROGRAM))["tier"] != "semantic"



def test_jump_target_drift_is_semantic_not_perfect():
    import copy
    from pydecomp.bytecode.disassembler import disassemble

    source = "def f(x):\n    if x:\n        return 1\n    return 2\n"
    original = _code(source)
    nested = next(item for item in original.consts if hasattr(item, "code"))
    changed_nested = copy.copy(nested)
    changed_nested.code = bytearray(nested.code)
    jumps = [offset for offset, op, _arg, _text in disassemble(nested, host_version())
             if "JUMP" in op or op in ("FOR_ITER", "SEND")]
    assert jumps
    changed_nested.code[jumps[0] + 1] ^= 1
    changed = copy.copy(original)
    changed.consts = tuple(changed_nested if item is nested else item
                           for item in original.consts)
    result = compare(source, changed)
    assert result["tier"] in ("semantic", "structural")
    assert result["tier"] != "perfect"
    assert result["perfect_match"] != "0/0 instructions identical"


def test_perfect_requirement_rejects_semantic_only_output():
    proof = build(PROGRAM.replace("return a + b", "return a * b"),
                  name="t.py", digest="d" * 64, size=10, kind="source", trace=[])
    assert proof.worst != "perfect"
    assert failure(proof, "perfect") is not None

def test_syntax_error_is_unverified():
    assert grade("def broken(:\n") == "unverified"


def test_order_is_semantic_structural_syntactic_unverified():
    assert TIER_RANK["perfect"] < TIER_RANK["semantic"] < TIER_RANK["structural"] \
        < TIER_RANK["syntactic"] < TIER_RANK["unverified"]


def test_proof_schema():
    proof = build(PROGRAM, name="t.py", digest="b" * 64, size=len(PROGRAM),
                  kind="source", trace=["layer 1: base64 → zlib · 12 B"])
    payload = proof.as_dict()
    for key in ("tool", "input", "layers", "tiers", "inferred", "lost", "guarantee"):
        assert key in payload, key
    assert payload["input"]["sha256"] == "b" * 64
    assert set(payload["tiers"]) == {"perfect", "semantic", "structural", "syntactic", "unverified"}
    assert "tier_0_units" in payload and "perfect_match" in payload
    assert "no input byte was executed" in payload["guarantee"]
    assert json.loads(json.dumps(payload))["tool"].startswith("pydecomp ")
    assert payload["layers"][0]["transform"] == "base64"


def test_identity_marks_semantic():
    proof = build(PROGRAM, name="t.py", digest="c" * 64, size=10, kind="source",
                  trace=[], identity=True)
    assert proof.worst == "perfect"
    assert proof.proven
    assert "byte-identical" in proof.markdown()


def test_strict_failure_names_the_tier():
    proof = build("def broken(:\n", name="t.py", digest="d" * 64, size=4,
                  kind="source", trace=[])
    why = failure(proof, "semantic")
    assert why and "unverified" in why
    assert proof.counts["unverified"] == 1


def test_strict_passes_for_proven_output():
    proof = build(PROGRAM, name="t.py", digest="e" * 64, size=10, kind="source",
                  trace=[], identity=True)
    assert failure(proof, "semantic") is None
    assert failure(proof, "perfect") is None


def test_markdown_lists_lost_and_inferred():
    proof = build("x = 1\n", name="t.py", digest="f" * 64, size=6, kind="strings",
                  trace=[], notes=["renamed 2 names"])
    sheet = proof.markdown()
    assert "## lost in the original encoding" in sheet
    assert "## inferred (marked, not invented)" in sheet
    assert "the program itself" in sheet


def test_write_produces_both_files(tmp_path=None):
    import tempfile
    folder = tmp_path or tempfile.mkdtemp()
    output = os.path.join(str(folder), "sample_deob.py")
    open(output, "w").close()
    proof = build("x = 1\n", name="sample.py", digest="a" * 64, size=6,
                  kind="source", trace=[])
    written = write(proof, output)
    assert set(written) == {"proof_json", "proof_md"}
    payload = json.load(open(written["proof_json"]))
    assert payload["output"]["name"] == "sample_deob.py"
    assert "| tier | units | meaning |" in open(written["proof_md"]).read()


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


def test_perfect_flag_reaches_the_single_file_engine(monkeypatch):
    from pydecomp import cli

    calls = {}
    monkeypatch.setattr(cli, "deobfuscate",
                        lambda *args, **kwargs: calls.update(kwargs) or "written.py")
    monkeypatch.setattr(cli, "USE_COLOR", False)
    monkeypatch.setattr(cli, "INTERACTIVE", False)
    assert cli.main(["input.py", "--perfect", "--no-color", "--no-anim"]) == 0
    assert calls["perfect"] is True


def test_perfect_refusal_sets_exit_two_and_writes_nothing(tmp_path, monkeypatch):
    from pydecomp import proof as proof_module
    from pydecomp.engine import run
    from pydecomp.proof.model import Proof

    sample = tmp_path / "sample.py"
    sample.write_text("value = 1\n", encoding="utf-8")

    def structural(text, **kwargs):
        result = Proof("pydecomp test", "sample.py", "a" * 64, len(text))
        result.mark("<module>", "structural", "fixture")
        return result

    monkeypatch.setattr(proof_module, "build", structural)
    output = tmp_path / "out"
    assert run.deobfuscate(str(sample), str(output), clean=False, reports=False,
                           perfect=True, proof=False) is None
    assert run.EXIT_CODE == 2
    assert not output.exists()
