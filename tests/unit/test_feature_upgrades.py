from __future__ import annotations

import io
import json
import os
import py_compile
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from pydecomp.bytecode.dump import dump_pyc
from pydecomp.bytecode.target import check_source, parse_versions
from pydecomp.containers import base as containers
from pydecomp.engine import dig as dig_module
from pydecomp.plugins.backends import pylingual
from pydecomp.triage import confidence, methods
from pydecomp.triage.compare import compare_text, render
from pydecomp.triage.iocs import extract
from pydecomp.triage.recipe import build as build_recipe
from pydecomp.triage.source_map import build as build_source_map


def _pyc(tmp_path: Path) -> Path:
    source = tmp_path / "small.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    target = tmp_path / "small.pyc"
    py_compile.compile(str(source), cfile=str(target), doraise=True)
    return target


def test_pyc_disassembly_is_versioned_bounded_and_static(tmp_path):
    result = dump_pyc(_pyc(tmp_path).read_bytes())
    assert "pyc-disassembly: CPython" in result
    assert "execution: none" in result
    assert "code-object 'add'" in result
    assert "BINARY_OP" in result or "BINARY_ADD" in result


def test_disassembly_refuses_a_truncated_or_unknown_pyc(tmp_path):
    with pytest.raises(ValueError):
        dump_pyc(b"not a pyc at all")
    good = _pyc(tmp_path).read_bytes()
    with pytest.raises(ValueError):
        dump_pyc(good[:6])                       # magic there, code object gone


def test_archive_member_that_lies_about_its_size_is_refused(monkeypatch):
    monkeypatch.setattr(containers, "MAX_ARCHIVE_ENTRY_BYTES", 64)
    monkeypatch.setattr(containers, "MAX_ARCHIVE_TOTAL_BYTES", 4096)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.py", b"\x00" * 4096)   # 4 KiB from 41 bytes on disk
    raw = bytearray(archive.getvalue())
    import struct
    # rewrite the declared uncompressed size with a value more flattering than the truth
    central = raw.find(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 4)  # declared 4 bytes, really 4096
    entries = containers.FreezerReader()._from_zip(bytes(raw))
    assert all(len(payload) <= 64 for _name, payload in entries)


def test_target_version_check_is_compile_only():
    versions = parse_versions("3.9, 3.10")
    assert versions == [(3, 9), (3, 10)]
    code = b"match 1:\n    case 1:\n        answer = 42\n"
    results = check_source(code, versions)
    by_version = {item["version"]: item["status"] for item in results}
    assert by_version["3.9"] == "invalid"
    assert by_version["3.10"] == "ok"
    assert parse_versions("3.13")[0] == (3, 13)
    with pytest.raises(ValueError):
        parse_versions("3.x")


def test_compare_reports_ast_function_and_indicator_changes():
    left = "def keep():\n    return 1\n\nurl = 'https://one.example/a'\n"
    right = "def keep():\n    return 2\n\ndef added():\n    return 3\n\nurl = 'https://two.example/b'\n"
    report = compare_text(left, right, "a.py", "b.py")
    assert report["functions"]["added"] == ["added"]
    assert report["functions"]["changed"] == ["keep"]
    assert report["iocs"]
    assert "functions changed: keep" in render(report)
    assert not report["same_text"]


def test_ioc_evidence_points_to_recovered_source_line():
    source = "title = 'safe'\nurl = 'https://evil.example/path'\n"
    sheet = extract(source)
    evidence = sheet["evidence"]["url"]
    assert evidence[0]["origin"] == "recovered source"
    assert evidence[0]["line"] == 2


def test_recipe_has_only_stable_hashes_and_steps():
    raw = b"original bytes"
    output = "print('static')\n"
    recipe = build_recipe(raw, output, ["layer 1: base64 → zlib · 20 B"])
    assert recipe["schema"] == "pydecomp-recipe-v1"
    assert recipe["input"]["bytes"] == len(raw)
    assert len(recipe["input"]["sha256"]) == 64
    assert recipe["steps"][0]["index"] == 1
    assert "not executed" in recipe["guarantee"]
    assert "path" not in json.dumps(recipe).lower()


def test_source_map_uses_output_spans_and_does_not_claim_original_offsets():
    source = "def one():\n    return 1\n\nclass Box:\n    pass\n"
    proof = {"tiers": {"semantic": ["one"], "syntactic": ["Box"]}}
    result = build_source_map(source, proof, ["layer 1: base64"])
    assert [(item["name"], item["start_line"], item["proof_tier"])
            for item in result["definitions"]] == [("one", 1, "semantic"), ("Box", 4, "syntactic")]
    assert "not a guessed per-line original offset" in result["attribution_note"]


def test_per_function_confidence_marks_each_definition():
    source = "def proven():\n    return 1\n\ndef shaky():\n    return 2\n"
    proof = {"tiers": {"semantic": ["proven"], "syntactic": ["shaky"]},
             "evidence": {"shaky:syntactic": "recompiled but reordered"}}
    rows = confidence.per_function(source, proof)
    assert [(row["name"], row["tier"]) for row in rows] == [("proven", "semantic"),
                                                            ("shaky", "syntactic")]
    assert rows[1]["detail"] == "recompiled but reordered"
    assert "shaky" in " ".join(confidence.render_functions(source, proof))


def test_hints_come_only_from_recorded_evidence():
    source = "# pydecomp: unsupported CALL_FUNCTION_EX (line 4)\nprint(1)\n"
    found = confidence.hints(source, [], [])
    assert any("CALL_FUNCTION_EX" in item for item in found)
    assert any("--disassemble" in item for item in found)
    assert confidence.hints("print(1)\n", ["layer 1: base64"], []) == []
    sealed = confidence.hints("x = 1\n", ["payload is encrypted: 2 blob(s)"], [])
    assert any("encrypted" in item for item in sealed)


def test_method_comparison_says_which_answer_holds_more():
    own = "def keep():\n    return 1\n"
    other = own + "\ndef extra():\n    return 2\n"
    comparison = methods.against(own, other, "sample_pylingual.py")
    assert methods.verdict(comparison).startswith("sample (PyLingual) has 1 definition")
    assert "functions added: extra" in "\n".join(methods.render(comparison))
    same = methods.against(own, own, "sample_pylingual.py")
    assert "identical text" in methods.verdict(same)


def test_engine_rows_report_the_chosen_method():
    rows = methods.engines({"ir": {"tier": "semantic", "detail": "emitted"},
                            "engine": "ssa-ir", "proven": True})
    assert rows[0]["method"] == "ssa-ir" and rows[0]["chosen"] is True
    rows = methods.engines({"engine": "stack", "proven": False})
    assert rows == [{"method": "stack", "tier": "unverified", "detail": "", "chosen": True}]


def test_zip_freezer_entry_limits(monkeypatch):
    monkeypatch.setattr(containers, "MAX_ARCHIVE_ENTRY_BYTES", 64)
    monkeypatch.setattr(containers, "MAX_ARCHIVE_TOTAL_BYTES", 96)
    monkeypatch.setattr(containers, "MAX_ARCHIVE_MEMBERS", 10)

    class Reader(containers.FreezerReader):
        suffixes = (".py",)

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("small.py", "x = 1\n")
        zf.writestr("large.py", "x" * 200)
        zf.writestr("other.py", "y = 2\n")
    entries = Reader()._from_zip(archive.getvalue())
    assert [name for name, _ in entries] == ["small.py", "other.py"]


def test_engine_zip_reader_skips_oversized_expanded_member(monkeypatch):
    monkeypatch.setattr(dig_module, "MAX_ARCHIVE_ENTRY_BYTES", 64)
    monkeypatch.setattr(dig_module, "MAX_ARCHIVE_TOTAL_BYTES", 96)
    monkeypatch.setattr(dig_module, "MAX_ARCHIVE_MEMBERS", 10)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.py", "x = 1\\n" * 100)
    trace = []
    result = dig_module._digest_bytes(archive.getvalue(), trace, 0, set(), 8)
    assert result is None
    assert any("bounded to 10 entries" in line for line in trace)


def test_pylingual_plan_is_offline_shell_free_and_never_run(tmp_path):
    pyc = _pyc(tmp_path)
    recipe = pylingual.plan(str(pyc), str(tmp_path / "out"))
    assert recipe["ok"] is True
    assert recipe["shell"] is False
    assert recipe["env"]["UV_OFFLINE"] == "1" and recipe["env"]["HF_HUB_OFFLINE"] == "1"
    assert recipe["uploads"].startswith("none")
    assert recipe["argv"][0] == "pylingual" and recipe["target"].startswith("3.")
    assert str(pyc) in recipe["argv"]
    assert "never runs this command" in recipe["note"]


def test_pylingual_plan_refuses_non_pyc(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("print('data')", encoding="utf-8")
    recipe = pylingual.plan(str(source))
    assert recipe["ok"] is False and ".pyc" in recipe["reason"]


def test_pylingual_ingest_compiles_before_adopting(tmp_path):
    pyc = _pyc(tmp_path)
    produced = tmp_path / "candidate.py"
    produced.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    output, message = pylingual.ingest(str(produced), str(pyc), str(tmp_path / "out"))
    assert output and Path(output).name == "small_pylingual.py"
    assert "not executed" in message
    assert "return a + b" in Path(output).read_text(encoding="utf-8")


def test_pylingual_ingest_rejects_text_that_does_not_compile(tmp_path):
    pyc = _pyc(tmp_path)
    produced = tmp_path / "candidate.py"
    produced.write_text("def broken(:\n", encoding="utf-8")
    output, message = pylingual.ingest(str(produced), str(pyc), str(tmp_path / "out"))
    assert output is None and "compile-only" in message
