from __future__ import annotations

import json
import py_compile
from pathlib import Path

import pytest

from pydecomp.cli import main


def _pyc(tmp_path):
    source = tmp_path / "small.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    pyc = tmp_path / "small.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)
    return pyc


def test_cli_recipe_sidecar(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text("def f():\n    return 7\n", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(source), "--no-color", "--no-anim", "--recipe", "-o", str(out)]) == 0
    recipe = next(out.glob("*.recipe.json"))
    data = json.loads(recipe.read_text(encoding="utf-8"))
    assert data["input"]["sha256"] and data["output"]["sha256"]
    assert "static-only" in data["guarantee"]
    capsys.readouterr()


def test_cli_pyc_disassembly_sidecar(tmp_path, capsys):
    source = tmp_path / "small.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    pyc = tmp_path / "small.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)
    out = tmp_path / "dump"
    assert main([str(pyc), "--disassemble", "--no-color", "--no-anim",
                 "-o", str(out)]) == 0
    dump = next(out.glob("*.dis.txt")).read_text(encoding="utf-8")
    assert "execution: none" in dump and "code-object 'add'" in dump
    capsys.readouterr()


def test_cli_source_map_sidecar(tmp_path, capsys):
    source = tmp_path / "mapped.py"
    source.write_text("def work():\n    return 1\n", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(source), "--source-map", "--no-color", "--no-anim",
                 "-o", str(out)]) == 0
    sidecar = next(out.glob("*.sourcemap.json"))
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["definitions"][0]["name"] == "work"
    assert data["attribution_note"].startswith("definition spans refer")
    capsys.readouterr()


def test_cli_source_map_needs_proof(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["sample.py", "--source-map", "--no-proof"])
    assert exc.value.code == 2


def test_cli_pylingual_plan_prints_command(tmp_path, capsys):
    pyc = _pyc(tmp_path)
    assert main([str(pyc), "--pylingual", "--no-color", "--no-anim"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["shell"] is False and payload["argv"][0] == "pylingual"


def test_cli_pylingual_import_differs_against_own_recovery(tmp_path, capsys):
    pyc = _pyc(tmp_path)
    out = tmp_path / "out"
    assert main([str(pyc), "--no-color", "--no-anim", "-o", str(out)]) == 0
    produced = tmp_path / "from_pylingual.py"
    produced.write_text("def add(a, b):\n    return b + a\n", encoding="utf-8")
    assert main([str(pyc), "--pylingual-import", str(produced),
                 "--no-color", "--no-anim", "-o", str(out)]) == 0
    printed = capsys.readouterr().out
    assert (out / "small_pylingual.py").exists()
    assert "functions" in printed or "identical" in printed


def test_cli_target_versions_pass_and_flag(tmp_path, capsys):
    source = tmp_path / "plain.py"
    source.write_text("def f():\n    return 1\n", encoding="utf-8")
    assert main([str(source), "--target-versions", "3.9", "--no-color", "--no-anim",
                 "-o", str(tmp_path / "out")]) == 0
    assert "Python 3.9: ok" in capsys.readouterr().out


def test_cli_target_versions_reject_new_syntax(tmp_path, capsys):
    source = tmp_path / "newer.py"
    source.write_text("match 1:\n    case 1:\n        pass\n", encoding="utf-8")
    assert main([str(source), "--target-versions", "3.9", "--no-color", "--no-anim",
                 "-o", str(tmp_path / "out")]) == 4
    assert "invalid" in capsys.readouterr().out


def test_cli_static_compare(tmp_path, capsys):
    left = tmp_path / "left.py"
    right = tmp_path / "right.py"
    left.write_text("def f():\n    return 1\n", encoding="utf-8")
    right.write_text("def f():\n    return 2\n", encoding="utf-8")
    assert main([str(left), "--compare-with", str(right), "--no-color", "--no-anim"]) == 0
    assert "functions changed: f" in capsys.readouterr().out


def test_batch_run_writes_one_summary(tmp_path, capsys):
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (folder / "b.py").write_text("VALUE = 2\n", encoding="utf-8")
    out = tmp_path / "out"
    assert main([str(folder), "--no-color", "--no-anim", "--reports",
                 "-o", str(out)]) == 0
    summary = json.loads((out / "batch-summary.json").read_text(encoding="utf-8"))
    assert summary["schema"] == "pydecomp-batch-v1" and summary["files"] == 2
    assert all("output" in row and len(row) > 1 for row in summary["results"])
    capsys.readouterr()


def test_offline_flag_rejects_network_request():
    with pytest.raises(SystemExit) as exc:
        main(["sample.py", "--offline", "--fetch-iocs"])
    assert exc.value.code == 2
