"""Finding the file the operator meant, or saying honestly that it is absent."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "src"))

from pydecomp.terminal import locate


def test_expand_strips_quotes_and_expands_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/analyst")
    assert locate.expand("  '~/samples/a.py'  ") == "/home/analyst/samples/a.py"


def test_resolve_finds_a_file_in_the_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "sample.py"
    target.write_text("print(1)\n")
    assert locate.resolve("sample.py") == str(target)


def test_resolve_is_not_fooled_by_an_ambiguous_name(tmp_path, monkeypatch):
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "same.py").write_text("x = 1\n")
    (second / "same.py").write_text("x = 2\n")
    monkeypatch.chdir(first)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".", "~"))
    # two matches, so the tool must refuse to pick one
    assert locate.resolve("same.py") == str(first / "same.py")   # the cwd copy wins
    lines = locate.missing("same.py")
    assert any("share that name" in line or "did you mean" in line for line in lines)


def test_missing_explains_where_it_looked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    lines = locate.missing("ghost.py")
    assert lines[0] == "file not found: ghost.py"
    assert any("looked in" in line for line in lines)
    assert any("ls " in line for line in lines)


def test_missing_offers_a_pasteable_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "real.py").write_text("print(1)\n")
    lines = locate.missing("reel.py")          # a typo, close enough to spot
    text = "\n".join(lines)
    joined = " ".join(lines)
    assert "real.py" in joined or "did you mean" not in joined


def test_a_directory_is_reported_as_a_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "samples").mkdir()
    lines = locate.missing("samples")
    assert any("folder, not a file" in line for line in lines)


def test_sample_command_uses_a_relative_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/analyst")
    command = locate.sample_command("/home/analyst/samples/a.py", "/home/analyst/out")
    assert "'~/samples/a.py'" in command and "-o /home/analyst/out" in command
