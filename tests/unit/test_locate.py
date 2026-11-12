"""Gate: the tool finds the file itself instead of telling you to paste a command.

A phone that types a name from the downloads folder should not have to copy a
path back into the shell.  These tests pin the decision: search the device, rank
what matches, use the newest, and say which one was used and what else matched.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "src"))

from pydecomp.terminal import locate


def test_expand_strips_quotes_and_expands_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/analyst")
    assert locate.expand("  '~/samples/a.py'  ") == "/home/analyst/samples/a.py"


def test_the_path_as_given_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "sample.py"
    target.write_text("print(1)\n")
    choice = locate.search("sample.py")
    assert choice is not None and choice.path == str(target)
    assert choice.direct and choice.reason == "path as given"


def test_a_file_outside_the_current_folder_is_found_and_used(tmp_path, monkeypatch):
    downloads = tmp_path / "storage" / "downloads"
    downloads.mkdir(parents=True)
    elsewhere = downloads / "KAMRUL~4.py"
    elsewhere.write_text("print(2)\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.chdir(tools)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".", "~", "~/storage/downloads"))
    monkeypatch.setattr(locate, "SCAN_ROOTS", ())
    choice = locate.search("KAMRUL~4.py")
    assert choice is not None, "the tool gave up instead of searching"
    assert choice.path == str(elsewhere)
    assert "found by name" in choice.reason
    assert not choice.direct


def test_the_newest_of_several_matches_is_used_and_the_rest_are_named(
        tmp_path, monkeypatch):
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    old = first / "same.py"
    old.write_text("x = 1\n")
    os.utime(old, (1_600_000_000, 1_600_000_000))
    new = second / "same.py"
    new.write_text("x = 2\n")
    here = tmp_path / "here"
    here.mkdir()
    monkeypatch.chdir(here)                      # the name is not in the cwd
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".", "~"))
    monkeypatch.setattr(locate, "SCAN_ROOTS", ())
    choice = locate.search("same.py")
    assert choice.path == str(new), "the newest copy should win"
    assert "newest of 2" in choice.reason
    assert str(old) in choice.alternatives


def test_pick_overrides_the_ranking(tmp_path, monkeypatch):
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    old = first / "same.py"
    old.write_text("x = 1\n")
    os.utime(old, (1_600_000_000, 1_600_000_000))
    (second / "same.py").write_text("x = 2\n")
    here = tmp_path / "here"
    here.mkdir()
    monkeypatch.chdir(here)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".", "~"))
    monkeypatch.setattr(locate, "SCAN_ROOTS", ())
    choice = locate.search("same.py", pick=2)
    assert choice.path == str(old)
    assert "--pick 2" in choice.reason


def test_case_only_differences_still_match(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Sample.py").write_text("x = 1\n")
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".",))
    choice = locate.search("sample.PY")
    assert choice is not None and choice.path.endswith("Sample.py")
    assert "ignoring case" in choice.reason


def test_a_typo_resolves_to_the_closest_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "real.py").write_text("x = 1\n")
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".",))
    choice = locate.search("reel.py")
    assert choice is not None and choice.path.endswith("real.py")


def test_nested_files_are_reached_by_the_scan(tmp_path, monkeypatch):
    deep = tmp_path / "storage" / "downloads" / "archive" / "deep"
    deep.mkdir(parents=True)
    target = deep / "buried.py"
    target.write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".",))
    monkeypatch.setattr(locate, "SCAN_ROOTS", ("~",))
    choice = locate.search("buried.py")
    assert choice is not None and choice.path == str(target)
    assert "scanning" in choice.reason


def test_nothing_found_never_tells_the_operator_to_type_the_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(locate, "SEARCH_DIRS", (".",))
    monkeypatch.setattr(locate, "SCAN_ROOTS", ())
    lines = locate.missing("ghost.py")
    text = " ".join(lines)
    assert "nothing named ghost.py" in text
    assert "paste" not in text
    assert "python pydecomp" not in text
    assert "what I can see right now" in text or "no python samples" in text


def test_a_directory_is_reported_as_a_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "samples").mkdir()
    lines = locate.missing("samples")
    assert any("folder, not a file" in line for line in lines)
    assert locate.search("samples") is None
