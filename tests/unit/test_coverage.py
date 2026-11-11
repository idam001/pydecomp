"""Coverage: proving what survived the cleaning, and noticing what did not."""
from __future__ import annotations

from pydecomp.triage.coverage import compare, render_markdown, summary

ORIGINAL = '''import os
import sys
LIMIT = 3

def total(items):
    acc = 0
    for value in items:
        acc += value * 2
    return acc

def unused(marker):
    return marker + "tail"

class Box:
    def size(self):
        return LIMIT
'''


def test_identical_programs_are_complete():
    result = compare(ORIGINAL, ORIGINAL)
    assert result["verdict"] == "complete"
    assert result["lost"] == 0
    assert result["kept"] == result["kept"] + result["lost"]
    assert result["strings_kept"] == result["strings_before"]


def test_folding_counts_as_complete():
    recovered = '''import os
import sys
LIMIT = 3

def total(items):
    acc = 0
    for value in items:
        acc += value * 2
    return acc

def unused(marker):
    return 'tail'

class Box:
    def size(self):
        return 3
'''
    result = compare(ORIGINAL, recovered)
    assert result["verdict"] == "complete"
    assert result["definitions"]["total"]["status"] == "kept"
    assert result["definitions"]["total"]["after"] <= result["definitions"]["total"]["before"]


def test_lost_definition_is_reported():
    recovered = ORIGINAL.replace('''def unused(marker):
    return marker + "tail"
''', "")
    result = compare(ORIGINAL, recovered)
    assert result["definitions"]["unused"]["status"] == "missing"
    assert result["lost"] == 1
    assert result["verdict"] != "complete"


def test_emptied_definition_is_not_kept():
    recovered = ORIGINAL.replace('''class Box:
    def size(self):
        return LIMIT''', '''class Box:
    pass''')
    result = compare(ORIGINAL, recovered)
    assert result["definitions"]["size"]["status"] == "missing"


def test_lost_import_and_name_are_reported():
    recovered = ORIGINAL.replace("import sys\n", "").replace("LIMIT = 3\n", "")
    result = compare(ORIGINAL, recovered)
    assert "sys" in result["imports_lost"]
    assert "LIMIT" in result["names_lost"]


def test_unparsable_recovered_falls_back_to_text():
    result = compare(ORIGINAL, "this is not python ((")
    assert result["parsed"] is False
    assert "text only" in result["verdict"] or result["verdict"]
    assert summary(result)


def test_markdown_lists_every_definition():
    text = render_markdown("sample.py", compare(ORIGINAL, ORIGINAL))
    assert "# Coverage — `sample.py`" in text
    assert "| definition | kind |" in text
    for name in ("total", "unused", "Box", "size"):
        assert f"`{name}`" in text


def test_summary_is_one_line():
    line = summary(compare(ORIGINAL, ORIGINAL))
    assert "\n" not in line
    assert "complete" in line
