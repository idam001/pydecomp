"""The fidelity guard: cleaning may improve the program, never replace it."""
from __future__ import annotations

from pydecomp.polish.fidelity import profile, summary, verify

PROGRAM = '''import os

LIMIT = 3

def collect(items):
    out = []
    for item in items:
        out.append(item * 2)
    return out

def tag():
    return "RECOVER_ME"
'''

BLOB = ("L1RkNldGb0FBQVRtMXJSR0FnQWhBUllBQUFCMEwrV2pBUVVIZUp3VlZjMlNxeW9RZmlXUm1K"
        "b3M3dUtZaUk0Sk9DQ2dzbE94eGdub2VCS1RHSjcrY2haZDFTem9ydjUrdWkrQUdXSjEyZ1Vv"
        "cHBLdHVNNUxGcUNaVm1Nc3JJMnBRRWVjdkc0eVhHSWhEa0tKWmFlUktuUm10MkU2a0V1SVR1")


def test_clean_program_is_kept():
    verdict = verify(PROGRAM, PROGRAM)
    assert verdict["kept"] == "cleaned"
    assert "verified" in summary(verdict)


def test_unparsable_cleaning_is_rolled_back():
    verdict = verify(PROGRAM, "def broken(:\n")
    assert verdict["kept"] == "unpacked"
    assert verdict["text"] == PROGRAM
    assert "parse" in verdict["reason"]


def test_losing_the_program_is_rolled_back():
    verdict = verify(PROGRAM, "import os\n")
    assert verdict["kept"] == "unpacked"
    assert verdict["text"] == PROGRAM
    assert "definition" in verdict["reason"]


def test_literal_dump_is_not_accepted_as_source():
    verdict = verify(PROGRAM, BLOB)
    assert verdict["kept"] == "unpacked"
    assert profile(BLOB)["rubbish"] is True


def test_recovering_source_from_a_blob_is_kept():
    verdict = verify(BLOB, PROGRAM)
    assert verdict["kept"] == "cleaned"


def test_folding_is_not_mistaken_for_loss():
    folded = '''import os
LIMIT = 3

def collect(items):
    out = []
    for item in items:
        out.append(item * 2)
    return out

def tag():
    return 'RECOVER_ME'
'''
    verdict = verify(PROGRAM, folded)
    assert verdict["kept"] == "cleaned"


def test_summary_never_lies_about_a_rollback():
    verdict = verify(PROGRAM, "import os\n")
    text = summary(verdict)
    assert "rolled back" in text and verdict["reason"] in text
