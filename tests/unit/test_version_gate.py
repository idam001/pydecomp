"""A packer's version gate is evidence, not an obstacle."""
import ast
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "src"))

from pydecomp.eval.expr_eval import _payload_score, _version_candidates
from pydecomp.eval.namespace import _FakeSys


def test_version_literal_is_found():
    tree = ast.parse("x = 'a' if str(sys.version[0:4]) == '3.12' else 'b'")
    assert _version_candidates(tree) == ["3.12"]


def test_unrelated_strings_are_not_versions():
    tree = ast.parse("x = 'hello' if sys.platform == 'linux' else '3.11'")
    assert _version_candidates(tree) == []


def test_fake_sys_reports_the_gated_version():
    assert _FakeSys("3.11").version.startswith("3.11.")
    assert _FakeSys("3.11").version_info[:2] == (3, 11)
    assert _FakeSys().version.startswith("3.14.")          # the historical default


def test_decoy_warning_scores_below_a_real_payload():
    decoy = _payload_score("text", 'print("You need install a python 3.13")')
    real = _payload_score("text", "def a():\n    return 1\n\ndef b():\n    return 2\n")
    assert decoy < real


def test_a_code_object_outranks_text():
    class Fake:
        code = b"\x00" * 500
        name = "<module>"
    assert _payload_score("code", ((3, 13), Fake())) > _payload_score("text", "x = 1")


def test_binary_payload_scores_above_nothing():
    assert _payload_score("bytes", b"\x00" * 4000) > 0
    assert _payload_score("text", "") == 0
