"""Gate: payload intelligence, and the precision rules that keep it honest.

A sealed payload cannot be unpacked, but its code object still carries a name
table.  These tests pin down what we are willing to say about it:

* names are deduplicated and stripped of the noise every module carries,
* CJK filler is counted as filler, never printed as a string,
* a capability claim needs an exact name — ``_walk_tb_with_full_positions`` must
  not become an ``os.walk`` (filesystem) claim just because it contains *walk*,
* single-byte XOR stays off unless asked for, because every candidate we
  measured on a real sample was noise.
"""
import sys

import pytest

sys.path.insert(0, "src")
from pydecomp.triage.payload import harvest, render, summary   # noqa: E402

SOURCE = '''
import sys

FILENAME = "original_script.py"
CJK = "\\u4e00\\u4e8c\\u4e09\\u56db\\u4e94\\u516d"
SEALED = {sealed}


def parse_rows(table, strict):
    rows = []
    for row in table:
        rows.append(row)
    return rows


class Counter:
    def __init__(self, limit):
        self.limit = limit
        self.system = None

    def _walk_tb_with_full_positions(self, value):
        return value
'''


# A packed payload carries its ciphertext as one literal constant, so the
# fixture does too: ``b"\x00\x01" * 4096`` at runtime is 2 bytes in the code
# object, which is not what the harvester is asked to classify.
SEALED_LITERAL = b"\x00\x01" * 4096


def _payload():
    return compile(SOURCE.format(sealed=repr(SEALED_LITERAL)), "<sealed-module>", "exec")


@pytest.fixture(scope="module")
def intel():
    return harvest(_payload())


def test_identifiers_are_deduplicated(intel):
    names = intel["identifiers"]
    assert len(names) == len(set(names))
    assert {"parse_rows", "Counter", "strict", "table"} <= set(names)


def test_common_names_are_not_reported_as_findings(intel):
    names = {name.lower() for name in intel["identifiers"]}
    assert not names & {"value", "name", "list", "print", "str", "range"}


def test_no_one_character_noise(intel):
    assert all(len(name) >= 3 for name in intel["identifiers"])


def test_cjk_filler_is_counted_not_printed(intel):
    assert intel["junk_strings"] >= 1
    assert all("\u4e00" not in text for text in intel["strings"])


def test_capability_needs_an_exact_name(intel):
    caps = intel["capabilities"]
    words = {word for names in caps.values() for word in names}
    # ``self.system = None`` is a real attribute name, so subprocess is fair.
    assert "system" in words
    assert "subprocess" in caps
    # ...but a traceback helper is not an os.walk.
    assert not any("walk_tb" in word for word in words)


def test_capability_words_are_normalised(intel):
    words = {word for names in intel["capabilities"].values() for word in names}
    assert all(word == word.strip("_") for word in words)


def test_xor_space_stays_closed_by_default(intel):
    assert intel["xor_searched"] is False
    assert intel["decoded"] == []


def test_xor_space_can_be_opened_explicitly():
    opened = harvest(_payload(), xor=True)
    assert opened["xor_searched"] is True
    assert isinstance(opened["decoded"], list)


def test_sealed_blobs_are_classified(intel):
    sealed = intel["sealed"]
    assert len(sealed) == 1                     # the fixture's 8,192-byte constant
    assert sealed[0]["size"] == 8192
    assert sealed[0]["kind"] in {"structured", "cyclical", "opaque", "high-entropy"}
    assert "4 blob(s)" not in summary(intel)    # the summary uses the sealed count


def test_render_includes_the_sealed_section(intel):
    text = render("sealed.py", intel)
    assert "## sealed blobs" in text
    assert "entropy" in text


def test_summary_is_one_line(intel):
    line = summary(intel)
    assert "\n" not in line
    assert "name(s)" in line


def test_render_never_claims_recovery(intel):
    text = render("sealed.py", intel)
    assert "Nothing here is recovered code" in text
    assert "parse_rows" in text
    assert "not reported" in text                    # the XOR line
    assert "leads, not as the program's source" in text


def test_render_survives_an_empty_payload():
    empty = harvest(compile("", "<empty>", "exec"))
    text = render("empty.py", empty)
    assert text.startswith("# payload intelligence")
    assert summary(empty)
