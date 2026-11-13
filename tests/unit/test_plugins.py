"""The backend tree: what it claims, and the rules that keep it honest.

Five trees of small modules - codecs, compress, cipher, containers, alphabet -
all behind one interface, so a technique can be added without touching the
search.  The tests below pin the properties the search depends on:

* discovery is complete and ordered, so a recipe in a report means the same
  thing twice;
* every backend decodes what it encodes, and refuses everything else without
  raising;
* a chain longer than one step is found (rc4 in front of base64 in front of
  zlib), and a blob of noise ends in no hit rather than a plausible one;
* running out of budget is reported, not silently turned into "no result".
"""
from __future__ import annotations

import base64
import gzip
import os
import random
import zlib

import pytest

from pydecomp.engine.peel import find_payloads
from pydecomp.engine.plugins_pass import explore_blobs, looks_like_payload
from pydecomp.plugins.backends import (Budget, Result, backends, by_name,
                                        describe, explore)
from pydecomp.plugins.backends.cipher.stream import rc4
from pydecomp.plugins.backends.registry import TREES


PAYLOAD = b"def greet(name):\n    return 'hello ' + name\n\nprint(greet('world'))\n"


def accept_text(data: bytes, chain) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return text == PAYLOAD.decode("utf-8")


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def test_every_tree_contributes_backends():
    kinds = {backend.kind for backend in backends()}
    assert {"codec", "compress", "cipher", "container"} <= kinds
    assert len(TREES) == 5


def test_discovery_is_ordered_and_unique():
    names = [backend.name for backend in backends()]
    assert len(names) == len(set(names))
    assert names == [backend.name for backend in backends()]


def test_a_community_decoder_takes_part_in_the_same_search():
    from pydecomp.plugins import register_decoder, unregister
    from pydecomp.plugins.backends import community, registry

    @register_decoder("unit_halves", priority=25, source="unit test")
    def halves(blob):
        try:
            text = bytes(blob).decode("ascii")
        except UnicodeDecodeError:
            return None
        if "|" not in text:
            return None
        front, _, back = text.partition("|")
        return (front + back).encode("ascii")

    try:
        registry.reset()
        names = [backend.name for backend in community.backends()]
        assert "plugin:unit_halves" in names
        blob = PAYLOAD[:30] + b"|" + PAYLOAD[30:]
        result = explore(blob, accept_text, depth=3, budget=Budget(opens=900))
        assert result.hits and result.hits[0].data == PAYLOAD
    finally:
        unregister("unit_halves")
        registry.reset()


def test_backends_can_be_filtered_by_kind():
    compress = backends("compress")
    assert compress and all(backend.kind == "compress" for backend in compress)
    assert by_name("zlib") is not None
    assert by_name("no-such-backend") is None
    assert any("zlib" in line for line in describe())


# --------------------------------------------------------------------------
# one backend at a time
# --------------------------------------------------------------------------

def test_zlib_opens_only_zlib():
    backend = by_name("zlib")
    assert backend is not None
    assert backend.candidates(zlib.compress(PAYLOAD))[0] == PAYLOAD
    assert backend.candidates(b"not a zlib stream at all") == []


def test_gzip_and_bz2_and_lzma_round_trip():
    import bz2
    import lzma
    for name, pack in (("gzip", lambda data: gzip.compress(data, mtime=0)),
                       ("bz2", bz2.compress), ("lzma", lzma.compress)):
        backend = by_name(name)
        assert backend is not None
        assert backend.candidates(pack(PAYLOAD))[0] == PAYLOAD


def test_a_backend_refuses_instead_of_raising():
    for backend in backends():
        for blob in (b"", b"\x00", os.urandom(64)):
            backend.candidates(blob)      # no exception, whatever the bytes


def test_single_byte_xor_offers_the_readable_keys_only():
    backend = by_name("xor1")
    assert backend is not None
    blob = bytes(byte ^ 0x5A for byte in PAYLOAD)
    assert PAYLOAD in backend.candidates(blob)


def test_rc4_with_the_key_in_front():
    backend = by_name("rc4head")
    assert backend is not None
    body = rc4(base64.b64encode(zlib.compress(PAYLOAD)), b"K3y!8z")
    assert backend.candidates(b"K3y!8z" + body)[0] == base64.b64encode(
        zlib.compress(PAYLOAD))


# --------------------------------------------------------------------------
# chains
# --------------------------------------------------------------------------

def test_bits_spelled_out_decode():
    backend = by_name("bits")
    assert backend is not None
    blob = "".join(format(byte, "08b") for byte in PAYLOAD).encode()
    assert backend.candidates(blob)[0] == PAYLOAD


def test_bits_hidden_in_zero_width_characters_decode():
    backend = by_name("bits")
    assert backend is not None
    text = "".join("\u200b" if bit == "0" else "\u200c"
                   for bit in "".join(format(byte, "08b") for byte in PAYLOAD))
    assert backend.candidates(text.encode("utf-8"))


def test_a_repeating_key_is_recovered_from_enough_ciphertext():
    from pydecomp.plugins.backends.cipher.repeatkey import _each_repeating_key
    program = ("import os\n\ndef collect(path='/tmp'):\n"
               "    return [name for name in os.listdir(path) if name]\n\n"
               "def report(rows):\n    return '\\n'.join(sorted(rows))\n\n"
               "print(report(collect()))\n") * 4
    inner = base64.b64encode(zlib.compress(program.encode()))
    key = b"\x13\x99\x2b\xf0\x7a\x51"
    blob = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(inner))
    assert inner in list(_each_repeating_key(blob))


def test_a_repeating_key_is_not_guessed_from_too_little_data():
    from pydecomp.plugins.backends.cipher.repeatkey import _each_repeating_key
    blob = bytes(byte ^ b"\x13\x99"[index % 2] for index, byte in enumerate(os.urandom(64)))
    assert list(_each_repeating_key(blob)) == []


def test_the_clock_ends_an_exploration_too():
    from pydecomp.plugins.backends.spec import Budget
    starved = Budget(opens=10_000, seconds=1e-9)
    result = explore(base64.b64encode(os.urandom(4096)), accept_text, depth=4,
                     budget=starved)
    assert result.exhausted is True


def test_a_three_step_chain_is_found():
    blob = b"K3y!8z" + rc4(base64.b64encode(zlib.compress(PAYLOAD)), b"K3y!8z")
    result = explore(blob, accept_text, depth=5, budget=Budget(opens=2000))
    assert result.hits, "rc4 in front of base64 in front of zlib"
    assert result.hits[0].chain == ("rc4head", "b64", "zlib")
    assert result.hits[0].data == PAYLOAD


def test_noise_ends_in_no_hit():
    random.seed(11)
    blob = bytes(random.randrange(256) for _ in range(512))
    result = explore(blob, accept_text, depth=3, budget=Budget(opens=200))
    assert result.hits == ()


def test_the_budget_is_reported_when_it_runs_out():
    blob = base64.b64encode(os.urandom(4096))
    result = explore(blob, accept_text, depth=4, budget=Budget(opens=3))
    assert isinstance(result, Result)
    assert result.exhausted is True


def test_a_payload_is_not_decoded_further():
    # base64 of base64 of the payload: the first decode is the answer, so the
    # chain stops there instead of reporting a longer one
    blob = base64.b64encode(base64.b64encode(PAYLOAD))
    result = explore(blob, accept_text, depth=4, budget=Budget(opens=400))
    assert len(result.hits) == 1
    assert result.hits[0].chain == ("b64", "b64")


# --------------------------------------------------------------------------
# the two rules the peeler relies on
# --------------------------------------------------------------------------

def test_a_recovered_chain_is_a_recipe_the_peeler_can_report():
    blob = base64.b64encode(zlib.compress(PAYLOAD))
    found = explore_blobs([blob])
    assert found and found[0][0] == ["b64", "zlib"]
    assert found[0][1] == PAYLOAD


def test_a_data_only_file_is_read_without_a_loader():
    source = ("_blob = %r\nraise SystemExit(0)\n"
              % base64.b64encode(zlib.compress(PAYLOAD)))
    payloads = find_payloads(source)
    assert [payload.data for payload in payloads] == [PAYLOAD]
    assert payloads[0].recipe == ["b64", "zlib"]


def test_a_loader_whose_key_is_unknown_still_gives_up_its_bytes():
    key = ord("A") ^ 0x5C
    mixed = bytes(byte ^ key for byte in base64.b64encode(zlib.compress(PAYLOAD)))
    source = ("import base64, os, zlib\n"
              "_seed = os.environ.get('PYDECOMP_SEED', 'A')\n"
              "_key = ord(_seed[0]) ^ 0x5C\n"
              "_p = %r\n"
              "exec(zlib.decompress(base64.b64decode("
              "bytes(b ^ _key for b in _p))))\n" % mixed)
    payloads = find_payloads(source)
    assert [payload.data for payload in payloads] == [PAYLOAD]


def test_the_loader_is_never_run():
    marker = os.path.join(os.path.dirname(__file__), ".executed")
    source = ("open(%r, 'w').write('ran')\n"
              "_ = %r\n" % (marker, base64.b64encode(zlib.compress(PAYLOAD))))
    find_payloads(source)
    assert not os.path.exists(marker)


def test_an_ordinary_extractor_is_not_treated_as_obfuscated():
    """A program that carries an archive is a program, not a layer.

    The backend tree can open any zip it is handed, so without a guard it would
    report a plain extractor as obfuscated and replace its source with the
    member it extracts.
    """
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.py", PAYLOAD.decode())
    packed = base64.b64encode(buffer.getvalue())
    source = ("import base64, io, zipfile\n"
              "_z = zipfile.ZipFile(io.BytesIO(base64.b64decode(%r)))\n"
              "_z.extractall('.')\n" % packed)
    assert find_payloads(source) == []
    # while the same bytes in a file that only carries them are a payload
    carrier = "_blob = %r\nraise SystemExit(0)\n" % packed
    assert [item.data for item in find_payloads(carrier)] == [PAYLOAD]


def test_prose_is_not_a_payload():
    assert not looks_like_payload(b"W:l@AG#HA1+9HA!Bk7f?HXE$(`;3Uc@GYh9[D3L#Z\n")
    assert not looks_like_payload(b"'W8j>AG#FA1+9FA!@k7d?FVE\"&^;3Uc>GYf9'\n")
    assert looks_like_payload(PAYLOAD)


@pytest.mark.parametrize("blob", [b"", b"\x00" * 8, os.urandom(32)])
def test_lookalikes_are_rejected(blob):
    assert not looks_like_payload(blob)


# --------------------------------------------------------------------------
# numeric spellings, order-only ciphers, carving
# --------------------------------------------------------------------------

def test_bytes_spelled_as_numbers_come_back():
    from pydecomp.plugins.backends.codecs.numeric import (
        _open_decimal, _open_hex_pairs, _open_json_array, _open_octal)

    numbers = [byte for byte in PAYLOAD]
    assert _open_decimal(" ".join(map(str, numbers)).encode()) == PAYLOAD
    assert _open_decimal(", ".join(map(str, numbers)).encode()) == PAYLOAD
    assert _open_json_array(repr(numbers).encode()) == PAYLOAD
    assert _open_octal(b" ".join(b"\\%o" % byte for byte in numbers)) == PAYLOAD
    assert _open_hex_pairs(b"-".join(b"%02x" % byte for byte in numbers)) == PAYLOAD


def test_plain_hex_is_not_claimed_by_the_pair_reader():
    from pydecomp.plugins.backends.codecs.numeric import _open_hex_pairs

    # bare hex belongs to the hex backend; this one only takes a spelled-out form
    assert _open_hex_pairs(PAYLOAD.hex().encode()) is None
    assert _open_hex_pairs(b"not hex at all, just words in a row here") is None


@pytest.mark.parametrize("rails", [2, 3, 4, 5, 8])
def test_rail_fence_is_its_own_inverse(rails):
    from pydecomp.plugins.backends.cipher.transposition import rail_fence_decode

    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows: list[list[int]] = [[] for _ in range(rails)]
    for index, byte in enumerate(PAYLOAD):
        rows[pattern[index % len(pattern)]].append(byte)
    written = bytes(byte for row in rows for byte in row)
    assert rail_fence_decode(written, rails) == PAYLOAD


@pytest.mark.parametrize("columns", [2, 3, 7, 16])
def test_columnar_is_its_own_inverse(columns):
    from pydecomp.plugins.backends.cipher.transposition import columnar_decode

    rows = [PAYLOAD[index:index + columns] for index in range(0, len(PAYLOAD), columns)]
    written = bytearray()
    for column in range(columns):
        for row in rows:
            if column < len(row):
                written.append(row[column])
    assert columnar_decode(bytes(written), columns) == PAYLOAD


def test_a_layer_that_starts_partway_in_is_carved_out():
    from pydecomp.plugins.backends.containers.carve import _each_carve

    packed = zlib.compress(PAYLOAD)
    carried = b"\x89PNG-ish banner bytes" + packed
    assert packed in list(_each_carve(carried))
    assert list(_each_carve(PAYLOAD)) == []


def test_the_step_after_a_candidate_decides_which_candidate_comes_first():
    from pydecomp.plugins.backends._share import promise

    # base64 of base64 opens twice; the same bytes turned around do not
    twice = base64.b64encode(base64.b64encode(PAYLOAD))
    assert promise(twice) > promise(twice[::-1])


def test_an_unwritten_buffer_is_not_a_payload():
    # bytearray(len(_s)) folded to zeros is a container's shape, so the fold may
    # not report it and must let the backend tree look at the bytes instead
    packed = base64.b64encode(zlib.compress(PAYLOAD))
    columns = 7
    rows = [packed[index:index + columns] for index in range(0, len(packed), columns)]
    written = bytearray()
    for column in range(columns):
        for row in rows:
            if column < len(row):
                written.append(row[column])
    source = ("import os\n"
              "_columns = int(os.environ.get('PYDECOMP_COLUMNS', '7'))\n"
              "_s = %r\n"
              "_rows = -(-len(_s) // _columns)\n"
              "_out = bytearray(len(_s))\n"
              "print(_out)\n"
              "raise SystemExit(0)\n" % bytes(written))
    assert [item.data for item in find_payloads(source)] == []


def test_data_uris_give_up_their_bytes():
    from pydecomp.plugins.backends.codecs.datauri import _open_data_uri

    packed = base64.b64encode(zlib.compress(PAYLOAD)).decode()
    assert _open_data_uri(("data:application/octet-stream;base64," + packed).encode()) \
        == zlib.compress(PAYLOAD)
    spelled = "".join("%%%02X" % byte for byte in PAYLOAD).encode()
    assert _open_data_uri(b"data:text/plain," + spelled) == PAYLOAD
    assert _open_data_uri(b"data:") is None
    assert _open_data_uri(PAYLOAD) is None


def test_wide_and_lookalike_text_fold_back():
    from pydecomp.plugins.backends.codecs.glyphs import _open_homoglyph, _open_wide

    wide = "".join(chr(ord(character) + 0xFEE0) for character in "def greet():")
    assert _open_wide(wide.encode()) == b"def greet():"
    lookalike = "def gre\u0435t(n\u0430me):"      # Cyrillic e and a
    assert _open_homoglyph(lookalike.encode()) == b"def greet(name):"
    assert _open_wide(PAYLOAD) is None
    assert _open_homoglyph(PAYLOAD) is None


def _repeating_key_fixture(length: int, repeats: int = 150) -> tuple[bytes, bytes]:
    source = b"".join(b"def step%d(value):\n    return value * %d + 1\n\n" % (index, index)
                      for index in range(repeats))
    plain = base64.b64encode(zlib.compress(source))
    key = bytes((index * 37 + 11) % 251 for index in range(length))
    return plain, bytes(byte ^ key[index % length] for index, byte in enumerate(plain))


@pytest.mark.parametrize("length", [3, 6, 8])
def test_a_repeating_key_is_recovered_without_the_key_in_the_file(length):
    from pydecomp.plugins.backends.cipher.repeatkey import _each_repeating_key

    plain, cipher = _repeating_key_fixture(length)
    assert plain in list(_each_repeating_key(cipher))


def test_a_short_ciphertext_is_not_claimed():
    from pydecomp.plugins.backends.cipher.repeatkey import MIN_COLUMN, _each_repeating_key

    plain, cipher = _repeating_key_fixture(4)
    truncated = cipher[:MIN_COLUMN - 1]
    assert list(_each_repeating_key(truncated)) == []


def test_noise_is_not_turned_into_a_key():
    from pydecomp.plugins.backends.cipher.repeatkey import _each_repeating_key

    assert list(_each_repeating_key(os.urandom(4096))) == []


# --------------------------------------------------------------------------
# the tree checked against itself: every declared inverse has to roundtrip
# --------------------------------------------------------------------------

def _forged_backends():
    return [backend for backend in backends() if backend.forge is not None]


def test_the_tree_declares_inverses_for_most_of_itself():
    assert len(_forged_backends()) >= 36


@pytest.mark.parametrize("name", [backend.name for backend in _forged_backends()])
def test_a_declared_inverse_roundtrips(name):
    from pydecomp.plugins.backends import by_name

    backend = by_name(name)
    # varied across the body on purpose: a payload that compresses to 120 bytes
    # is below the column length a repeating-key solve needs, and these tests
    # are about the backends, not about that limit
    body = b"".join(b"def step%d(value):\n    return value * %d + 1\n\n" % (index, index)
                    for index in range(40))
    payload = base64.b64encode(zlib.compress(body))
    forged = backend.inverts(payload)
    assert forged is not None, f"{name} forged nothing"
    assert forged != payload
    if backend.kind == "container":
        # a container cuts the layer free; opening it is the next step's job
        assert backend.candidates(forged)
    else:
        assert payload in backend.candidates(forged)


def test_a_backend_without_an_inverse_says_so_rather_than_guessing():
    from pydecomp.plugins.backends import by_name

    backend = by_name("xorself")           # its key is written as its own stream
    assert backend.forge is None
    assert backend.inverts(PAYLOAD) is None


def test_the_two_byte_swaps_are_their_own_inverse():
    from pydecomp.plugins.backends.cipher.bitrev import _open_bitrev, _open_nibble

    payload = b"def greet(name):\n    return 'hello ' + name\n"
    turned = payload.translate(
        bytes(int(f"{byte:08b}"[::-1], 2) for byte in range(256)))
    assert turned != payload
    assert _open_bitrev(turned) == payload
    swapped = payload.translate(bytes(((b & 0x0F) << 4) | (b >> 4) for b in range(256)))
    assert _open_nibble(swapped) == payload


def test_a_uu_body_longer_than_one_line_comes_back_whole():
    from pydecomp.plugins.backends.codecs.rearrange import _forge_uu, _open_uu

    payload = b"def step(value):\n    return value * 7 + 1\n\n" * 20
    forged = _forge_uu(payload)
    assert forged.count(b"\n") > 2
    # every line carries its own length: joining them and decoding once returns
    # the first line and silently drops the rest, which is what this checks
    assert _open_uu(forged) == payload
