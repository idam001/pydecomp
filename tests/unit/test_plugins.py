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
