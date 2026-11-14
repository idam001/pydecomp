from __future__ import annotations

from pydecomp.engine import decode


def test_deep_decode_cache_never_exceeds_capacity_and_evicts_oldest(monkeypatch):
    decode._DECODE_CACHE.clear()
    monkeypatch.setattr(decode, "_DECODE_CACHE_CAP", 2)
    calls = []

    def fake_decode(blob, _depth, _limit):
        calls.append(blob)
        return blob, ["identity"]

    monkeypatch.setattr(decode, "_deep_decode_uncached", fake_decode)
    try:
        assert decode.deep_decode(b"first") == (b"first", ["identity"])
        assert decode.deep_decode(b"second") == (b"second", ["identity"])
        assert len(decode._DECODE_CACHE) == 2
        assert decode.deep_decode(b"third") == (b"third", ["identity"])
        assert len(decode._DECODE_CACHE) == 2
        assert decode.deep_decode(b"first") == (b"first", ["identity"])
        assert calls == [b"first", b"second", b"third", b"first"]
        assert len(decode._DECODE_CACHE) == 2
    finally:
        decode._DECODE_CACHE.clear()
