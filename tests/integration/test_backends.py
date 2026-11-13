#!/usr/bin/env python3
"""Gate: the backend tree opens what it says, refuses what it should, and is wired.

Four questions, all of them about behaviour rather than structure:

  reach      a chain of codec, compression and cipher is found from bytes alone
  refuse     a blob of noise ends in no hit, and prose is not a payload
  budget     running out of work is reported instead of becoming "nothing"
  wiring     a real file whose key only exists at run time still gives up its
             payload, and the recipe says which chain read it

Run directly::

    PYTHONPATH=src python3 tests/integration/test_backends.py
"""
from __future__ import annotations

import base64
import os
import random
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

FAILED = []


def ok(condition, message):
    if condition:
        print(f"ok    {message}")
    else:
        print(f"FAIL  {message}")
        FAILED.append(message)


def main() -> int:
    from pydecomp.engine.peel import find_payloads
    from pydecomp.engine.plugins_pass import explore_blobs, looks_like_payload
    from pydecomp.plugins.backends import Budget, backends, describe, explore
    from pydecomp.plugins.backends.cipher.stream import rc4

    payload = (b"import os\n\n"
               b"def collect(path='/tmp'):\n"
               b"    return [name for name in os.listdir(path)]\n\n"
               b"print(len(collect()))\n")

    def accept(data, chain):
        return data == payload

    ok(len(backends()) >= 40, f"{len(backends())} backends registered across five trees")
    ok(len({line.split()[0] for line in describe()}) >= 4,
       "every kind is represented: " + ", ".join(sorted({line.split()[0] for line in describe()})))

    found = explore_blobs([base64.b64encode(zlib.compress(payload))])
    ok(bool(found) and found[0][0] == ["b64", "zlib"], "codec + compression chain found")

    blob = b"K3y!8z" + rc4(payload, b"K3y!8z")
    result = explore(blob, accept, depth=5, budget=Budget(opens=4000))
    ok(bool(result.hits), "cipher in front of the data is found")

    random.seed(3)
    noise = bytes(random.randrange(256) for _ in range(1024))
    ok(explore(noise, accept, depth=3, budget=Budget(opens=300)).hits == (),
       "a kilobyte of noise ends in no hit")
    ok(not looks_like_payload(b"W:l@AG#HA1+9HA!Bk7f?HXE$(`;3Uc@GYh9[D3L#Z\n"),
       "prose that happens to parse is not a payload")

    starved = explore(base64.b64encode(os.urandom(2048)), accept, depth=4,
                      budget=Budget(opens=2))
    ok(starved.exhausted and starved.hits == (), "an exhausted search says so")

    key = ord("A") ^ 0x5C
    mixed = bytes(byte ^ key for byte in base64.b64encode(zlib.compress(payload)))
    source = ("import base64, os, zlib\n"
              "_seed = os.environ.get('PYDECOMP_SEED', 'A')\n"
              "_key = ord(_seed[0]) ^ 0x5C\n"
              "_p = %r\n"
              "exec(zlib.decompress(base64.b64decode("
              "bytes(b ^ _key for b in _p))))\n" % mixed)
    payloads = find_payloads(source)
    ok([item.data for item in payloads] == [payload],
       "a loader whose key exists only at run time still yields its payload")
    ok(payloads and payloads[0].recipe, "the recipe names the chain that read it")

    data_only = "_blob = %r\nraise SystemExit(0)\n" % base64.b64encode(
        zlib.compress(payload))
    ok([item.data for item in find_payloads(data_only)] == [payload],
       "a data-only file is read without a loader")

    if FAILED:
        print(f"\n{len(FAILED)} failed")
        return 1
    print(f"\n9 checks passed — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
