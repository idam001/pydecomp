"""Build a PyArmor-8/9-shaped case from first principles.

The real format is not published by its vendor, so this fixture is built from
the layout the public research describes (``PY`` + six digits, a packed header
with the interpreter version, protection byte and 12-byte AES-CTR nonce, then
the encrypted marshal stream) and from what the runtime does: AES-128-CTR over
the marshalled code object, with the key living in the ``pyarmor_runtime``
library.

Building it here means the whole static path - header parse, key hunt, decrypt,
marshal parse, lift - is exercised against bytes with a known answer, instead
of being asserted to work.
"""
from __future__ import annotations

import marshal
import os

from pydecomp.crypto.aes import AES
from pydecomp.crypto.modes import ctr_xor

HEADER = 0x40
OFF_VERSION = 9
OFF_PROTECT = 0x14
OFF_NONCE = 0x2C

PROGRAM = '''\
"""Reconciliation worker."""

RELAY = "https://relay.internal.example/collect"
MARKER = "PYARMOR-FIXTURE-MARKER"


def collect(rows):
    total = 0
    for row in rows:
        if row.get("amount"):
            total += int(row["amount"])
    return total


def ship(payload):
    import json
    body = json.dumps(payload, sort_keys=True)
    return len(body)


if __name__ == "__main__":
    print(collect([{"amount": "5"}, {"amount": "7"}]))
'''


def make_blob(version=(3, 13), key=b"\x11\x22\x33\x44\x55\x66\x77\x88"
              b"\x99\xaa\xbb\xcc\xdd\xee\xff\x10",
              nonce=b"nonce-000000",
              program: str = PROGRAM) -> bytes:
    """A ``PY`` + six digits blob whose ciphertext is a marshalled code object."""
    code = compile(program, "<pyarmor-inner>", "exec")
    plain = marshal.dumps(code)
    cipher = ctr_xor(AES(key), nonce, plain, counter_bits=32, start=1)
    header = bytearray(HEADER)
    header[0:8] = b"PY000000"
    header[8] = 0
    header[OFF_VERSION] = version[0]
    header[OFF_VERSION + 1] = version[1]
    header[OFF_PROTECT] = 0x08
    header[OFF_NONCE:OFF_NONCE + 12] = nonce
    header[0x38:0x3C] = (len(cipher) + HEADER).to_bytes(4, "little")
    header[0x3C:0x40] = HEADER.to_bytes(4, "little")
    return bytes(header) + cipher


def make_loader(blob: bytes) -> str:
    return (
        "# Pyarmor 9.0.0 (trial), 000000, non-profits, 2026-11-01T00:00:00\n"
        "from pyarmor_runtime_000000 import __pyarmor__\n"
        f"__pyarmor__(__name__, __file__, {blob!r})\n"
    )


def make_runtime(key: bytes) -> bytes:
    """A native library stand-in that carries the runtime key where it really is."""
    noise = bytes(range(256)) * 4
    body = (b"\x7fELF\x02\x01\x01\x00" + noise +
            b"Pyarmor Runtime (Trial) Information:\n"
            b"AES key: " + key.hex().encode() + b"\n"
            b"Mix string AES nonce: " + bytes(range(11, 23)).hex().encode() + b"\n" +
            noise)
    return body


def build(folder: str, program: str = PROGRAM, key: bytes | None = None) -> dict:
    """Write loader + runtime under *folder*; return the paths and the truth."""
    key = key or b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x10"
    nonce = b"nonce-000000"
    os.makedirs(folder, exist_ok=True)
    blob = make_blob(key=key, nonce=nonce, program=program)
    loader = os.path.join(folder, "worker.py")
    with open(loader, "w", encoding="utf-8") as handle:
        handle.write(make_loader(blob))
    runtime_dir = os.path.join(folder, "pyarmor_runtime_000000")
    os.makedirs(runtime_dir, exist_ok=True)
    runtime = os.path.join(runtime_dir, "pyarmor_runtime.so")
    with open(runtime, "wb") as handle:
        handle.write(make_runtime(key))
    return {"loader": loader, "runtime": runtime, "blob": blob,
            "key": key, "nonce": nonce, "program": program,
            "marker": "PYARMOR-FIXTURE-MARKER"}
