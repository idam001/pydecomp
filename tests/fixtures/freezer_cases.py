"""Build one case per freezer, from the formats themselves.

Every freezer here is written byte by byte - the CArchive cookie and table of
contents, the ``library.zip`` inside a PE, the ``PEX-INFO`` zip, the zipapp
bootstrap - so the readers are tested against the format rather than against
another copy of the reader.
"""
from __future__ import annotations

import io
import json
import marshal
import struct
import zipfile

PROGRAM = '''\
"""Freezer case."""

MARKER = "FREEZER-MARKER"


def run(x):
    return x * 2 + 1
'''

PROGRAM2 = '''\
def helper(rows):
    return sum(len(row) for row in rows)
'''


def pyc_bytes(source: str, filename: str = "<frozen>") -> bytes:
    """A real .pyc: magic + zeroed header + marshal of the code object."""
    import sys
    magic = __import__("importlib.util", fromlist=["MAGIC_NUMBER"]).MAGIC_NUMBER
    code = compile(source, filename, "exec")
    return magic + b"\x00" * 12 + marshal.dumps(code)


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


# --------------------------------------------------------------------- shiv
def shiv() -> bytes:
    return _zip({
        "_bootstrap/__init__.py": b"# shiv entry\n",
        "site-packages/app/__init__.py": PROGRAM.encode(),
        "app.pyz": b"",
    })


# ---------------------------------------------------------------------- pex
def pex() -> bytes:
    info = json.dumps({"requirements": [], "distributions": {}, "entry_point": "app.main"})
    return _zip({
        "PEX-INFO": info.encode(),
        ".bootstrap/_pex/__init__.py": b"# pex\n",
        "app/main.py": PROGRAM.encode(),
        "app/model.py": PROGRAM2.encode(),
    })


# ---------------------------------------------------------------- briefcase
def briefcase() -> bytes:
    return _zip({
        "app_packages/widget/__init__.py": PROGRAM.encode(),
        "widget-1.0.dist-info/METADATA": b"Name: widget\nVersion: 1.0\n",
        "briefcase.toml": b"[paths]\n",
        "app/app.py": PROGRAM2.encode(),
    })


# ---------------------------------------------------------------- cx_Freeze
def _library_zip() -> bytes:
    return _zip({
        "app.pyc": pyc_bytes(PROGRAM, "app.py"),
        "helper.pyc": pyc_bytes(PROGRAM2, "helper.py"),
        "boot.pyc": pyc_bytes("x = 1\n", "boot.py"),
    })


def cx_freeze() -> bytes:
    """A dist: the frozen executable beside its library.zip."""
    return _zip({
        "library.zip": _library_zip(),
        "lib/python313.zip": b"",
    })


def cx_freeze_bare() -> bytes:
    return _library_zip()


# ------------------------------------------------------------------ py2exe
def py2exe() -> bytes:
    image = b"MZ" + b"\x00" * 126 + b"python3.13.dll\x00" + b"\x00" * 4096
    return image + _library_zip()


# -------------------------------------------------------------- pyinstaller
COOKIE = struct.Struct("!8sIIII64s")
ENTRY = struct.Struct("!IIIIBc")
MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def _entry(name: bytes, offset: int, payload: bytes, flag: int, kind: bytes,
           uncompressed: int | None = None) -> bytes:
    body = ENTRY.pack(ENTRY.size + len(name), offset, len(payload),
                      uncompressed if uncompressed is not None else len(payload),
                      flag, kind) + name
    return body


def pyinstaller() -> bytes:
    """A CArchive with a script member and a PYZ holding two modules."""
    import zlib
    script = marshal.dumps(compile(PROGRAM, "script.py", "exec"))
    modules = {}
    for name, source in (("pkg.mod", PROGRAM), ("pkg.other", PROGRAM2)):
        modules[name] = zlib.compress(marshal.dumps(compile(source, name, "exec")))
    chunks = b"".join(modules.values())
    base = 0
    for _ in range(8):                     # the table's own size is part of the offset
        offset = base
        table = []
        for name, chunk in modules.items():
            table.append((name, ("z", offset, len(chunk))))
            offset += len(chunk)
        toc_blob = marshal.dumps(table)
        if len(toc_blob) == base:
            break
        base = len(toc_blob)
    pyz = zlib.compress(marshal.dumps(table) + chunks)
    data = script + pyz
    toc = (_entry(b"script", 0, script, 0, b"s") +
           _entry(b"PYZ-00.pyz", len(script), pyz, 1, b"z",
                  uncompressed=len(marshal.dumps(table) + chunks)))
    archive = data + toc
    cookie = COOKIE.pack(MAGIC, len(archive) + COOKIE.size, len(data), len(toc),
                         313, b"python3.13")
    return archive + cookie


CASES = {
    "shiv": shiv,
    "pex": pex,
    "briefcase": briefcase,
    "cx_freeze": cx_freeze,
    "cx_freeze_bare": cx_freeze_bare,
    "py2exe": py2exe,
    "pyinstaller": pyinstaller,
}


def write_all(folder: str) -> dict[str, str]:
    import os
    os.makedirs(folder, exist_ok=True)
    paths = {}
    for name, builder in CASES.items():
        path = os.path.join(folder, name + ".bin")
        with open(path, "wb") as handle:
            handle.write(builder())
        paths[name] = path
    return paths
