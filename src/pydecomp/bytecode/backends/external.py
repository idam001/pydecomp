"""pydecomp - external backends.

Some interpreters are covered by a project that has spent years on them.  Using
it beats reimplementing it: the backend writes the sample's own bytes to a
temporary ``.pyc``, runs the tool, and reads back text.  The sample is never
imported or executed - a decompiler reads bytecode, it does not run it.

If the tool is missing the backend is simply not a candidate.  A missing
backend never fails a run, and it never changes the output for a version the
native pipeline already handles.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from ..backends.base import Backend

TIMEOUT = 600

#: name -> (argv template, versions it is known to cover)
TOOLS = {
    "pycdc-rs": (["{path}"], ((3, 11), (3, 15))),
    "pycdc": (["{path}"], ((1, 0), (3, 15))),
    "depyo": (["decompile", "{path}", "-o", "{out}"], ((3, 8), (3, 15))),
    "uncompyle6": (["-o", "{out}", "{path}"], ((1, 0), (3, 8))),
    "decompyle3": (["-o", "{out}", "{path}"], ((3, 7), (3, 10))),
}


class ExternalBackend(Backend):
    """A decompiler that lives in another package, invoked statically."""

    kind = "external"

    def __init__(self, name: str, argv: list[str] | None = None,
                 versions: tuple | None = None):
        self.name = name
        template, covered = TOOLS.get(name, (["{path}"], ((1, 0), (3, 99))))
        self.argv = list(argv or template)
        self.versions = versions or covered
        self._path: str | None = None

    def find(self) -> str | None:
        if self._path is None:
            self._path = shutil.which(self.name) or ""
        return self._path or None

    def available(self) -> bool:
        return self.find() is not None

    def decompile(self, data: bytes, version: tuple) -> str | None:
        tool = self.find()
        if not tool or not data:
            return None
        folder = tempfile.mkdtemp(prefix="pydecomp-backend-")
        path = os.path.join(folder, "sample.pyc")
        out = os.path.join(folder, "out")
        os.makedirs(out, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        argv = [tool] + [part.format(path=path, out=out) for part in self.argv]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = (done.stdout or "").strip()
        if not text or "Traceback" in text[:400]:
            text = ""
        if not text:
            for root, _dirs, files in os.walk(out):
                for entry in sorted(files):
                    if not entry.endswith(".py"):
                        continue
                    try:
                        with open(os.path.join(root, entry), encoding="utf-8",
                                  errors="surrogateescape") as handle:
                            text = handle.read()
                    except OSError:
                        continue
                    if text.strip():
                        break
                if text:
                    break
        return text or None


def installed() -> list[ExternalBackend]:
    """Every external backend this machine can actually run."""
    found = []
    for name in TOOLS:
        backend = ExternalBackend(name)
        if backend.available():
            found.append(backend)
    return found
