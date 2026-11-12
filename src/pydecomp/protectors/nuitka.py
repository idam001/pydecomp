"""pydecomp - nuitka recovery front end.

Nuitka compiles Python to C and then to machine code, so a bytecode decompiler
has nothing to read.  Recovery is done by a native-code tool that knows Nuitka's
constant blobs and dispatch tables; pydecomp does not reimplement that, it
*orchestrates* it and ingests the audit it produces:

* HEXPYRION (successor to nuitka-revenant) - ``hexpyrion <binary> --json``
* nuitka-revenant - ``nuitka-revenant <binary> -o <dir>``

When neither is installed the run is not lost: Nuitka leaves its module
constants, string tables and the original file names in the binary, so the
static carve still reports what is in there, and this module says exactly which
command would go further.  That is a limit of *this* machine, not of the file.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

NAME = "nuitka"
_MARKERS = (b"Nuitka", b"NUITKA", b".nbc", b"__nuitka_binary_dir")
_ELF = b"\x7fELF"
_PE = b"MZ"
TIMEOUT = 1800


def detect(data: bytes) -> bool:
    if not data:
        return False
    native = data[:4] == _ELF or data[:2] == _PE
    if not native:
        return False
    window = data[:1 << 20] if len(data) > (1 << 20) else data
    return any(marker in window for marker in _MARKERS)


def detect_source(text: str) -> bool:
    return "nuitka" in text[:4096].lower() if text else False


def tools() -> list[tuple[str, list[str], str]]:
    """(name, argv, how to read the result) for each installed backend."""
    found = []
    hexpyrion = shutil.which("hexpyrion") or shutil.which("hexpyrion.exe")
    if hexpyrion:
        found.append(("hexpyrion", [hexpyrion, "{input}", "--json", "-o", "{out}"],
                      "json"))
    revenant = shutil.which("nuitka-revenant") or shutil.which("revenant")
    if revenant:
        found.append(("nuitka-revenant", [revenant, "{input}", "-o", "{out}"], "files"))
    return found


def available() -> str:
    names = [name for name, _argv, _kind in tools()]
    return ", ".join(names) if names else "none installed"


def recover(binary_path: str, out_dir: str) -> dict:
    """Run the first installed backend and read back what it produced."""
    result: dict = {"backend": None, "files": [], "audit": {}, "note": ""}
    path = os.path.abspath(binary_path)
    if not os.path.isfile(path):
        result["note"] = f"no such file: {binary_path}"
        return result
    os.makedirs(out_dir, exist_ok=True)
    for name, argv, kind in tools():
        command = [part.format(input=path, out=out_dir) for part in argv]
        try:
            done = subprocess.run(command, capture_output=True, text=True,
                                  timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["note"] = f"{name}: {type(exc).__name__}"
            continue
        result["backend"] = name
        if kind == "json":
            for blob in (done.stdout, done.stderr):
                text = blob.strip()
                if not text.startswith(("{", "[")):
                    continue
                try:
                    result["audit"] = json.loads(text)
                except ValueError:
                    continue
                break
        result["files"] = sorted(
            os.path.join(out_dir, entry) for entry in os.listdir(out_dir)
            if entry.endswith((".py", ".pyi")))
        if result["files"] or result["audit"]:
            if isinstance(result["audit"], dict):
                result["audit"].setdefault("backend", name)
                result["audit"].setdefault("argv", command)
            return result
        result["note"] = f"{name} produced nothing it could read back"
    if not result["note"]:
        result["note"] = ("no Nuitka recovery backend is installed here - "
                          f"checked hexpyrion and nuitka-revenant; the carve "
                          f"below is what the binary itself holds")
    return result


def summary(result: dict) -> str:
    if result.get("files"):
        return (f"{result['backend']}: {len(result['files'])} source file(s) "
                "recovered from the native image")
    return result.get("note") or "nothing recovered"
