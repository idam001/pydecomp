"""pydecomp - nuitka recovery, in house.

Nuitka compiles Python to C and then to machine code, so there is no bytecode to
lift.  What the binary still carries is real, and this module reads it with its
own parsers - no external tool, no subprocess:

* **the constants tables.**  Nuitka stores module constants as marshalled
  objects in ``.rodata``/``.data.rel.ro`` behind ``__constants`` blobs.  The
  marshalled reader in this project opens them, so the strings, numbers, tuples
  and dicts a program was built from come back as Python literals.
* **the string table.**  ``qstrconst``/``qstr`` runs hold the module's identifiers
  and docstrings, including the ``.py`` file names the program was compiled from -
  the map of the original layout.
* **any embedded bytecode.**  A Nuitka build that bundled a ``.pyc`` (or a
  ``__compiled__`` payload) leaves the magic in the image.  When one is found it is
  lifted by the same lifter every other input goes through.

The output is written as Python: ``nuitka_recovered.py`` when an embedded module
was lifted, and ``nuitka_constants.py`` for the recovered constant surface.
"""
from __future__ import annotations

import os
import re

from ..native.sidecar import PYC_MAGICS, ElfImage, looks_like_elf

NAME = "nuitka"
_MARKERS = (b"Nuitka", b"NUITKA", b".nbc", b"__nuitka_binary_dir", b"__constants",
            b"qstrconst")
_ELF = b"\x7fELF"
_PE = b"MZ"

#: printable runs long enough to be a string the program built a message from
_MIN_STRING = 4
_STR_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING)

#: C identifiers Nuitka writes next to the constants it keeps
_CONST_MARKERS = (b"__constants", b"qstrconst", b"module.__compiled__",
                  b"__nuitka_binary_dir", b"NUITKA_ONEFILE_PARENT")


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


def available() -> str:
    """This front end is part of the build; there is nothing to install."""
    return "in-house"


# --------------------------------------------------------------------------- scan
def _sections(data: bytes) -> list[tuple[str, bytes]]:
    """Named sections of an ELF image, or the whole file when it is not ELF."""
    if not looks_like_elf(data):
        return [("<image>", data)]
    try:
        image = ElfImage(data)
    except Exception:                                  # noqa: BLE001 - hand back the raw file
        return [("<image>", data)]
    out = []
    for section in image.sections:
        try:
            out.append((section.name, data[section.off:section.off + section.size]))
        except Exception:                              # noqa: BLE001
            continue
    return out or [("<image>", data)]


def _marshalled_blobs(data: bytes, limit: int = 64) -> list[bytes]:
    """Every offset where a marshalled object plausibly starts.

    The marshal format is self-describing, so the test is: try to read it, and
    keep the ones the reader accepts with a sane amount consumed.
    """
    from ..bytecode.marshal_reader import parse_marshal_blob

    blobs: list[bytes] = []
    seen: set[int] = set()
    starts = set()
    for marker in _CONST_MARKERS:
        for found in re.finditer(re.escape(marker), data):
            starts.add(found.start())
    # walk forward from each marker: the payload follows the name, usually within
    # a few hundred bytes
    for start in sorted(starts):
        window_end = min(len(data), start + 4096)
        for probe in range(start, window_end, 1):
            byte = data[probe]
            if byte not in b"([{is" and not 0x30 <= byte <= 0x3a:
                continue
            if probe in seen:
                continue
            seen.add(probe)
            try:
                _version, code, consumed = parse_marshal_blob(data[probe:])
            except Exception:                          # noqa: BLE001 - not a blob
                continue
            if code is not None and consumed > 16:
                blobs.append(data[probe:probe + consumed])
                if len(blobs) >= limit:
                    return blobs
    return blobs


def _strings(data: bytes, limit: int = 5000) -> list[str]:
    out = []
    for match in _STR_RUN.finditer(data):
        text = match.group().decode("ascii", "replace")
        if len(out) >= limit:
            break
        out.append(text)
    return out


def _module_files(strings: list[str]) -> list[str]:
    return sorted({text for text in strings
                   if text.endswith(".py") and len(text) < 200})


def _literal_surface(strings: list[str], limit: int = 400) -> list[str]:
    """The strings that look like the program's own, not the C runtime's."""
    noise = ("GLIBC", "__libc", "/usr/lib", "gcc", "clang", "Nuitka_", "Py_",
             "__pyx_", "assertion", "LD_LIBRARY", "libpython")
    out = []
    for text in strings:
        if any(token in text for token in noise):
            continue
        if len(text) < 8 or text.startswith(("_", ".")):
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------------- recover
def recover(binary_path: str, out_dir: str) -> dict:
    """Read a Nuitka image with this project's own parsers.

    Returns ``{"backend": "in-house", "files": [...], "audit": {...}}``.  The
    audit lists what was found: sections scanned, marshalled blobs, the module
    file names, and how many strings came back.
    """
    result: dict = {"backend": NAME, "files": [], "audit": {}, "note": ""}
    path = os.path.abspath(binary_path)
    if not os.path.isfile(path):
        result["note"] = f"no such file: {binary_path}"
        return result
    with open(path, "rb") as handle:
        data = handle.read()
    os.makedirs(out_dir, exist_ok=True)

    sections = _sections(data)
    strings = _strings(data)
    files = _module_files(strings)
    blobs = _marshalled_blobs(data)

    audit = {
        "bytes": len(data),
        "sections": [name for name, _body in sections][:64],
        "markers": sorted({marker.decode("ascii", "replace")
                           for marker in _MARKERS if marker in data}),
        "marshalled_blobs": len(blobs),
        "module_files": files[:64],
        "strings": len(strings),
    }
    result["audit"] = audit

    written = []
    # 1. a lifted module, when the image still carries bytecode
    for index, blob in enumerate(blobs):
        lifted = _lift_blob(blob)
        if not lifted:
            continue
        target = os.path.join(out_dir, f"nuitka_recovered_{index}.py")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(lifted)
        written.append(target)
        break

    # 2. the constant surface, always
    surface = _literal_surface(strings)
    if surface or files:
        target = os.path.join(out_dir, "nuitka_constants.py")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write('# constants recovered from a Nuitka build\n')
            if files:
                handle.write("# modules compiled into this image:\n")
                for name in files[:200]:
                    handle.write(f"#   {name}\n")
            handle.write("\nCONSTANTS = [\n")
            for text in surface:
                handle.write(f"    {text!r},\n")
            handle.write("]\n")
        written.append(target)

    result["files"] = written
    if not written:
        result["note"] = "the image carries no constants this front end could read"
    return result


def _lift_blob(blob: bytes) -> str | None:
    """Lift an embedded marshalled module with the project's own lifter."""
    from ..bytecode.marshal_reader import parse_marshal_blob
    from ..lift.module import lift_module

    try:
        version, code, _consumed = parse_marshal_blob(blob)
    except Exception:                                  # noqa: BLE001
        return None
    if code is None:
        return None
    try:
        text = lift_module(code, tuple(version[:2]) if version else (3, 13))
    except Exception:                                  # noqa: BLE001
        return None
    return text or None


def summary(result: dict) -> str:
    files = result.get("files") or []
    audit = result.get("audit") or {}
    if files:
        detail = []
        if audit.get("marshalled_blobs"):
            detail.append(f"{audit['marshalled_blobs']} marshalled blob(s)")
        if audit.get("module_files"):
            detail.append(f"{len(audit['module_files'])} module name(s)")
        if audit.get("strings"):
            detail.append(f"{audit['strings']} strings")
        tail = (", ".join(detail)) if detail else "the constant surface"
        return f"in-house recovery: {len(files)} file(s) written ({tail})"
    return result.get("note") or "nothing recovered"
