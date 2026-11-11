"""pydecomp - __init__."""
from __future__ import annotations

import base64
import os
import struct
import sys
import time
import types
import zlib

from ..terminal.animate import animate_bar, animate_text, spinner
from ..terminal.banner import header
from ..terminal.color import BOLD, CYAN, GREEN, GREY, RED, WHITE, YELLOW, paint
from ..terminal.panel import panel

_EMBEDDED_NATIVE = None

def _probe_elf() -> bytes:
    """A valid, empty ELF header — the selftest needs no sample on disk."""
    import struct
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack("<HHIQQQIHHHHHH",
                         3,            # ET_DYN
                         0x3E,         # EM_X86_64
                         1,            # EV_CURRENT
                         0, 0, 0, 0,   # entry, phoff, shoff
                         64, 56, 0, 64, 0, 0)   # ehsize, phentsize, phnum, ...
    return ident + header + b"\x00" * 16

def _load_native():
    """Import the native layer however this build ships it.

    Three layouts have to work: ``native.py`` next to this file, ``native.py``
    on ``PYTHONPATH``, and the single-file build where the same source is
    embedded (compressed) in this very file.  Nothing here executes a sample;
    only Python code that belongs to the tool is run.
    """
    import types
    here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else ""
    if here and here not in sys.path:
        sys.path.insert(0, here)
    try:                                             # packaged layout
        from . import sidecar as module               # noqa: PLC0415 - optional part
        return module
    except ImportError:
        pass
    try:                                             # legacy sibling module
        import native as module                       # noqa: PLC0415 - optional sibling
        return module
    except ImportError:
        pass
    packed = globals().get("_EMBEDDED_NATIVE")
    if not packed:
        return None
    try:
        import base64
        import zlib
        source = zlib.decompress(base64.b64decode(packed)).decode("utf-8")
    except Exception:                                # noqa: BLE001 - corrupt build
        return None
    module = types.ModuleType("native")
    module.__file__ = globals().get("__file__", "<pydecomp>")
    sys.modules["native"] = module
    # the native layer imports this module back; when we are the script, that
    # name has to resolve to __main__
    sys.modules.setdefault("pydecomp", sys.modules.get("__main__", module))
    try:
        exec(compile(source, "<native.py>", "exec"), module.__dict__)   # noqa: S102
    except Exception:                                # noqa: BLE001 - keep the tool usable
        return None
    return module

def native_hint() -> str:
    """One line telling the user how to fix a missing native layer."""
    return ("the native layer is not installed — install the package "
            "(`pip install pydecomp[cython]`), keep native.py beside the script, or "
            "run the single-file build (`python3 tools/build_single.py`)")

def is_elf(path: str) -> bool:
    """True when the file starts with the ELF magic (never executed to check)."""
    try:
        with open(os.path.expanduser(path), "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False

def deobfuscate_native(src_path: str, out_dir: str | None = None,
                       mode: str = "auto") -> str | None:
    """Cython / ELF front-end: recover source, write it, print the panel."""
    started = time.time()
    src_path = os.path.abspath(os.path.expanduser(str(src_path).strip().strip("'\"")))
    if not os.path.isfile(src_path):
        print("   " + paint("✘", RED) + " " + paint(f"file not found: {src_path}", RED))
        return None

    name = os.path.basename(src_path)
    raw_size = os.path.getsize(src_path)
    label = {"cython": "Cython module", "elf": "ELF binary"}.get(mode, "native object")
    animate_text(f"Reading {name}", 0.45)
    spinner(f"mapping {raw_size:,} bytes as ELF", 0.5)

    native_mod = _load_native()
    if native_mod is None:
        print("   " + paint("✘", RED) + " " + paint(native_hint(), YELLOW))
        return None

    try:
        result = native_mod.analyse_native(
            src_path, out_dir or os.path.dirname(src_path) or ".", mode)
    except Exception as exc:                        # noqa: BLE001 - report, never crash the menu
        if "not an ELF" in str(exc):
            print("   " + paint("✘", RED) + " "
                  + paint("that file is not an ELF object — option 1 handles "
                          "Python scripts", YELLOW))
            return None
        print("   " + paint("✘", RED) + " "
              + paint(f"{label} analysis failed: {type(exc).__name__}: {exc}", RED))
        return None

    stats = result.get("stats", {})
    written = result.get("written", [])
    for index, path in enumerate(written[:3]):
        animate_bar(f"stage {index + 1}", 0.38, CYAN, os.path.basename(path))

    source_path = result.get("primary") or next(
        (path for path in written if path.endswith(".py")),
        written[0] if written else None)
    if source_path is None:
        print("   " + paint("✘", RED) + " nothing was written")
        return None
    nbytes = os.path.getsize(source_path)
    elapsed = time.time() - started
    kind = result.get("kind", label)
    if kind == "cython":
        result_label = f"cython   {stats.get('tier', '?')}"
        detail = (f"{stats.get('methods', 0)} methods   "
                  f"{stats.get('functions', 0)} functions   "
                  f"{stats.get('classes', 0)} classes")
        recovered = []
        if stats.get("docstrings"):
            recovered.append(f"{stats['docstrings']} docstrings")
        if stats.get("source_lines"):
            recovered.append(f"{stats['source_lines']} verbatim source lines")
        if stats.get("line_rows"):
            recovered.append(f"{stats['line_rows']} line rows")
        if stats.get("identifiers"):
            recovered.append(f"{stats['identifiers']} identifiers")
        if stats.get("literals"):
            recovered.append(f"{stats['literals']} literals")
    else:
        findings = result.get("findings", {})
        result_label = "elf   container + payload scan"
        detail = (f"{stats.get('payloads', 0)} payload"
                  f"{'' if stats.get('payloads') == 1 else 's'}   "
                  f"{findings.get('sections', '')}"
                  f"{'sections' if findings.get('sections') else 'no sections'}")
        detail = (f"{stats.get('payloads', 0)} payload"
                  f"{'' if stats.get('payloads') == 1 else 's'}   "
                  f"python ext: {'yes' if findings.get('python_extension') else 'no'}"
                  f"   cython: {'yes' if findings.get('cython') else 'no'}")
        recovered = []
        for key in ("pyinstaller", "pyz", "zip_members"):
            if findings.get(key):
                recovered.append(f"{findings[key]} {key}")
    rows = [
        ("target", f"{name}   {raw_size:,} bytes", WHITE),
        ("result", result_label, WHITE),
        ("found", detail, WHITE),
        ("rebuilt", "  ·  ".join(recovered) or "structure only", WHITE),
    ]
    if stats.get("payloads"):
        detail = (f"{stats['payloads']} payload"
                  f"{'' if stats['payloads'] == 1 else 's'}")
        if stats.get("payload_functions"):
            detail += (f"   {stats['payload_functions']} functions   "
                       f"{stats.get('payload_rebuilt', 0)} rebuilt exactly")
        rows.append(("payload", detail, WHITE))
        if stats.get("payload_audit"):
            rows.append(("runnable", stats["payload_audit"], WHITE))
    rows.append(("output", f"{os.path.basename(source_path)}   {nbytes:,} bytes",
                 GREEN + BOLD))
    others = [os.path.basename(path) for path in written if path != source_path]
    if others:
        rows.append(("also", ", ".join(others), GREY))
    rows.append(("elapsed", f"{elapsed:.2f}s", GREY))
    print()
    panel("DONE", rows, tint=GREEN)
    print()
    print("   " + paint(f"cat '{source_path}'", GREY))
    return source_path
