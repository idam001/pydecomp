"""pydecomp - cli."""
from __future__ import annotations

import argparse
import os
import sys

from .bytecode.magic import host_version, parse_pyc
from .bytecode.roundtrip import identity_report
from .engine.decode import _deep_mode
from .engine.run import deobfuscate, deobfuscate_tree
from .limits import __version__
from .native import _load_native, _probe_elf, deobfuscate_native, is_elf, native_hint
from .terminal.banner import header
from .terminal.color import (CYAN, GREEN, GREY, INTERACTIVE, RED, USE_COLOR,
                             WHITE, ok, paint)
from .terminal.menu import interactive_loop
from .terminal.panel import panel

def selftest() -> int:
    """Report what this build can actually do — useful on a fresh install."""
    import platform
    from .terminal import identity
    rows = [("pydecomp", __version__, WHITE),
            ("author", identity.author(), CYAN),
            ("network", identity.network(), WHITE),
            ("country", identity.country_label(), WHITE),
            ("python", platform.python_version(), WHITE),
            ("platform", f"{platform.system()} {platform.machine()}", WHITE)]
    native = _load_native()
    if native is None:
        rows.append(("native", "missing — " + native_hint(), RED))
        panel("SELFTEST", rows, tint=RED)
        return 1
    embedded = globals().get("_EMBEDDED_NATIVE") is not None
    # In the single-file bundle the sidecar is a module-table entry, so it has no
    # __file__; saying so is the honest answer, crashing is not.
    location = getattr(native, "__file__", None)
    where = "embedded" if embedded or not location else os.path.dirname(location)
    rows.append(("native", f"{getattr(native, '__version__', '?')} ({where})", GREEN))
    rows.append(("menu 1", "scripts: loaders, names, ciphers, marshal, pyc, IOCs", GREEN))
    try:
        from .plugins.backends import backends as _backends
        kinds = {}
        for backend in _backends():
            kinds[backend.kind] = kinds.get(backend.kind, 0) + 1
        rows.append(("backends", f"{len(_backends())} across "
                     + ", ".join(f"{kind} {count}" for kind, count in sorted(kinds.items())),
                     GREEN))
    except Exception as exc:                        # noqa: BLE001 - report, do not crash
        rows.append(("backends", f"{type(exc).__name__}: {exc}", RED))
    rows.append(("menu 2", "Cython: tables, tiers S/B/A, payloads", GREEN))
    rows.append(("menu 3", "ELF: marshal, pyc, zip, PyInstaller, zlib/bz2/xz", GREEN))
    print()
    panel("SELFTEST", rows, tint=GREEN)
    print()
    print("   " + paint("reading a known-good ELF header is the last check …", GREY))
    try:
        image = native.ElfImage(_probe_elf(), "<probe>")
        ok("ELF parser: " + image.summary().get("type", "?"))
    except Exception as exc:                        # noqa: BLE001 - report, do not crash
        print("   " + paint(f"✘ ELF parser: {type(exc).__name__}: {exc}", RED))
        return 1
    ok("native layer is ready — options 2 and 3 will work")
    return 0

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pydecomp",
        description="Deobfuscate a packed Python script and save the result.")
    ap.add_argument("file", nargs="?", help="script to deobfuscate (skips the menu)")
    ap.add_argument("-o", "--out", default=None, help="output folder")
    ap.add_argument("--no-color", action="store_true", help="disable colour")
    ap.add_argument("--no-anim", action="store_true", help="disable animation")
    ap.add_argument("-m", "--mode", choices=("auto", "cython", "elf"), default="auto",
                    help="native mode: cython source recovery, ELF payload hunt, or auto")
    ap.add_argument("--selftest", action="store_true",
                    help="check the install: native layer, backends, menu options")
    ap.add_argument("--backends", action="store_true",
                    help="list the decoder backends and exit")
    ap.add_argument("--verify", action="store_true",
                    help="recompile the result and report instruction identity")
    ap.add_argument("--dry-run", action="store_true",
                    help="static runnability check: compile, resolve every name, report gaps")
    ap.add_argument("--no-clean", action="store_true",
                    help="keep the recovered file exactly as lifted (no renaming/folding)")
    ap.add_argument("--reports", action="store_true",
                    help="also write .report.json / .report.md next to the output")
    ap.add_argument("--diff", action="store_true",
                    help="compare the recovered program with the unpacked original "
                         "and report what was kept")
    ap.add_argument("--yara", action="store_true",
                    help="also write a YARA rule built from the recovered indicators")
    ap.add_argument("--artifacts", action="store_true",
                    help="keep the untouched input bytes next to the output")
    ap.add_argument("--neutralize", action="store_true",
                    help="disable anti-VM/anti-debug/expiry guards in the output")
    ap.add_argument("--pick", type=int, default=None, metavar="N",
                    help="when several files share a name, take the Nth newest "
                         "(default: the newest, and say so)")
    ap.add_argument("--html", action="store_true",
                    help="also write a self-contained .report.html (source, proof, "
                         "indicators) that opens offline")
    ap.add_argument("--check-proof", default=None, metavar="FILE",
                    help="re-derive a .proof.json from the sample and the output; "
                         "exits 4 if they have drifted")
    ap.add_argument("--fetch-iocs", action="store_true",
                    help="fetch the URLs the loader would have fetched and unpack "
                         "the responses statically (opt-in network access)")
    ap.add_argument("--mcp", action="store_true",
                    help="start the MCP server on stdio instead of analysing a file")
    ap.add_argument("--allow-write", action="store_true",
                    help="let the MCP server write recovered files")
    ap.add_argument("--pyarmor-runtime", default=None, metavar="PATH",
                    help="pyarmor_runtime library to derive the key from "
                         "(found beside the sample automatically)")
    ap.add_argument("--pyarmor-key", default=None, metavar="HEX",
                    help="runtime AES key, if you already have it")
    ap.add_argument("--strict", action="store_true",
                    help="write nothing unless every recovered unit is "
                         "instruction-identical to the original (exits 3)")
    ap.add_argument("--no-proof", action="store_true",
                    help="do not write the .proof.json / .proof.md companions")
    ap.add_argument("--annotate", action="store_true",
                    help="carry the proof tier as a comment header in the output")
    ap.add_argument("--fast", action="store_true",
                    help="skip the expensive proofs (opaque-predicate solving); "
                         "identical output for clean files")
    ap.add_argument("--deep", action="store_true",
                    help="spend more time: deeper decoder chains, more XOR keys")
    ap.add_argument("--legacy", action="store_true",
                    help="use the stack engine alone, skipping the SSA pipeline")
    ap.add_argument("--version", action="version", version=f"pydecomp {__version__}")
    args = ap.parse_args(argv)

    if getattr(args, "legacy", False):
        from .lift.module import ENGINE_SWITCH
        ENGINE_SWITCH["ssa"] = False

    global USE_COLOR, INTERACTIVE
    if args.no_color:
        USE_COLOR = False
    if args.no_anim:
        INTERACTIVE = False

    if args.check_proof:
        from .proof.verify import render as render_check, summary as summary_check
        from .proof.verify import verify as verify_proof
        result = verify_proof(args.check_proof)
        print()
        for line in render_check(result).splitlines():
            tint = GREEN if result["ok"] else RED
            print("   " + paint(line, tint if line.startswith(("proof", result["message"]))
                                else WHITE))
        print("   " + paint(summary_check(result), GREEN if result["ok"] else RED))
        print()
        if not result["checks"]:
            return 2
        return 0 if result["ok"] else 4

    if getattr(args, "backends", False):
        from .plugins.backends import describe
        for line in describe():
            print(line)
        return 0
    if args.selftest:
        return selftest()

    if args.mcp or args.file == "mcp":
        from .mcp.server import serve
        return serve(allow_write=args.allow_write)

    if args.file:
        if USE_COLOR:
            header(do_clear=False)
        if args.mode != "auto" or is_elf(args.file):
            return 0 if deobfuscate_native(args.file, args.out, args.mode) else 1
        if args.deep:
            _deep_mode()
        if os.path.isdir(args.file) or args.file.endswith((".zip", ".whl", ".tar.gz")):
            written = deobfuscate_tree(args.file, args.out,
                                       clean=not args.no_clean,
                                       keep_artifacts=args.artifacts,
                                       reports=args.reports,
                                       yara=args.yara,
                                       diff=args.diff,
                                       verify=args.verify, dry_run=args.dry_run,
                                       neutralize=args.neutralize, fast=args.fast,
                                       pick=args.pick, strict=args.strict,
                                       proof=not args.no_proof,
                                       annotate=args.annotate,
                                       pyarmor_runtime=args.pyarmor_runtime,
                                       pyarmor_key=args.pyarmor_key,
                                       fetch_iocs=args.fetch_iocs,
                                       html_report=args.html)
            if written:
                return 0
            from .engine import run as _run
            return _run.EXIT_CODE or 1
        path = deobfuscate(args.file, args.out, clean=not args.no_clean,
                           keep_artifacts=args.artifacts,
                           reports=args.reports,
                           yara=args.yara,
                           diff=args.diff,
                           verify=args.verify, dry_run=args.dry_run,
                           neutralize=args.neutralize, fast=args.fast,
                           pick=args.pick, strict=args.strict,
                           proof=not args.no_proof, annotate=args.annotate,
                           pyarmor_runtime=args.pyarmor_runtime,
                           pyarmor_key=args.pyarmor_key,
                           fetch_iocs=args.fetch_iocs,
                           html_report=args.html)
        if path and args.verify:
            try:
                try:
                    version, module = parse_pyc(open(args.file, "rb").read())
                except Exception:                    # noqa: BLE001 - plain source input
                    version = None
                if not version:
                    version = host_version()
                text = open(path, encoding="utf-8").read()
                for line in identity_report(text, version):
                    print("   " + paint(line, GREY))
            except Exception as exc:                 # noqa: BLE001 - verification is optional
                print("   " + paint(f"verification unavailable: "
                                    f"{type(exc).__name__}: {exc}", GREY))
        if path:
            return 0
        from .engine import run as _run
        return _run.EXIT_CODE or 1

    return interactive_loop(args.out)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
