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
    ap.add_argument("--fast", action="store_true",
                    help="skip the expensive proofs (opaque-predicate solving); "
                         "identical output for clean files")
    ap.add_argument("--deep", action="store_true",
                    help="spend more time: deeper decoder chains, more XOR keys")
    ap.add_argument("--version", action="version", version=f"pydecomp {__version__}")
    args = ap.parse_args(argv)

    global USE_COLOR, INTERACTIVE
    if args.no_color:
        USE_COLOR = False
    if args.no_anim:
        INTERACTIVE = False

    if args.selftest:
        return selftest()

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
                                       pick=args.pick)
            return 0 if written else 1
        path = deobfuscate(args.file, args.out, clean=not args.no_clean,
                           keep_artifacts=args.artifacts,
                           reports=args.reports,
                           yara=args.yara,
                           diff=args.diff,
                           verify=args.verify, dry_run=args.dry_run,
                           neutralize=args.neutralize, fast=args.fast,
                           pick=args.pick)
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
        return 0 if path else 1

    return interactive_loop(args.out)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
