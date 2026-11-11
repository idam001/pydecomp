#!/usr/bin/env python3
"""Build the binary fixtures used by ``tests/integration/test_native.py``.

The fixtures are generated, not committed, because they are compiler output:
the same ``demo_module.py`` becomes four different ``.so`` files (plain,
``-g``, ``-O0`` and stripped) and three payload carriers (hex, base64, zip and
zlib/marshal appended to a stripped module).

Requirements: CPython 3.9+, ``cython`` and ``gcc``.  Without them the script
still produces the text payloads and the tests skip the ELF cases.

    python3 tests/fixtures/native/make_native_fixtures.py

Nothing here runs the fixture payload; ``compile()``/``marshal.dumps()`` only
produce bytes that pydecomp is then expected to recover statically.
"""
from __future__ import annotations

import base64
import marshal
import pathlib
import shutil
import subprocess
import sys
import zipfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
DEMO = HERE / "demo_module.py"

PAYLOAD = '''"""Payload used to test carve-outs from compiled images."""
import json

LIMIT = 3
MARKER = "RECOVER_ME_7731"


class Headers:
    def __init__(self, host):
        self.host = host

    def as_dict(self):
        return {"Host": self.host}


def parse_payload(blob):
    data = json.loads(blob)
    return data.get("items", [])[:LIMIT]


def main(blob):
    return parse_payload(blob)
'''


def _run(cmd: list[str]) -> bool:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (FileNotFoundError, OSError):
        return False
    if done.returncode != 0:
        print(f"  ! {' '.join(cmd[:3])} failed: {done.stderr.strip()[:200]}")
    return done.returncode == 0


def build_extension() -> None:
    if not shutil.which("gcc"):
        print("gcc missing - skipping the compiled fixtures")
        return
    if not _run([sys.executable, "-m", "cython", "--line-directives", "-3",
                 str(DEMO), "-o", str(HERE / "demo_module.c")]):
        print("cython missing - skipping the compiled fixtures")
        return
    include = subprocess.run([sys.executable, "-c",
                              "import sysconfig;print(sysconfig.get_paths()['include'])"],
                             capture_output=True, text=True).stdout.strip()
    c_file = str(HERE / "demo_module.c")
    builds = {
        "demo_module.so": ["-O1"],
        "demo_lines.so": ["-O0", "-g"],
        "demo_module_g.so": ["-O0"],
    }
    for name, flags in builds.items():
        _run(["gcc", "-shared", "-fPIC", *flags, f"-I{include}", c_file,
              "-o", str(HERE / name)])
    if (HERE / "demo_module.so").exists():
        shutil.copyfile(HERE / "demo_module.so", HERE / "demo_stripped.so")
        _run(["strip", "-s", str(HERE / "demo_stripped.so")])


def build_payloads() -> None:
    source = PAYLOAD.encode("utf-8")
    (HERE / "payload_src.py").write_bytes(source)
    base = HERE / "demo_stripped.so"
    if not base.exists():
        print("no stripped .so - skipping the payload carriers")
        return
    image = base.read_bytes()
    (HERE / "packed_hex.so").write_bytes(image + b"\n" + source.hex().encode() + b"\n")
    (HERE / "packed_b64.so").write_bytes(image + b"\n" + base64.b64encode(source) + b"\n")

    archive = HERE / "packed_zip.so"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("payload_src.py", source)
    archive.write_bytes(image + archive.read_bytes())

    code = compile(PAYLOAD, "payload_src.py", "exec")
    (HERE / "packed_marshal.so").write_bytes(
        image + b"\n" + zlib.compress(marshal.dumps(code), 9) + b"\n")


def copy_real_sample() -> None:
    """The Android Cython stub, when the sample tree is available."""
    for candidate in (pathlib.Path("/home/user/uploads/xynora.so.txt"),
                      HERE.parents[2] / "uploads" / "xynora.so.txt"):
        if candidate.exists():
            shutil.copyfile(candidate, HERE / "xynora.so")
            print(f"  copied {candidate.name} -> xynora.so ({candidate.stat().st_size:,} B)")
            return


def main() -> int:
    build_extension()
    build_payloads()
    copy_real_sample()
    written = sorted(p.name for p in HERE.iterdir()
                     if p.suffix in {".so", ".c"} or p.name == "payload_src.py")
    print(f"fixtures: {', '.join(written) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
