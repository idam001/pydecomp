#!/usr/bin/env python3
"""Build the evaluation corpus: every family of cooking pydecomp claims to undo.

Nothing here obfuscates "in general".  Each family is one *precise* stack of
transforms applied to real payload programs, written down in
``corpus/<family>/<case>/`` with a ``truth.json`` that names the payload by
digest.  That is what makes the evaluation a measurement instead of a vibe: a
family is either recovered or it is not, and the corpus says which case failed.

    python3 tools/make_corpus.py            # build everything
    python3 tools/make_corpus.py --check    # is the committed corpus current?
    python3 tools/make_corpus.py --list     # the families and their stacks

Adding a family is adding one entry to FAMILIES; the trainer and the evaluator
read the corpus directory, so they pick it up without being told.
"""
from __future__ import annotations

import argparse
import base64
import bz2
import codecs
import gzip
import hashlib
import json
import lzma
import marshal
import os
import py_compile
import shutil
import sys
import tempfile
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")

# --- payloads ---------------------------------------------------------------
# Small, varied, and every one of them is a program a person would recognise.
PAYLOADS = {
    "arith": (
        "def area(width, height):\n"
        "    if width <= 0 or height <= 0:\n"
        "        raise ValueError('positive only')\n"
        "    return width * height\n"
        "\n"
        "total = 0\n"
        "for side in [2, 3, 5]:\n"
        "    total += area(side, side)\n"
    ),
    "text": (
        "import re\n"
        "\n"
        "IP = re.compile(r'\\b\\d{1,3}(\\.\\d{1,3}){3}\\b')\n"
        "\n"
        "def hosts(blob):\n"
        "    return sorted(set(IP.findall(blob)))\n"
    ),
    "objects": (
        "class Session:\n"
        "    def __init__(self, host, port=443):\n"
        "        self.host = host\n"
        "        self.port = port\n"
        "\n"
        "    def url(self):\n"
        "        return f'https://{self.host}:{self.port}/'\n"
        "\n"
        "default = Session('example.com')\n"
    ),
    "io": (
        "import os\n"
        "\n"
        "def sizes(folder):\n"
        "    found = {}\n"
        "    for name in os.listdir(folder):\n"
        "        found[name] = os.path.getsize(os.path.join(folder, name))\n"
        "    return found\n"
    ),
}

# --- layers: name -> (encode, decode, python expression) --------------------
# encode() turns the payload into the blob, decode() is what a loader does.
OPS = {
    "b64": (base64.b64encode, lambda b: base64.b64decode(b, validate=False),
            "base64.b64decode({x})"),
    "b64url": (base64.urlsafe_b64encode, base64.urlsafe_b64decode,
               "base64.urlsafe_b64decode({x})"),
    "base32": (base64.b32encode, base64.b32decode, "base64.b32decode({x})"),
    "base85": (base64.b85encode, base64.b85decode, "base64.b85decode({x})"),
    "a85": (base64.a85encode, base64.a85decode, "base64.a85decode({x})"),
    "hex": (lambda b: b.hex().encode(), lambda b: bytes.fromhex(b.decode()),
            "bytes.fromhex({x}.decode())"),
    "zlib": (zlib.compress, zlib.decompress, "zlib.decompress({x})"),
    "lzma": (lzma.compress, lzma.decompress, "lzma.decompress({x})"),
    "gzip": (gzip.compress, gzip.decompress, "gzip.decompress({x})"),
    "bz2": (bz2.compress, bz2.decompress, "bz2.decompress({x})"),
    "reverse": (lambda b: b[::-1], lambda b: b[::-1], "({x})[::-1]"),
    "rot13": (lambda b: codecs.encode(b.decode(), "rot13").encode(),
              lambda b: codecs.decode(b.decode(), "rot13").encode(),
              "codecs.decode({x}.decode(), 'rot13').encode()"),
    "xor5a": (lambda b: bytes(x ^ 0x5A for x in b),
              lambda b: bytes(x ^ 0x5A for x in b),
              "bytes(b ^ 0x5A for b in {x})"),
    "xor33": (lambda b: bytes(x ^ 0x33 for x in b),
              lambda b: bytes(x ^ 0x33 for x in b),
              "bytes(b ^ 0x33 for b in {x})"),
    "escapes": (lambda b: "".join("\\x%02x" % x for x in b).encode(),
                lambda b: b.decode().encode("latin-1").decode("unicode_escape").encode("latin-1"),
                "bytes({x}, 'utf-8').decode('unicode_escape').encode('latin-1')"),
}

# --- families ---------------------------------------------------------------
# layers are written outermost first, exactly as the loader expression nests
# them: ("zlib", "b64") -> exec(zlib.decompress(base64.b64decode(_p)))
# tail says how the loader finally turns bytes into code:
#   "exec"     exec(source text)
#   "marshal"  marshal.loads(bytes)
#   "pychead"  marshal.loads(bytes[16:])
#   "zip"      a zip archive holding payload.py
#   "refuse"   bytes that are not a program: inventing source would be a lie
FAMILIES: dict[str, dict] = {
    "a_b64":        {"layers": ("b64",)},
    "b_b64_twice":  {"layers": ("b64", "b64")},
    "c_zlib_b64":   {"layers": ("zlib", "b64")},
    "d_b64_zlib":   {"layers": ("b64", "zlib")},
    "e_lzma_b64":   {"layers": ("lzma", "b64")},
    "f_gzip_b64":   {"layers": ("gzip", "b64")},
    "g_bz2_b64":    {"layers": ("bz2", "b64")},
    "h_b32_b64":    {"layers": ("b64", "base32")},
    "i_b85":        {"layers": ("base85",)},
    "j_a85":        {"layers": ("a85",)},
    "k_b64url":     {"layers": ("b64url",)},
    "l_hex":        {"layers": ("hex",)},
    "m_escaped":    {"layers": ("escapes",)},
    "n_xor_b64":    {"layers": ("xor5a", "b64")},
    "o_reverse_b64": {"layers": ("reverse", "b64")},
    "p_rot13_b64":  {"layers": ("b64", "rot13")},
    "q_mix_three":  {"layers": ("zlib", "xor33", "b64")},
    "r_mix_four":   {"layers": ("b64", "b64", "zlib", "b64")},
    "s_chr_array":  {"layers": (), "tail": "exec", "builder": "chr"},
    "t_zip_member": {"layers": ("b64",), "tail": "zip"},
    "u_marshal_b64": {"layers": ("b64",), "tail": "marshal", "payload": "marshal"},
    "v_pyc_b64":    {"layers": ("b64",), "tail": "pychead", "payload": "pyc"},
    "w_bare_marshal": {"layers": (), "tail": "marshal", "payload": "marshal"},
    "x_marshal_zlib": {"layers": ("zlib", "b64"), "tail": "marshal", "payload": "marshal"},
    "y_pyc_zlib_b64": {"layers": ("zlib", "b64"), "tail": "pychead", "payload": "pyc"},
    "z_refuse":     {"layers": ("b64",), "tail": "refuse"},
}

HEADER = "import base64, codecs, zlib, lzma, gzip, bz2, marshal\n_p = {blob}\n"


def compile_artifacts(source: str) -> dict:
    """The .pyc and bare marshal bytes for a payload.  Nothing is executed."""
    folder = tempfile.mkdtemp(prefix="corpus-")
    try:
        path = os.path.join(folder, "payload.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        target = path + "c"
        py_compile.compile(path, cfile=target, doraise=True)
        with open(target, "rb") as handle:
            pyc = handle.read()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return {"pyc": pyc, "marshal": marshal.dumps(compile(source, "payload.py", "exec"))}


def cook(payload: bytes, layers: tuple[str, ...]) -> tuple[bytes, list[str]]:
    """Wrap the payload so that applying ``layers`` in order undoes the wrapping."""
    blob = payload
    for name in layers:
        blob = OPS[name][0](blob)
    return blob, list(layers)


def loader_for(cooked: bytes, layers: tuple[str, ...], tail: str) -> str:
    expression = "_p"
    for name in reversed(layers):
        expression = OPS[name][2].format(x=expression)
    if tail == "exec":
        body = f"exec({expression})\n"
    elif tail == "marshal":
        body = f"_code = marshal.loads({expression})\n"
    elif tail == "pychead":
        body = f"_code = marshal.loads(({expression})[16:])\n"
    else:
        body = f"_data = {expression}\n"
    return HEADER.format(blob=repr(cooked)) + body


def build_case(folder: str, name: str, payload_name: str, source: str) -> dict:
    spec = FAMILIES[name]
    layers = tuple(spec["layers"])
    tail = spec.get("tail", "exec")
    os.makedirs(folder, exist_ok=True)

    raw = source.encode()
    if spec.get("builder") == "chr":
        numbers = ", ".join(str(item) for item in raw)
        loader = "_p = ''.join(chr(n) for n in [" + numbers + "])\nexec(_p)\n"
        cooked = b""
        truth_layers = ["chr-array"]
    elif tail == "zip":
        buffer = os.path.join(folder, ".payload.zip")
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.py", source)
        with open(buffer, "rb") as handle:
            packed = handle.read()
        os.unlink(buffer)
        cooked, truth_layers = cook(packed, layers)
        loader = loader_for(cooked, layers, "exec")
        truth_layers = truth_layers + ["zip"]
    elif tail == "refuse":
        cooked, truth_layers = cook(b"this is not a program at all\n", layers)
        loader = loader_for(cooked, layers, "exec")
    elif tail in ("marshal", "pychead"):
        artifacts = compile_artifacts(source)
        payload = artifacts["marshal"] if spec.get("payload") == "marshal" else artifacts["pyc"]
        cooked, truth_layers = cook(payload, layers)
        loader = loader_for(cooked, layers, tail)
    else:
        cooked, truth_layers = cook(raw, layers)
        loader = loader_for(cooked, layers, "exec")

    truth = {
        "family": name,
        "payload": payload_name,
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "tail": tail,
        "layers": truth_layers,
        "expect": "refuse" if tail == "refuse" else "recover",
    }
    for label, text in (("sample.py", loader), ("payload.py", source)):
        with open(os.path.join(folder, label), "w", encoding="utf-8") as handle:
            handle.write(text)
    with open(os.path.join(folder, "truth.json"), "w", encoding="utf-8") as handle:
        json.dump(truth, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return truth


def build(verbose: bool = True) -> dict:
    manifest: dict = {"cases": 0, "families": {}}
    if os.path.isdir(CORPUS):
        shutil.rmtree(CORPUS)
    for name in sorted(FAMILIES):
        rows = []
        for payload_name in sorted(PAYLOADS):
            folder = os.path.join(CORPUS, name, payload_name)
            truth = build_case(folder, name, payload_name, PAYLOADS[payload_name])
            rows.append({"payload": payload_name, "expect": truth["expect"],
                         "layers": truth["layers"]})
            manifest["cases"] += 1
        manifest["families"][name] = rows
        if verbose:
            print(f"  {name:<17} {len(rows)} case(s)  {' → '.join(rows[0]['layers']) or 'bare'}")
    with open(os.path.join(CORPUS, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return manifest


def fingerprint() -> str:
    digest = hashlib.sha256()
    for folder, _dirs, files in sorted(os.walk(CORPUS)):
        for name in sorted(files):
            if name in ("manifest.json", "SHA256"):
                continue
            path = os.path.join(folder, name)
            digest.update(os.path.relpath(path, CORPUS).encode("utf-8"))
            with open(path, "rb") as handle:
                digest.update(handle.read())
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="build the evaluation corpus")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the committed corpus is not what this script builds")
    parser.add_argument("--list", action="store_true", help="families and their stacks")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.list:
        for name in sorted(FAMILIES):
            spec = FAMILIES[name]
            stack = " → ".join(spec["layers"]) or spec.get("builder", "bare")
            print(f"{name:<17} tail={spec.get('tail', 'exec'):<8} {stack}")
        return 0

    if args.check:
        recorded = os.path.join(CORPUS, "SHA256")
        if not os.path.isfile(recorded):
            print("corpus/SHA256 is missing: run tools/make_corpus.py")
            return 1
        with open(recorded, encoding="utf-8") as handle:
            want = handle.read().strip()
        manifest = build(verbose=False)
        digest = fingerprint()
        if digest != want:
            print(f"corpus drift: committed {want[:16]}… rebuilt {digest[:16]}…")
            return 1
        print(f"ok corpus {manifest['cases']} case(s) {digest[:16]}…")
        return 0

    manifest = build(verbose=not args.quiet)
    digest = fingerprint()
    with open(os.path.join(CORPUS, "SHA256"), "w", encoding="utf-8") as handle:
        handle.write(digest + "\n")
    print(f"{manifest['cases']} case(s) across {len(manifest['families'])} families  {digest[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
