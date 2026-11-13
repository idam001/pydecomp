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


# --- codecs with their own alphabets ---------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
Z85 = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
       ".-:+=^!/*?&<>()[]{}@%$#")


def _base_n_encode(data: bytes, alphabet: str) -> bytes:
    number = int.from_bytes(data, "big")
    out = []
    while number:
        number, rest = divmod(number, len(alphabet))
        out.append(alphabet[rest])
    return ("".join(reversed(out)) or alphabet[0]).encode()


def _base_n_decode(data: bytes, alphabet: str) -> bytes:
    number = 0
    for symbol in data.decode().strip():
        number = number * len(alphabet) + alphabet.index(symbol)
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def _b58(data: bytes) -> bytes:
    return _base_n_encode(data, B58)


def _b62(data: bytes) -> bytes:
    return _base_n_encode(data, B62)


def _b45(data: bytes) -> bytes:
    out = []
    for index in range(0, len(data) - 1, 2):
        value = data[index] * 256 + data[index + 1]
        out.append(B45[value % 45])
        out.append(B45[(value // 45) % 45])
        out.append(B45[value // 2025])
    if len(data) % 2:
        value = data[-1]
        out.append(B45[value % 45])
        out.append(B45[value // 45])
    return "".join(out).encode()


def _uu(data: bytes) -> bytes:
    """uuencode in 45-byte blocks, the way uuencode always did it."""
    out = []
    for index in range(0, len(data), 45):
        out.append(__import__("binascii").b2a_uu(data[index:index + 45],
                                                 backtick=False).strip())
    return b"\n".join(out)


def _z85(data: bytes) -> bytes:
    # Z85 works in 4-byte groups; the payload is padded and the loader slices the
    # padding off again, which is what real z85 loaders do
    while len(data) % 4:
        data += b"\x00"
    out = []
    for index in range(0, len(data), 4):
        value = int.from_bytes(data[index:index + 4], "big")
        chunk = []
        for _ in range(5):
            value, rest = divmod(value, 85)
            chunk.append(Z85[rest])
        out.extend(reversed(chunk))
    return "".join(out).encode()


OPS["base58"] = (_b58, lambda b: _base_n_decode(b, B58), "B58_({x})")
OPS["base62"] = (_b62, lambda b: _base_n_decode(b, B62), "B62_({x})")
OPS["base45"] = (_b45, None, "B45_({x})")
OPS["z85"] = (_z85, None, "Z85_({x})")
OPS["uu"] = (_uu, None, "UU_({x})")

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
    "z_refuse":     {"layers": ("b64",), "tail": "refuse"},    "aa_base58":    {"layers": ("base58",), "tail": "alphabet", "alphabet": "B58"},
    "ab_base62":    {"layers": ("base62",), "tail": "alphabet", "alphabet": "B62"},
    "ac_base45":    {"layers": ("base45",), "tail": "alphabet", "alphabet": "B45"},
    "ad_z85":       {"layers": ("z85",), "tail": "alphabet", "alphabet": "Z85"},
    "ae_uu":        {"layers": ("uu",), "tail": "alphabet", "alphabet": "UU"},
    "af_hex_upper": {"layers": ("hex",)},
    "ag_double_zip": {"layers": ("b64",), "tail": "zip2"},
    "ah_eval_chain": {"layers": ("b64",), "tail": "eval"},
    "ai_stacked_mixed": {"layers": ("b64", "zlib", "b64", "xor5a")},
    "aj_string_table": {"layers": (), "tail": "table"},    # --- research-driven families: the shapes real samples actually use -----
    "ak_inline_import": {"layers": ("zlib", "b64"), "tail": "inline_import"},
    "al_lambda_indirect": {"layers": ("b64",), "tail": "lambda"},
    "am_lambda_reverse": {"layers": ("b64",), "tail": "lambda_reverse"},
    "an_nested_exec": {"layers": (), "tail": "nested"},
    "ao_zero_width": {"layers": (), "tail": "zero_width"},
    "ap_exec_compile": {"layers": ("b64",), "tail": "exec_compile"},
    "aq_b85_zlib_marshal": {"layers": ("zlib", "base85"), "tail": "marshal_payload",
                            "payload": "marshal"},
    "ar_deep_twelve": {"layers": ("b64", "zlib") * 6, "tail": "exec"},
    "as_string_array": {"layers": (), "tail": "array"},
    "au_builtins_alias": {"layers": ("zlib", "b64"), "sink": "builtins_alias"},
    "av_sys_modules": {"layers": ("bz2", "b64"), "sink": "sys_modules"},
    "aw_getattribute": {"layers": ("b64",), "sink": "getattribute"},
    "ax_split_sink": {"layers": ("zlib",), "sink": "split"},
    "at_chr_arith": {"layers": (), "tail": "chr_arith"},


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


#: spellings of `exec` that a loader uses so that a plain text scan misses it.
#: Each is the same call; only the route to the builtin changes.
SINK_SPELLINGS = {
    "builtins_alias": ("import builtins\n_b = builtins\n", "_b.exec"),
    "sys_modules": ("import sys\n", "sys.modules['builtins'].exec"),
    "getattribute": ("", "__import__('builtins').__getattribute__('ex' + 'ec')"),
    "split": ("", "getattr(__import__('built' + 'ins'), 'ex' + 'ec')"),
}


def _hide_sink(loader: str, sink: str) -> str:
    """Rewrite the trailing ``exec(...)`` into a spelling that hides it."""
    header, spelling = SINK_SPELLINGS[sink]
    lines = loader.rstrip("\n").splitlines()
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index].strip()
        if line.startswith("exec(") and line.endswith(")"):
            lines[index] = f"{spelling}{line[4:]}"
            break
    else:
        return loader
    return header + "\n".join(lines) + "\n"


def loader_for(cooked: bytes, layers: tuple[str, ...], tail: str) -> str:
    expression = "_p"
    for name in reversed(layers):
        expression = OPS[name][2].format(x=expression)
    if tail == "exec":
        body = f"exec({expression})\n"
    elif tail == "eval":
        # eval(compile(...)): the payload is handed to a compiler, not to exec
        body = f"_code = compile({expression}, '<payload>', 'exec')\n"
    elif tail == "table":
        body = ("_data = base64.b64decode(_p)\n"
                "_text = bytes(b ^ 0x2B for b in _data).decode('utf-8')\n"
                "exec(_text)\n")
    elif tail == "inline_import":
        cooked, truth_layers = cook(raw, layers)
        loader = ("_p = %r\n"
                  "exec(__import__('zlib').decompress("
                  "__import__('base64').b64decode(_p)))\n" % cooked)
    elif tail == "lambda":
        cooked, truth_layers = cook(raw, layers)
        loader = ("import base64\n"
                  "_p = %r\n"
                  "_ = lambda __: base64.b64decode(__)\n"
                  "exec((_)(_p))\n" % cooked)
    elif tail == "lambda_reverse":
        cooked = OPS["b64"][0](raw)[::-1]
        truth_layers = ["reverse", "base64"]
        loader = ("import base64\n"
                  "_p = %r\n"
                  "_ = lambda __: base64.b64decode(__[::-1])\n"
                  "exec((_)(_p))\n" % cooked)
    elif tail == "nested":
        # TrustedSec's bytecode stack: marshal inside marshal inside zlib, each
        # level a loader that loads the next
        level = marshal.dumps(compile(source, "payload.py", "exec"))
        for _ in range(3):
            wrapper = b"from marshal import loads\nexec(loads(%r))" % level
            level = marshal.dumps(compile(wrapper, "level", "exec"))
        cooked = zlib.compress(level)
        truth_layers = ["zlib", "marshal", "marshal", "marshal"]
        loader = ("import zlib\nfrom marshal import loads\n"
                  "exec(loads(zlib.decompress(%r)))\n" % cooked)
    elif tail == "zero_width":
        bits = "".join(
            "".join("\u200b" if bit == "0" else "\u200c" for bit in format(byte, "08b"))
            for byte in raw)
        cooked = bits.encode("utf-8")
        truth_layers = ["zero-width"]
        loader = ("_s = %r\n"
                  "_b = ''.join('0' if c == '\\u200b' else '1' for c in _s)\n"
                  "exec(bytes(int(_b[i:i + 8], 2) for i in range(0, len(_b), 8))"
                  ".decode())\n" % bits)
    elif tail == "exec_compile":
        cooked, truth_layers = cook(raw, layers)
        loader = ("import base64\n"
                  "_p = %r\n"
                  "exec(compile(base64.b64decode(_p), '<payload>', 'exec'))\n" % cooked)
    elif tail == "marshal_payload":
        artifacts = compile_artifacts(source)
        cooked, truth_layers = cook(artifacts["marshal"], layers)
        loader = ("import base64, zlib, marshal\n"
                  "_p = %r\n"
                  "exec(marshal.loads(zlib.decompress(base64.b85decode(_p))))\n" % cooked)
    elif tail == "array":
        pieces = [raw[index:index + 24] for index in range(0, len(raw), 24)]
        baked = ", ".join(repr(piece) for piece in pieces)
        cooked = raw
        truth_layers = ["string-array"]
        loader = ("_t = [%s]\n"
                  "exec(b''.join(_t).decode())\n" % baked)
    elif tail == "chr_arith":
        numbers = ", ".join(str(byte ^ 0x21) for byte in raw)
        cooked = raw
        truth_layers = ["chr-xor"]
        loader = ("_n = [%s]\n"
                  "exec(bytes([c ^ 0x21 for c in _n]).decode())\n" % numbers)
    elif tail == "alphabet":
        codec = spec["alphabet"]
        cooked, truth_layers = cook(raw, layers)
        if codec == "UU":
            loader = (HEADER.format(blob=repr(cooked))
                      + "import binascii\n"
                        "exec(binascii.a2b_uu(_p).decode())\n")
        else:
            alphabet = {"B58": B58, "B62": B62, "B45": B45, "Z85": Z85}[codec]
            if codec == "Z85":
                loader = (HEADER.format(blob=repr(cooked))
                          + f"_A = {alphabet!r}\n"
                            "_o = bytearray()\n"
                            "for _i in range(0, len(_p), 5):\n"
                            "    _v = 0\n"
                            "    for _c in _p[_i:_i + 5]:\n"
                            "        _v = _v * 85 + _A.index(chr(_c))\n"
                            "    _o.extend(_v.to_bytes(4, 'big'))\n"
                            "exec(bytes(_o).rstrip(b'\\x00').decode())\n")
                truth_layers = list(truth_layers)
                with open(os.path.join(folder, "sample.py"), "w", encoding="utf-8") as handle:
                    handle.write(loader)
                with open(os.path.join(folder, "payload.py"), "w", encoding="utf-8") as handle:
                    handle.write(source)
                truth = {"family": name, "payload": payload_name,
                         "payload_sha256": hashlib.sha256(raw).hexdigest(),
                         "tail": tail, "layers": truth_layers, "expect": "recover"}
                with open(os.path.join(folder, "truth.json"), "w", encoding="utf-8") as handle:
                    json.dump(truth, handle, indent=1, sort_keys=True)
                    handle.write("\n")
                return truth
            loader = (HEADER.format(blob=repr(cooked))
                      + f"_A = {alphabet!r}\n"
                        "_n = 0\n"
                        "for _c in _p.decode():\n"
                        "    _n = _n * len(_A) + _A.index(_c)\n"
                        "exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big')"
                        ".decode())\n")
        truth_layers = list(truth_layers)
    elif tail == "zip2":
        body = f"_inner = {expression}\n"
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
    elif tail == "inline_import":
        cooked, truth_layers = cook(raw, layers)
        loader = ("_p = %r\n"
                  "exec(__import__('zlib').decompress("
                  "__import__('base64').b64decode(_p)))\n" % cooked)
    elif tail == "lambda":
        cooked, truth_layers = cook(raw, layers)
        loader = ("import base64\n"
                  "_p = %r\n"
                  "_ = lambda __: base64.b64decode(__)\n"
                  "exec((_)(_p))\n" % cooked)
    elif tail == "lambda_reverse":
        cooked = OPS["b64"][0](raw)[::-1]
        truth_layers = ["reverse", "base64"]
        loader = ("import base64\n"
                  "_p = %r\n"
                  "_ = lambda __: base64.b64decode(__[::-1])\n"
                  "exec((_)(_p))\n" % cooked)
    elif tail == "nested":
        # TrustedSec's bytecode stack: marshal inside marshal inside zlib, each
        # level a loader that loads the next
        level = marshal.dumps(compile(source, "payload.py", "exec"))
        for _ in range(3):
            wrapper = b"from marshal import loads\nexec(loads(%r))" % level
            level = marshal.dumps(compile(wrapper, "level", "exec"))
        cooked = zlib.compress(level)
        truth_layers = ["zlib", "marshal", "marshal", "marshal"]
        loader = ("import zlib\nfrom marshal import loads\n"
                  "exec(loads(zlib.decompress(%r)))\n" % cooked)
    elif tail == "zero_width":
        bits = "".join(
            "".join("\u200b" if bit == "0" else "\u200c" for bit in format(byte, "08b"))
            for byte in raw)
        cooked = bits.encode("utf-8")
        truth_layers = ["zero-width"]
        loader = ("_s = %r\n"
                  "_b = ''.join('0' if c == '\\u200b' else '1' for c in _s)\n"
                  "exec(bytes(int(_b[i:i + 8], 2) for i in range(0, len(_b), 8))"
                  ".decode())\n" % bits)
    elif tail == "exec_compile":
        cooked, truth_layers = cook(raw, layers)
        loader = ("import base64\n"
                  "_p = %r\n"
                  "exec(compile(base64.b64decode(_p), '<payload>', 'exec'))\n" % cooked)
    elif tail == "marshal_payload":
        artifacts = compile_artifacts(source)
        cooked, truth_layers = cook(artifacts["marshal"], layers)
        loader = ("import base64, zlib, marshal\n"
                  "_p = %r\n"
                  "exec(marshal.loads(zlib.decompress(base64.b85decode(_p))))\n" % cooked)
    elif tail == "array":
        pieces = [raw[index:index + 24] for index in range(0, len(raw), 24)]
        baked = ", ".join(repr(piece) for piece in pieces)
        cooked = raw
        truth_layers = ["string-array"]
        loader = ("_t = [%s]\n"
                  "exec(b''.join(_t).decode())\n" % baked)
    elif tail == "chr_arith":
        numbers = ", ".join(str(byte ^ 0x21) for byte in raw)
        cooked = raw
        truth_layers = ["chr-xor"]
        loader = ("_n = [%s]\n"
                  "exec(bytes([c ^ 0x21 for c in _n]).decode())\n" % numbers)
    elif tail == "alphabet":
        codec = spec["alphabet"]
        cooked, truth_layers = cook(raw, layers)
        if codec == "UU":
            loader = (HEADER.format(blob=repr(cooked))
                      + "import binascii\n"
                        "exec(binascii.a2b_uu(_p).decode())\n")
        else:
            alphabet = {"B58": B58, "B62": B62, "B45": B45, "Z85": Z85}[codec]
            if codec == "Z85":
                loader = (HEADER.format(blob=repr(cooked))
                          + f"_A = {alphabet!r}\n"
                            "_o = bytearray()\n"
                            "for _i in range(0, len(_p), 5):\n"
                            "    _v = 0\n"
                            "    for _c in _p[_i:_i + 5]:\n"
                            "        _v = _v * 85 + _A.index(chr(_c))\n"
                            "    _o.extend(_v.to_bytes(4, 'big'))\n"
                            "exec(bytes(_o).rstrip(b'\\x00').decode())\n")
                truth_layers = list(truth_layers)
                with open(os.path.join(folder, "sample.py"), "w", encoding="utf-8") as handle:
                    handle.write(loader)
                with open(os.path.join(folder, "payload.py"), "w", encoding="utf-8") as handle:
                    handle.write(source)
                truth = {"family": name, "payload": payload_name,
                         "payload_sha256": hashlib.sha256(raw).hexdigest(),
                         "tail": tail, "layers": truth_layers, "expect": "recover"}
                with open(os.path.join(folder, "truth.json"), "w", encoding="utf-8") as handle:
                    json.dump(truth, handle, indent=1, sort_keys=True)
                    handle.write("\n")
                return truth
            loader = (HEADER.format(blob=repr(cooked))
                      + f"_A = {alphabet!r}\n"
                        "_n = 0\n"
                        "for _c in _p.decode():\n"
                        "    _n = _n * len(_A) + _A.index(_c)\n"
                        "exec(_n.to_bytes((_n.bit_length() + 7) // 8, 'big')"
                        ".decode())\n")
        truth_layers = list(truth_layers)
    elif tail == "zip2":
        inner = os.path.join(folder, ".inner.zip")
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.py", source)
        with open(inner, "rb") as handle:
            packed = handle.read()
        os.unlink(inner)
        outer = os.path.join(folder, ".outer.zip")
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("inner.zip", packed)
        with open(outer, "rb") as handle:
            packed = handle.read()
        os.unlink(outer)
        cooked, truth_layers = cook(packed, layers)
        loader = loader_for(cooked, layers, "exec")
        truth_layers = truth_layers + ["zip", "zip"]
    elif tail == "table":
        # the payload is encrypted, and the key is written in the loader
        cooked = base64.b64encode(bytes(b ^ 0x2B for b in raw))
        truth_layers = ["base64", "xor(key=0x2b)"]
        loader = (HEADER.format(blob=repr(cooked))
                  + "_data = base64.b64decode(_p)\n"
                    "_text = bytes(b ^ 0x2B for b in _data).decode('utf-8')\n"
                    "exec(_text)\n")
    elif tail == "eval":
        cooked, truth_layers = cook(raw, layers)
        loader = loader_for(cooked, layers, "eval")
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

    sink = spec.get("sink")
    if sink:
        loader = _hide_sink(loader, sink)

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
