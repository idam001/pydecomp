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
import importlib.util
import hashlib
import json
import lzma
import marshal
import os
import shutil
import sys
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
    "gzip": (lambda data: gzip.compress(data, mtime=0), gzip.decompress,
             "gzip.decompress({x})"),
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
    "ay_loop_replay": {"layers": ("b64", "lzma", "zlib"), "tail": "loop_replay"},
    "az_str_builder": {"layers": (), "tail": "str_builder"},
    "ba_map_chr": {"layers": (), "tail": "map_chr"},
    "bb_int_bytes": {"layers": (), "tail": "int_bytes"},
    "bc_chunks": {"layers": (), "tail": "chunks"},
    "bd_while_break": {"layers": ("zlib", "b64"), "tail": "while_break"},
    "be_dict_dispatch": {"layers": ("b64",), "tail": "dict_dispatch"},
    "bf_zip_xor": {"layers": (), "tail": "zip_xor"},
    "bg_hex_xor": {"layers": (), "tail": "hex_xor"},
    "bh_dict_join": {"layers": ("b64",), "tail": "dict_join"},
    "bi_zip_join": {"layers": ("b64",), "tail": "zip_join"},
    "bj_nested_comp": {"layers": ("b64",), "tail": "nested_comp"},
    "bk_sorted_values": {"layers": ("b64",), "tail": "sorted_values"},
    "bl_reduce_join": {"layers": ("b64",), "tail": "reduce_join"},
    "bm_chr_join": {"layers": ("b64",), "tail": "chr_join"},
    "bn_accumulate": {"layers": (), "tail": "accumulate"},
    "bo_backend_xor": {"layers": (), "tail": "backend_xor"},
    "bp_backend_rc4": {"layers": (), "tail": "backend_rc4"},
    "bq_backend_bare_blob": {"layers": (), "tail": "backend_bare"},
    "br_backend_bits": {"layers": (), "tail": "backend_bits"},
    "bs_backend_columns": {"layers": (), "tail": "backend_columns"},
    "bt_backend_numbers": {"layers": (), "tail": "backend_numbers"},


}

HEADER = "import base64, codecs, zlib, lzma, gzip, bz2, marshal\n_p = {blob}\n"


def compile_artifacts(source: str) -> dict:
    """The .pyc and bare marshal bytes for a payload.  Nothing is executed.

    The header is written here rather than by py_compile so the bytes do not
    depend on the moment the corpus is built: flags 0, source mtime 0, size 0.
    """
    code = marshal.dumps(compile(source, "payload.py", "exec"))
    header = importlib.util.MAGIC_NUMBER + b"\x00" * 12
    return {"pyc": header + code, "marshal": code}


def _rc4(data: bytes, key: bytes) -> bytes:
    """RC4, written out: the corpus must not borrow the tool's own implementation."""
    box = list(range(256))
    index = 0
    for position in range(256):
        index = (index + box[position] + key[position % len(key)]) & 0xFF
        box[position], box[index] = box[index], box[position]
    out = bytearray()
    first = second = 0
    for byte in data:
        first = (first + 1) & 0xFF
        second = (second + box[first]) & 0xFF
        box[first], box[second] = box[second], box[first]
        out.append(byte ^ box[(box[first] + box[second]) & 0xFF])
    return bytes(out)


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
    """The nested decoder expression a loader writes, ending in ``tail``.

    Only the four plain endings live here.  Every shaped loader (a loop, a jump
    table, a string builder, an alphabet) is written by ``build_case`` next to
    the bytes it needs, so there is one implementation of each, not two.
    """
    expression = "_p"
    for name in reversed(layers):
        expression = OPS[name][2].format(x=expression)
    body = {
        "exec": f"exec({expression})\n",
        # eval(compile(...)) hands the payload to a compiler, not to exec
        "eval": f"_code = compile({expression}, '<payload>', 'exec')\n",
        "marshal": f"_code = marshal.loads({expression})\n",
        "pychead": f"_code = marshal.loads(({expression})[16:])\n",
    }.get(tail, f"_data = {expression}\n")
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
    elif tail == "loop_replay":
        cooked, truth_layers = cook(raw, layers)
        undo = "_d"
        for layer in reversed(layers):
            undo = {"b64": "base64.b64decode({x})", "zlib": "zlib.decompress({x})",
                    "lzma": "lzma.decompress({x})", "gzip": "gzip.decompress({x})",
                    "bz2": "bz2.decompress({x})"}[layer].format(x=undo)
        loader = (HEADER.format(blob=repr(cooked))
                  + "_d = _p\n"
                    "for _ in range(1):\n"
                    f"    _d = {undo}\n"
                    "exec(_d.decode())\n")
        truth_layers = list(truth_layers)
    elif tail == "str_builder":
        cooked = raw
        loader = ("_n = %r\n"
                  "_s = ''\n"
                  "for _c in _n:\n"
                  "    _s += chr(_c)\n"
                  "exec(_s)\n" % list(raw))
        truth_layers = ["str-builder"]
    elif tail == "map_chr":
        cooked = raw
        loader = ("_n = %r\n"
                  "exec(''.join(map(chr, _n)))\n" % list(raw))
        truth_layers = ["map-chr"]
    elif tail == "int_bytes":
        number = int.from_bytes(raw, "big")
        cooked = raw
        loader = ("_n = %d\n"
                  "_b = _n.to_bytes((_n.bit_length() + 7) // 8, 'big')\n"
                  "exec(_b.decode())\n" % number)
        truth_layers = ["big-int"]
    elif tail == "chunks":
        pieces = [raw[index:index + 17] for index in range(0, len(raw), 17)]
        cooked = raw
        loader = ("_c = %r\n"
                  "exec(''.join(_c))\n" % [piece.decode("utf-8", "surrogateescape")
                                           for piece in pieces])
        truth_layers = ["chunk-join"]
    elif tail == "while_break":
        cooked, truth_layers = cook(raw, layers)
        loader = (HEADER.format(blob=repr(cooked))
                  + "_d = None\n"
                    "while True:\n"
                    "    _d = zlib.decompress(base64.b64decode(_p))\n"
                    "    break\n"
                    "exec(_d.decode())\n")
        truth_layers = list(truth_layers)
    elif tail == "dict_dispatch":
        cooked, truth_layers = cook(raw, layers)
        loader = (HEADER.format(blob=repr(cooked))
                  + "_T = {0: lambda: base64.b64decode(_p)}\n"
                    "_S = 0\n"
                    "_v = None\n"
                    "while _S in _T:\n"
                    "    _v = _T[_S]()\n"
                    "    _S += 1\n"
                    "exec(_v.decode())\n")
        truth_layers = list(truth_layers)
    elif tail == "zip_xor":
        key = b"\x1d\x5b\x93"
        mixed = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw))
        cooked = raw
        loader = ("_k = %r\n"
                  "_m = %r\n"
                  "exec(bytes(a ^ b for a, b in zip(_m, _k * (len(_m) // len(_k) + 1)))"
                  ".decode())\n" % (list(key), list(mixed)))
        truth_layers = ["zip-xor"]
    elif tail == "hex_xor":
        cooked = raw
        loader = ("_h = %r\n"
                  "exec(bytes(b ^ 0x37 for b in bytes.fromhex(_h)).decode())\n"
                  % bytes(byte ^ 0x37 for byte in raw).hex())
        truth_layers = ["hex-xor"]
    elif tail == "dict_join":
        cooked, truth_layers = cook(raw, layers)
        pieces = [(index, cooked[index:index + 12])
                  for index in range(0, len(cooked), 12)]
        loader = ("import base64\n"
                  + "_D = {%s}\n" % ", ".join("%d: %r" % piece for piece in pieces)
                  + "exec(base64.b64decode(b''.join(_D[_k] for _k in sorted(_D)))"
                    ".decode())\n")
        truth_layers = list(truth_layers) + ["dict-join"]
    elif tail == "zip_join":
        cooked, truth_layers = cook(raw, layers)
        loader = ("import base64\n"
                  "_x = %r\n_y = %r\n"
                  "_p = b''.join(bytes([a, b]) for a, b in zip(_x, _y + b'\\x00'))\n"
                  "exec(base64.b64decode(_p.rstrip(b'\\x00')).decode())\n"
                  % (cooked[::2], cooked[1::2]))
        truth_layers = list(truth_layers) + ["zip-join"]
    elif tail == "nested_comp":
        cooked, truth_layers = cook(raw, layers)
        groups = [[cooked[index:index + 10]] for index in range(0, len(cooked), 10)]
        loader = ("import base64\n"
                  "_L = %r\n"
                  "_p = b''.join(part for group in _L for part in group)\n"
                  "exec(base64.b64decode(_p).decode())\n" % (groups,))
        truth_layers = list(truth_layers) + ["nested-comprehension"]
    elif tail == "sorted_values":
        cooked, truth_layers = cook(raw, layers)
        pieces = [(index, cooked[index:index + 8])
                  for index in range(0, len(cooked), 8)]
        loader = ("import base64\n"
                  + "_D = {%s}\n" % ", ".join("%d: %r" % piece
                                             for piece in reversed(pieces))
                  + "_p = b''.join(_D[_k] for _k in sorted(_D.keys()))\n"
                    "exec(base64.b64decode(_p).decode())\n")
        truth_layers = list(truth_layers) + ["sorted-values"]
    elif tail == "reduce_join":
        cooked, truth_layers = cook(raw, layers)
        chunks = [cooked[index:index + 20] for index in range(0, len(cooked), 20)]
        loader = ("import base64\nfrom functools import reduce\n"
                  "_C = %r\n"
                  "_p = reduce(lambda a, b: a + b, _C)\n"
                  "exec(base64.b64decode(_p).decode())\n" % (chunks,))
        truth_layers = list(truth_layers) + ["reduce-join"]
    elif tail == "chr_join":
        cooked, truth_layers = cook(raw, layers)
        numbers = ", ".join(str(byte) for byte in cooked)
        loader = ("import base64\n"
                  "_s = ''.join(chr(n) for n in [%s])\n"
                  "exec(base64.b64decode(_s).decode())\n" % numbers)
        truth_layers = list(truth_layers) + ["chr-join"]
    elif tail == "accumulate":
        key = 0x5A
        numbers = ", ".join(str(byte ^ key) for byte in raw)
        loader = ("_n = [%s]\n"
                  "_b = bytearray()\n"
                  "for _c in _n:\n"
                  "    _b.append(_c ^ 0x%X)\n"
                  "exec(bytes(_b).decode())\n" % (numbers, key))
        cooked = raw
        truth_layers = ["accumulate", "xor(key=0x5a)"]
    elif tail == "backend_xor":
        # the key is read from the environment when the loader runs, so no
        # expression can be folded: only the bytes can be read
        baked = os.environ.get("PYDECOMP_SEED", "A")
        key = ord(baked[0]) ^ 0x5C
        mixed = bytes(byte ^ key
                      for byte in base64.b64encode(zlib.compress(raw)))
        loader = ("import base64, os, zlib\n"
                  "_seed = os.environ.get('PYDECOMP_SEED', 'A')\n"
                  "_key = ord(_seed[0]) ^ 0x5C\n"
                  "_p = %r\n"
                  "exec(zlib.decompress(base64.b64decode("
                  "bytes(b ^ _key for b in _p))))\n" % mixed)
        cooked = raw
        truth_layers = ["xor(key from env)", "base64", "zlib"]
    elif tail == "backend_rc4":
        key = b"K3y!8z"
        body = _rc4(base64.b64encode(zlib.compress(raw)), key)
        loader = ("import base64, zlib\n"
                  "def _ksa(key):\n"
                  "    box = list(range(256))\n"
                  "    index = 0\n"
                  "    for position in range(256):\n"
                  "        index = (index + box[position] + key[position %% len(key)]) & 0xFF\n"
                  "        box[position], box[index] = box[index], box[position]\n"
                  "    return box\n"
                  "def _rc4(data, key):\n"
                  "    box = _ksa(key)\n"
                  "    out = bytearray()\n"
                  "    first = second = 0\n"
                  "    for byte in data:\n"
                  "        first = (first + 1) & 0xFF\n"
                  "        second = (second + box[first]) & 0xFF\n"
                  "        box[first], box[second] = box[second], box[first]\n"
                  "        out.append(byte ^ box[(box[first] + box[second]) & 0xFF])\n"
                  "    return bytes(out)\n"
                  "_p = %r\n"
                  "exec(zlib.decompress(base64.b64decode(_rc4(_p[6:], _p[:6]))))\n"
                  % (key + body))
        cooked = raw
        truth_layers = ["rc4(key in front)", "base64", "zlib"]
    elif tail == "backend_bare":
        # no loader at all: a data file.  Nothing in it is an expression to
        # fold, which is exactly when the backend tree earns its keep
        payload_body = base64.b64encode(zlib.compress(raw))
        loader = ("# collected by the dropper, never executed here\n"
                  "_blob = %r\n"
                  "raise SystemExit(0)\n" % payload_body)
        cooked = raw
        truth_layers = ["base64", "zlib"]
    elif tail == "backend_bits":
        inner = base64.b64encode(zlib.compress(raw))
        bits = "".join(format(byte, "08b") for byte in inner)
        loader = ("import os\n"
                  "_width = int(os.environ.get('PYDECOMP_WIDTH', '8'))\n"
                  "_s = %r\n"
                  "_b = bytes(int(_s[i:i + _width], 2) for i in range(0, len(_s), _width))\n"
                  "exec(__import__('zlib').decompress(__import__('base64')"
                  ".b64decode(_b)))\n" % bits)
        cooked = raw
        truth_layers = ["bits", "base64", "zlib"]
    elif tail == "backend_columns":
        inner = base64.b64encode(zlib.compress(raw))
        columns = int(os.environ.get("PYDECOMP_COLUMNS", "7"))
        rows = [inner[index:index + columns] for index in range(0, len(inner), columns)]
        transposed = bytearray()
        for column in range(columns):
            for row in rows:
                if column < len(row):
                    transposed.append(row[column])
        loader = ("import os\n"
                  "_columns = int(os.environ.get('PYDECOMP_COLUMNS', '7'))\n"
                  "_s = %r\n"
                  "_rows = -(-len(_s) // _columns)\n"
                  "_short = _rows * _columns - len(_s)\n"
                  "_out = bytearray(len(_s))\n"
                  "_at = 0\n"
                  "for _c in range(_columns):\n"
                  "    _length = _rows - (1 if _c >= _columns - _short else 0)\n"
                  "    for _r in range(_length):\n"
                  "        _out[_r * _columns + _c] = _s[_at]\n"
                  "        _at += 1\n"
                  "exec(__import__('zlib').decompress(__import__('base64')"
                  ".b64decode(bytes(_out))))\n" % bytes(transposed))
        cooked = raw
        truth_layers = ["columnar", "base64", "zlib"]
    elif tail == "backend_numbers":
        inner = base64.b64encode(zlib.compress(raw))
        numbers = ", ".join(str(byte) for byte in inner)
        loader = ("import os\n"
                  "_sep = os.environ.get('PYDECOMP_SEP', ',')\n"
                  "_s = %r\n"
                  "_b = bytes(int(_x) for _x in _s.split(_sep) if _x.strip())\n"
                  "exec(__import__('zlib').decompress(__import__('base64')"
                  ".b64decode(_b)))\n" % numbers)
        cooked = raw
        truth_layers = ["decimal", "base64", "zlib"]
    elif tail == "zip2":
        inner = os.path.join(folder, ".inner.zip")
        info = zipfile.ZipInfo("payload.py", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr(info, source)
        with open(inner, "rb") as handle:
            packed = handle.read()
        os.unlink(inner)
        outer = os.path.join(folder, ".outer.zip")
        info = zipfile.ZipInfo("inner.zip", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr(info, packed)
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
        info = zipfile.ZipInfo("payload.py", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(info, source)
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
