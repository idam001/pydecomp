"""Build a benchmark of the hardest Python-obfuscation classes and score pydecomp.

Each case is written to ``tests/obf_cases/`` together with the ground truth, so
the report can say exactly what was recovered and what was lost.  Nothing here
is executed beyond ``py_compile`` / ``marshal`` bookkeeping.
"""
import base64
import bz2
import json
import lzma
import marshal
import os
import py_compile
import random
import shutil
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "obf_cases")

SECRET = "ghp_9f2Ak4LmQ7pR1sT8uV3wX6yZ0bN5cD"
ENDPOINT = "https://api.internal.example/v2/keys"
MARKER = "RECOVER_ME_7731"


# --------------------------------------------------------------------- sources
PLAIN = f'''
import hashlib

SECRET_TOKEN = "{SECRET}"
ENDPOINT = "{ENDPOINT}"


def sign(payload, key=SECRET_TOKEN):
    body = str(payload) + key
    return hashlib.sha256(body.encode()).hexdigest()


def verify(payload, digest):
    return sign(payload) == digest


def report(items):
    out = []
    for item in items:
        if item > 3:
            out.append(item * 2)
        else:
            out.append(0)
    return out
'''


def xor_strings_source():
    key = 0x5A

    def enc(text):
        return [ord(c) ^ key for c in text]

    secret = enc(SECRET)
    endpoint = enc(ENDPOINT)
    marker = enc(MARKER)
    return f'''
_KEY = {key}

def _d(data):
    return "".join(chr(b ^ _KEY) for b in data)

SECRET_TOKEN = _d({secret})
ENDPOINT = _d({endpoint})


def tag():
    return _d({marker})


def sign(payload, key=SECRET_TOKEN):
    import hashlib
    return hashlib.sha256((str(payload) + key).encode()).hexdigest()
'''


def chr_array_source():
    def arr(text):
        return ", ".join(str(ord(c)) for c in text)

    return f'''
import hashlib

SECRET_TOKEN = "".join([chr(n) for n in [{arr(SECRET)}]])
ENDPOINT = "".join([chr(n) for n in [{arr(ENDPOINT)}]])


def tag():
    return "".join([chr(n) for n in [{arr(MARKER)}]])


def sign(payload):
    return hashlib.sha256((str(payload) + SECRET_TOKEN).encode()).hexdigest()
'''


def b64_layers_source():
    def wrap(text):
        return base64.b64encode(zlib.compress(text.encode())).decode()

    return f'''
import base64
import zlib

SECRET_TOKEN = zlib.decompress(base64.b64decode("{wrap(SECRET)}")).decode()
ENDPOINT = zlib.decompress(base64.b64decode("{wrap(ENDPOINT)}")).decode()


def tag():
    return zlib.decompress(base64.b64decode("{wrap(MARKER)}")).decode()


def sign(payload):
    import hashlib
    return hashlib.sha256((str(payload) + SECRET_TOKEN).encode()).hexdigest()
'''


FLATTENED = f'''
import hashlib

SECRET_TOKEN = _s0()


def _s0():
    return "{SECRET}"


def sign(payload):
    state = 0
    digest = None
    body = None
    while True:
        if state == 0:
            body = str(payload) + SECRET_TOKEN
            state = 1
        elif state == 1:
            digest = hashlib.sha256(body.encode()).hexdigest()
            state = 2
        elif state == 2:
            return digest
'''


def opaque_source():
    return f'''
import hashlib

SECRET_TOKEN = "{SECRET}"


def tag():
    junk = 0
    if (3 * 3 == 9) and (1 + 1 == 2):
        junk = junk + 1
    else:
        junk = junk - 999
    if (0.5 * 4 == 2.0) or False:
        return "{MARKER}"
    return "wrong-" + str(junk)


def sign(payload):
    dead = []
    for i in range(0):
        dead.append(i * 2)
    if (7 ^ 7) == 0:
        return hashlib.sha256((str(payload) + SECRET_TOKEN).encode()).hexdigest()
    return "unreachable"
'''


def mixed_boolean_source():
    """MBA-style arithmetic: a+b written as (a^b)+2*(a&b), counts as noise."""
    return f'''
SECRET_TOKEN = "{SECRET}"


def _mba(a, b):
    return (a ^ b) + 2 * (a & b)


def add(a, b):
    return _mba(a, b)


def tag():
    return "{MARKER}"
'''


# --------------------------------------------------------------------- builders
def write_case(name, filename, blob: bytes, truth: dict):
    folder = os.path.join(OUT, name)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, filename), "wb") as handle:
        handle.write(blob)
    with open(os.path.join(folder, "truth.json"), "w") as handle:
        json.dump(truth, handle, indent=2)
    return folder


def as_pyc(source: str, filename="sample.py") -> bytes:
    folder = os.path.join(OUT, "_tmp")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "w") as handle:
        handle.write(source)
    # UNCHECKED_HASH keeps the fixture byte-identical between runs: the
    # default (mtime) header would change on every rebuild.  ``dfile`` keeps the
    # code object's filename stable too, so the fixture does not depend on where
    # the checkout lives (a fresh clone used to regenerate different bytes).
    pyc = py_compile.compile(path, cfile=path + "c", dfile="sample.py", doraise=True,
                             invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    with open(pyc, "rb") as handle:
        blob = handle.read()
    return blob


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def build():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    truth = {"secret": SECRET, "endpoint": ENDPOINT, "marker": MARKER}
    made = []

    # 1 - plain .pyc, no obfuscation at all
    write_case("01_plain_pyc", "sample.pyc", as_pyc(PLAIN), truth)
    made.append("01_plain_pyc")

    # 2 - XOR string table with a runtime decoder
    write_case("02_xor_strings", "sample.pyc", as_pyc(xor_strings_source()), truth)
    made.append("02_xor_strings")

    # 3 - integers expanded to chr() arrays
    write_case("03_chr_arrays", "sample.pyc", as_pyc(chr_array_source()), truth)
    made.append("03_chr_arrays")

    # 4 - base64 + zlib per literal
    write_case("04_b64_zlib_strings", "sample.pyc", as_pyc(b64_layers_source()), truth)
    made.append("04_b64_zlib_strings")

    # 5 - control-flow flattened dispatcher
    write_case("05_flattened", "sample.pyc", as_pyc(FLATTENED), truth)
    made.append("05_flattened")

    # 6 - opaque predicates and dead code
    write_case("06_opaque_dead", "sample.pyc", as_pyc(opaque_source()), truth)
    made.append("06_opaque_dead")

    # 7 - mixed boolean arithmetic
    write_case("07_mba", "sample.pyc", as_pyc(mixed_boolean_source()), truth)
    made.append("07_mba")

    # 8 - source hidden inside an exec(compile(b64(zlib(...))))
    inner = PLAIN.encode()
    chain = base64.b64encode(zlib.compress(inner)).decode()
    loader = ('import base64,zlib\n'
              f'_p = "{chain}"\n'
              'exec(compile(zlib.decompress(base64.b64decode(_p)), "<p>", "exec"))\n')
    write_case("08_exec_layered", "sample.py", loader.encode(), truth)
    made.append("08_exec_layered")

    # 9 - marshalled code encrypted with a repeating key, decrypted in a stub
    code = marshal.dumps(compile(PLAIN, "<p>", "exec"))
    key = b"\x8f\x2c\x51\xa7"
    payload = xor_bytes(code, key)
    stub = ("import marshal\n"
            f"_k = {list(key)}\n"
            f"_b = {list(payload)}\n"
            "_d = bytes(b ^ _k[i % len(_k)] for i, b in enumerate(_b))\n"
            "exec(marshal.loads(_d))\n")
    write_case("09_marshal_xor", "sample.py", stub.encode(), truth)
    made.append("09_marshal_xor")

    # 10 - zip bundle holding the pyc (PyInstaller / zipapp shape)
    bundle = os.path.join(OUT, "_tmp", "bundle.zip")
    # fixed timestamp: a zip entry otherwise records the wall clock, which
    # would make the fixture differ on every rebuild
    stamp = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(bundle, "w") as archive:
        info = zipfile.ZipInfo("payload.pyc", date_time=stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, as_pyc(PLAIN))
    with open(bundle, "rb") as handle:
        write_case("10_zip_bundle", "bundle.zip", handle.read(), truth)
    made.append("10_zip_bundle")

    # 11 - the nightmare: layered + encrypted + flattened + opaque + renamed
    nightmare_src = f'''
import base64
import lzma
import zlib

_K = {[ord(c) ^ 0x33 for c in SECRET]}


def _q(v):
    return "".join(chr(x ^ 0x33) for x in v)


def _junk(a, b):
    return (a * 3) - (b * 3) + 0


TOKEN = _q(_K)


def gate(x):
    s = 0
    r = None
    while True:
        if s == 0:
            r = _q({[ord(c) ^ 0x33 for c in MARKER]})
            s = 1
        elif s == 1:
            if (2 + 2) == 4:
                return r
            s = 0
'''
    blob = marshal.dumps(compile(nightmare_src, "<n>", "exec"))
    for _ in range(3):
        blob = lzma.compress(zlib.compress(base64.b64encode(blob)))
        blob = base64.b64encode(blob)
    wrapper = ("import base64,lzma,zlib,marshal\n"
               f"_p = {blob.decode()!r}\n"
               "_d = _p\n"
               "for _ in range(1):\n"
               "    _d = base64.b64decode(_d)\n"
               "    _d = zlib.decompress(lzma.decompress(_d))\n"
               "exec(marshal.loads(_d))\n")
    write_case("11_nightmare", "sample.py", wrapper.encode(), truth)
    made.append("11_nightmare")

    shutil.rmtree(os.path.join(OUT, "_tmp"), ignore_errors=True)
    print("built:", ", ".join(made))
    return made


if __name__ == "__main__":
    build()
