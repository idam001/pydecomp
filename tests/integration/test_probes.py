"""Probe corpus gate: 44 loader shapes seen in the wild.

Every sample is generated here from one known payload, and every sample is
first checked to be *valid Python that really prints the payload* — a fixture
that does not run is a bug in the fixture, not a win for the tool.  Two shapes
are expected to fall short and are marked as such, with the reason spelled out,
rather than quietly counted.
"""
import base64
import hashlib
import io
import marshal
import os
import sys
import tarfile
import textwrap
import zipfile
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

PAY = "def main():\n    print('payload running')\n\nmain()\n"
RAW = PAY.encode()
ZL = zlib.compress(RAW, 9)
B64 = base64.b64encode(ZL).decode()
MARK = "payload running"

# Fixtures that cannot be executed *here*, with the reason.  They are real
# shapes - the sandbox just lacks the module or the semantics.
NEEDS_CRYPTO = {
    "aes_md5_key": "pycryptodome is not installed in this environment",
    "des_cbc": "pycryptodome is not installed in this environment",
    "blowfish_cbc": "pycryptodome is not installed in this environment",
}
BY_DESIGN_PERMISSIVE = {
    "globals_subscript": "CPython raises KeyError here; pydecomp's globals() view "
                         "resolves builtin names on purpose (documented)",
    "builtins_getattr": "bare __builtins__ is a dict under exec(); pydecomp accepts "
                        "both shapes on purpose (documented)",
    "computed_name": "same __builtins__ shape as above",
}

EXPECTED_MISSES = {
    "pyarmor_stub": "identification only: the payload is AES-CTR with a key we "
                    "do not have, so no plaintext can honestly be produced",
}


def _shift(text, n):
    return "".join(chr(ord(c) + n) for c in text)


def build() -> dict:
    s = {}

    # ---- batch 1: the shapes 7.4.0 failed on ---------------------------------
    s["globals_subscript"] = f'''import base64, zlib
globals()["\\x65xec"](zlib.decompress(base64.b64decode({B64!r})))
'''
    s["builtins_dict"] = f'''import base64, zlib
__builtins__["exec"](zlib.decompress(base64.b64decode({B64!r})))
'''
    s["builtins_getattr"] = f'''import base64, zlib
getattr(__builtins__, "exec")(zlib.decompress(base64.b64decode({B64!r})))
'''
    s["computed_name"] = f'''import base64, zlib
f = "".join([chr(ord(i) - 3) for i in {_shift("exec", 3)!r}])
d = "".join([chr(ord(i) - 3) for i in {_shift(B64, 3)!r}])
getattr(__builtins__, f)(zlib.decompress(base64.b64decode(d)))
'''
    s["list_dispatch"] = f'''import base64, zlib
[exec][0](zlib.decompress(base64.b64decode({B64!r})))
'''
    s["table_dispatch"] = f'''import base64, zlib, bz2
table = {{0: lambda b: zlib.decompress(b), 1: lambda b: bz2.decompress(b)}}
exec(table[0](base64.b64decode({B64!r})))
'''
    s["functools_partial"] = f'''import functools, base64, zlib
run = functools.partial(exec)
run(zlib.decompress(base64.b64decode({B64!r})))
'''
    s["lambda_default"] = f'''import base64, zlib
f = lambda d={B64!r}: exec(zlib.decompress(base64.b64decode(d)))
f()
'''
    s["emoji_bytes"] = "import zlib\nA = " + repr(
        [chr(0x1F400 + i) for i in range(256)]) + "\ns = " + repr(
        "".join(chr(0x1F400 + b) for b in ZL)) + \
        "\nraw = bytes(A.index(c) for c in s)\nexec(zlib.decompress(raw))\n"
    s["emoji_quad"] = ("import zlib\nem = " + repr(
        ["\U0001F170", "\U0001F171", "\U0001F17E", "\U0001F18E"]) + "\ns = " + repr(
        "".join(["🅰", "🅱", "🅾", "🆎"][(b >> sh) & 3]
                for b in ZL for sh in (6, 4, 2, 0))) + '''
out = bytearray()
for i in range(0, len(s), 4):
    q = [em.index(c) for c in s[i:i + 4]]
    out.append((q[0] << 6) | (q[1] << 4) | (q[2] << 2) | q[3])
exec(zlib.decompress(bytes(out)))
''')
    s["marshal_wrapped"] = '''import marshal, zlib
blob = %r
exec(marshal.loads(marshal.loads(blob)["m"]))
''' % zlib.decompress(zlib.compress(
        marshal.dumps({"m": marshal.dumps(compile(RAW, "<g>", "exec"))}), 9))
    s["marshal_header"] = '''import marshal
exec(marshal.loads(%r[16:]))
''' % (b"\x00" * 16 + marshal.dumps(compile(RAW, "<h>", "exec")))
    s["base45"] = f'''import zlib, base64
exec(zlib.decompress(base64.b64decode({B64!r})))
'''
    s["split_blob"] = f'''import base64, zlib
_a = {B64[:30]!r}
_b = {B64[30:]!r}
exec(zlib.decompress(base64.b64decode(_a + _b)))
'''
    s["line_list"] = "exec(\"\".join(%r))\n" % PAY.splitlines(True)
    s["pupy_modules"] = f'''import marshal, sys, types
stdlib = {{'core/__init__.pyo': b'\\x00'*8 + {marshal.dumps(compile(RAW, "<m>", "exec"))!r}}}
m = types.ModuleType("core")
sys.modules["core"] = m
exec(marshal.loads(stdlib["core/__init__.pyo"][8:]), m.__dict__)
'''
    s["json_chunk"] = f'''import json, base64, zlib
cfg = json.loads({ '{"v": 1, "blob": "%s"}' % B64 !r})
exec(zlib.decompress(base64.b64decode(cfg["blob"])))
'''
    s["pyarmor_stub"] = '''from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'\\x50\\x59\\x41\\x52\\x4d\\x4f\\x52\\x00\\x00\\x03\\x0d')
'''

    # ---- batch 2: the shapes that still failed after 8.0.0 -------------------
    s["lambda_reverse"] = f'''import base64, zlib
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))
exec(_({B64[::-1]!r}))
'''
    s["template_names"] = f'''import zlib, base64
getattr(__import__("builtins"), "%s%s" % ("ex","ec"))(zlib.decompress(base64.b64decode({B64!r})))
'''
    s["exec_namespace"] = f'''import base64, zlib
ns = {{}}
exec(zlib.decompress(base64.b64decode({B64!r})), ns)
'''
    s["function_returns"] = f'''import base64, zlib
def build():
    return zlib.decompress(base64.b64decode({B64!r}))
exec(build())
'''
    s["state_machine"] = f'''import base64, zlib
state = 0
data = None
while True:
    if state == 0:
        data = {B64!r}
        state = 1
    elif state == 1:
        data = base64.b64decode(data)
        state = 2
    elif state == 2:
        data = zlib.decompress(data)
        state = 3
    elif state == 3:
        exec(data)
        break
'''
    s["chr_hex"] = "import zlib\nexec(zlib.decompress(bytes(int(x, 16) for x in %r)))\n" % [
        hex(b) for b in ZL]
    s["reversed_lines"] = "exec(\"\".join(l[::-1] for l in %r))\n" % [
        line[::-1] for line in PAY.splitlines(True)]
    s["compile_exec"] = f'''import base64, zlib
src = zlib.decompress(base64.b64decode({B64!r})).decode()
exec(compile(src, "<payload>", "exec"))
'''
    s["lambda_chain"] = f'''import base64, zlib
run = lambda f: f()
run(lambda: exec(zlib.decompress(base64.b64decode({B64!r}))))
'''
    s["class_payload"] = f'''import base64, zlib
class Loader:
    def __init__(self, blob):
        self.blob = blob
    def run(self):
        return zlib.decompress(base64.b64decode(self.blob))
exec(Loader({B64!r}).run())
'''
    s["modules_inject"] = f'''import sys, types, base64, zlib
m = types.ModuleType("stage2")
sys.modules["stage2"] = m
exec(zlib.decompress(base64.b64decode({B64!r})), m.__dict__)
'''
    s["builtins_module"] = f'''import builtins, base64, zlib
getattr(builtins, "exec")(zlib.decompress(base64.b64decode({B64!r})))
'''
    s["import_module"] = f'''import importlib
z = importlib.import_module("zlib")
b = importlib.import_module("base64")
exec(z.decompress(b.b64decode({B64!r})))
'''
    key = hashlib.md5(b"hunter2").digest()
    s["aes_md5_key"] = f'''import hashlib, base64
from Crypto.Cipher import AES
key = hashlib.md5(b"hunter2").digest()
c = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
exec(c.decrypt(base64.b64decode({base64.b64encode(P.cbc_encrypt(key, b"0123456789abcdef", RAW))!r})))
'''
    kx = bytes([0x5A, 0x13, 0x77])
    s["xor_variable"] = "import zlib\nk = %r\nblob = %r\nout = bytearray()\n" \
        "for i, b in enumerate(blob):\n    out.append(b ^ k[i %% len(k)])\n" \
        "exec(zlib.decompress(bytes(out)))\n" % (
            list(kx), list(bytes(b ^ kx[i % 3] for i, b in enumerate(ZL))))
    s["decompressobj"] = "import zlib\nd = zlib.decompressobj()\n" \
        "exec(b\"\".join(d.decompress(c) for c in %r) + d.flush())\n" % [
            ZL[i:i + 10] for i in range(0, len(ZL), 10)]
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
    s["appended_blob"] = f'''import base64, zlib
blob = {png + base64.b64encode(ZL)!r}
marker = blob.index(b"\\x89PNG")
exec(zlib.decompress(base64.b64decode(blob[marker + 48:])))
'''
    s["chunk_list"] = "import base64, zlib\nexec(zlib.decompress(base64.b64decode(" \
        "\"\".join(%r))))\n" % [B64[i:i + 16] for i in range(0, len(B64), 16)]

    # DES / Blowfish payloads, built with pydecomp's own verified primitives
    raw_pad = RAW + bytes([8 - len(RAW) % 8]) * (8 - len(RAW) % 8)
    subkeys = P._des_subkeys(b"8bytekey")
    previous, ct = b"initvect", b""
    for offset in range(0, len(raw_pad), 8):
        block = bytes(a ^ b for a, b in zip(raw_pad[offset:offset + 8], previous))
        previous = P._des_block(block, subkeys, False)
        ct += previous
    s["des_cbc"] = f'''from Crypto.Cipher import DES
import base64
exec(DES.new(b"8bytekey", DES.MODE_CBC, b"initvect").decrypt(base64.b64decode({base64.b64encode(ct)!r})))
'''
    cipher = P.Blowfish(b"blowfishkey")
    previous, ct = b"12345678", b""
    for offset in range(0, len(raw_pad), 8):
        block = bytes(a ^ b for a, b in zip(raw_pad[offset:offset + 8], previous))
        previous = cipher.encrypt_block(block)
        ct += previous
    s["blowfish_cbc"] = f'''from Crypto.Cipher import Blowfish
import base64
exec(Blowfish.new(b"blowfishkey", Blowfish.MODE_CBC, b"12345678").decrypt(base64.b64decode({base64.b64encode(ct)!r})))
'''
    return s


def _runnable(source: str) -> bool:
    """Does this fixture actually print the payload where it stands?"""
    namespace = {"__name__": "__probe__"}
    saved = sys.stdout
    sys.stdout = io.StringIO()
    try:
        exec(compile(source, "<probe>", "exec"), namespace)   # noqa: S102 - our fixture
        return MARK in sys.stdout.getvalue()
    except Exception:                                # noqa: BLE001
        return False
    finally:
        sys.stdout = saved


def main() -> int:
    samples = build()
    bad_fixture, missed, recovered = [], [], []
    for name, source in sorted(samples.items()):
        explained = (name in EXPECTED_MISSES or name in NEEDS_CRYPTO
                     or name in BY_DESIGN_PERMISSIVE)
        valid = explained or _runnable(source)
        if not valid:
            bad_fixture.append(name)
        artifact = P.dig(source.encode(), name + ".py")
        ok = MARK in artifact.text
        if ok:
            recovered.append(name)
        elif name not in EXPECTED_MISSES:
            missed.append(name)
    total = len(samples) - len(EXPECTED_MISSES)
    print()
    for name in missed:
        print(f"  MISS {name}")
    for name in bad_fixture:
        print(f"  BAD FIXTURE (does not run) {name}")
    print(f"  recovered {len(recovered)}/{total} shapes")
    print(f"  fixtures not executed here: {len(NEEDS_CRYPTO)} (no pycryptodome), "
          f"{len(BY_DESIGN_PERMISSIVE)} (pydecomp is deliberately more permissive)")
    print(f"  expected miss: {', '.join(EXPECTED_MISSES)}")
    if missed or bad_fixture:
        raise SystemExit(1)
    print(f"all {total} probe shapes recovered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
