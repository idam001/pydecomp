"""1.0.0 gates: *reconstruction* - not just unwrapping, but rebuilding source.

The difference between a packer-unwrapper and a reconstruction engine is whether
it can follow the sample's own logic without running it.  These checks pin that
down:

* a decoder the sample defines itself is interpreted on its literal argument
  (``_d(_q)`` -> ``'print(...)'``), which is what defeats every "unknown
  obfuscation" verdict;
* constant propagation feeds that inlining, and the whole pass set runs to a
  **fixed point** - so literal → decoder → fold → opaque-predicate pruning all
  chain up;
* Hyperion containers give up their ``__code__`` payload;
* pyobfuscate.com builds are decrypted from their own PBKDF2 key schedule
  (AES-GCM, 1,000,000 iterations), statically;
* and when a payload genuinely cannot be opened, its ciphertext is emitted with
  the reason - never withheld.
"""
import base64
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pydecomp as P                                              # noqa: E402

from pydecomp.crypto.aes import AES                               # noqa: E402
from pydecomp.crypto.gcm import _gcm_tag, _ghash                  # noqa: E402
from pydecomp.crypto.kdf import pbkdf2_hmac_sha256                # noqa: E402
from pydecomp.crypto.modes import ctr_xor                         # noqa: E402
from pydecomp.decoders import hyperion as HY                      # noqa: E402
from pydecomp.decoders import pyobfuscate_com as PO               # noqa: E402
from pydecomp.polish.apply import polish_source                   # noqa: E402
from pydecomp.polish.evaluate import evaluate_text                # noqa: E402

FAILED = []
CHECKS = []


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


def eq(got, want, what=""):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, wanted {want!r}")


def ok(cond, what=""):
    if not cond:
        raise AssertionError(what or "expected true")


# ---------------------------------------------------------------------------
# the pure-expression interpreter
# ---------------------------------------------------------------------------

@check("expression evaluator: decode chains fold to the plaintext")
def _evaluator():
    import zlib
    blob = base64.b64encode(zlib.compress(b"print('deep chain')")[::-1]).decode()
    expression = f"zlib.decompress(base64.b64decode({blob!r})[::-1]).decode()"
    env = {"zlib": None}
    value = evaluate_text(f"__import__" if False else expression.replace(
        "zlib.", ""), {})
    # the module proxies are bound by name in the evaluator
    from pydecomp.polish.evaluate import _MODULES
    expression = (f"_MODULES['zlib']['decompress'](base64.b64decode({blob!r})[::-1])"
                  ".decode()")
    from pydecomp.polish import evaluate as EV
    tree = EV._ast.parse(f"zlib.decompress(base64.b64decode({blob!r})[::-1]).decode()",
                         mode="eval")
    got = EV.evaluate(tree.body, {})
    eq(got, "print('deep chain')", "chain evaluated")


@check("expression evaluator refuses anything impure")
def _evaluator_guards():
    from pydecomp.polish import evaluate as EV
    for snippet in ("open('/etc/passwd').read()",
                    "__import__('os').system('id')",
                    "os.listdir('.')",
                    "some_unknown_name"):
        tree = EV._ast.parse(snippet, mode="eval")
        try:
            EV.evaluate(tree.body, {})
        except EV.Unevaluable:
            continue
        raise AssertionError(f"evaluated something impure: {snippet}")


# ---------------------------------------------------------------------------
# inlining and fixed-point chaining
# ---------------------------------------------------------------------------

@check("decoder inlining: the sample's own decoder is interpreted")
def _inline_decoder():
    payload = base64.b64encode(b"print('recovered by inlining')")[::-1].decode()
    source = (
        "import base64\n"
        "def _d(s):\n"
        "    return base64.b64decode(s[::-1]).decode()\n"
        f"_q = {payload!r}\n"
        "print(_d(_q))\n"
    )
    out, notes = polish_source(source)
    ok("print('recovered by inlining')" in out, out)
    ok(any("inlined" in note for note in notes), notes)


@check("fixed point: literal → decoder → fold → opaque pruning in one pass")
def _fixpoint():
    secret = base64.b64encode(b"unlocked").decode()
    source = (
        "import base64\n"
        "def dec(x):\n"
        "    return base64.b64decode(x).decode()\n"
        f"_key = 'aGVsbG8='\n"
        f"_lock = {secret!r}\n"
        "def guard(n):\n"
        "    if n * n >= 0:\n"
        "        return dec(_lock)\n"
        "    return dec('ZmFrZQ==')\n"
        "print(guard(3), dec(_key))\n"
    )
    out, notes = polish_source(source)
    ok("'unlocked'" in out, out)
    ok("'hello'" in out, out)
    ok("'fake'" not in out, "dead branch pruned after folding")
    ok(len(notes) >= 3, notes)


@check("fixed point: nested helper functions resolve in any order")
def _nested_helpers():
    inner = base64.b64encode(b"layer-two").decode()
    middle = base64.b64encode(inner.encode()).decode()
    source = (
        "import base64\n"
        "def two(x):\n"
        "    return base64.b64decode(x).decode()\n"
        "def one(x):\n"
        "    return two(base64.b64decode(x).decode())\n"
        f"print(one({middle!r}))\n"
    )
    out, _notes = polish_source(source)
    ok("'layer-two'" in out, out)


# ---------------------------------------------------------------------------
# named packers
# ---------------------------------------------------------------------------

@check("hyperion: __code__ payload becomes the recovered program")
def _hyperion():
    source = (
        "__obfuscator__ = 'Hyperion'\n"
        "__github__ = 'https://github.com/billythegoat356/Hyperion'\n"
        "__code__ = 'print(\"hyperion payload\")'\n"
        "_while, Product, _builtins, _power, Add, Builtins = "
        "exec, str, tuple, map, ord, globals\n"
        "class _cube:\n"
        "    def execute(code=str):\n"
        "        return _while(Product(_builtins(_power(Add, code))))\n"
    )
    ok(HY.is_hyperion(source), "container recognised")
    payload, how = HY.payload(source)
    eq(payload, 'print("hyperion payload")', "payload literal")
    art = P.dig(source.encode(), "h.py")
    ok('print("hyperion payload")' in art.text, art.text)
    ok(any("Hyperion" in line for line in art.trace), art.trace)


@check("hyperion: ordinal-tuple payload is joined back to source")
def _hyperion_ordinals():
    program = 'print("ordinals")'
    numbers = ", ".join(str(ord(char)) for char in program)
    source = ("__obfuscator__ = 'Hyperion'\n"
              "__github__ = 'x'\n"
              f"__code__ = ({numbers})\n")
    payload, how = HY.payload(source)
    eq(payload, program, "ordinals joined")
    eq(how, "ordinal tuple", "method reported")


def _seal(key, nonce, plaintext):
    """AES-GCM seal with an arbitrary-length nonce, matching ``gcm_decrypt``."""
    cipher = AES(key)
    h = int.from_bytes(cipher.encrypt_block(b"\x00" * 16), "big")
    padded = nonce + b"\x00" * ((16 - len(nonce) % 16) % 16)
    j0 = _ghash(h, padded + (0).to_bytes(8, "big")
                + (len(nonce) * 8).to_bytes(8, "big")).to_bytes(16, "big")
    ciphertext = ctr_xor(cipher, j0[:12], plaintext, start=2)
    tag, _ = _gcm_tag(cipher, nonce, ciphertext)
    return ciphertext, tag


def _pyobfuscate_sample(plaintext: bytes, password: str, with_password=True):
    salt, nonce = os.urandom(16), os.urandom(16)
    key = pbkdf2_hmac_sha256(password, salt, 1_000_000, 32)
    ciphertext, tag = _seal(key, nonce, plaintext)
    blob = salt + nonce + tag + ciphertext
    encoded = base64.b85encode(blob).decode()
    third = len(encoded) // 3
    field = f", 'key': '{password}'" if with_password else ""
    return (f"pyobfuscate({{'pyc': \"\"\"{encoded[:third]}\"\"\", "
            f"'pye': \"\"\"{encoded[third:]}\"\"\"{field}}})\n")


@check("pyobfuscate.com: AES-GCM payload decrypted from its own key schedule")
def _pyobfuscate_gcm():
    program = b'print("pyobfuscate payload reconstructed")\n'
    sample = _pyobfuscate_sample(program, "lIlIIlIlIIl")
    ok(PO.is_pyobfuscate(sample), "container recognised")
    start = time.time()
    art = P.dig(sample.encode(), "obf.py")
    elapsed = time.time() - start
    ok(elapsed < 30, f"decryption took {elapsed:.1f}s")
    ok("pyobfuscate payload reconstructed" in art.text, art.text)
    ok(any("PBKDF2" in line for line in art.trace), art.trace)


@check("pyobfuscate.com: a missing password is reported, not hidden")
def _pyobfuscate_locked():
    sample = _pyobfuscate_sample(b'print("locked")', "lIlIIlIlIIl", with_password=False)
    plaintext, facts = PO.decrypt(sample)
    eq(plaintext, None, "cannot open a locked payload")
    ok("password" in facts["reason"], facts["reason"])
    art = P.dig(sample.encode(), "obf.py")
    ok("pyobfuscate" in art.text, "the container is still emitted whole")


@check("a recovered program keeps its shape at scale")
def _scale():
    body = "\n".join(
        f"def step_{index}(value):\n"
        f"    token = {base64.b64encode(f'k{index}'.encode())!r}\n"
        f"    raw = dec(token)\n"
        f"    if value * value >= 0:\n"
        f"        return raw + str((value ^ {index}) + 2 * (value & {index}))\n"
        f"    return None\n"
        for index in range(80)
    )
    source = ("import base64\n"
              "def dec(x):\n"
              "    return base64.b64decode(x).decode()\n\n" + body)
    out, notes = polish_source(source)
    eq(out.count("def step_"), 80, "every function survives")
    ok(out.count("+ str(value + ") >= 80, "mba rewritten inside every function")
    ok("if value * value >= 0" not in out, "opaque guards pruned")
    ok(any("inlined" in note for note in notes), notes)


if __name__ == "__main__":
    print()
    if FAILED:
        print(f"{len(FAILED)} failed: {', '.join(FAILED)}")
        raise SystemExit(1)
    print(f"all {len(CHECKS)} checks passed")
