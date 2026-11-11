"""pydecomp - shims."""
from __future__ import annotations

import hashlib
import sys

from ..core.util import to_bytes
from ..core.values import Val
from ..crypto.aes import AES
from ..crypto.blowfish import (
    blowfish_cbc_decrypt, blowfish_ecb_decrypt, des_ecb_decrypt,
)
from ..crypto.chacha20 import chacha20_xor
from ..crypto.des import _des_block, _des_subkeys, des3_cbc_decrypt, des_cbc_decrypt
from ..crypto.fernet import fernet_decrypt
from ..crypto.gcm import gcm_decrypt, gcm_encrypt
from ..crypto.modes import (
    MODE_CBC, MODE_CFB, MODE_CTR, MODE_ECB, MODE_GCM, MODE_OFB,
    _unpad, cbc_decrypt, cfb_decrypt, ctr_block_xor, ecb_decrypt, ofb_decrypt,
)
from ..crypto.poly1305 import chacha20poly1305_open, chacha20poly1305_seal
from ..crypto.rc4 import rc4
from ..exceptions import EvalFailed, EvalUnsafe, _ExprRefuse
from ..terminal.color import step

class _CipherObject:
    """Base class: the evaluator calls ``_pydecomp_call`` for every attribute."""

    label = "cipher"

    def _pydecomp_call(self, attr, args, kwargs):
        raise EvalUnsafe(f".{attr} on {self.label}")

class _Aead(_CipherObject):
    """`AESGCM(key)` / `ChaCha20Poly1305(key)` from cryptography."""

    def __init__(self, key, kind="aesgcm"):
        if isinstance(key, str):
            key = key.encode("latin-1")
        key = bytes(key)
        if kind == "aesgcm":
            if len(key) not in (16, 24, 32):
                raise EvalFailed(f"AESGCM key must be 16/24/32 bytes, got {len(key)}")
        elif kind == "chacha20poly1305":
            if len(key) != 32:
                raise EvalFailed(f"ChaCha20Poly1305 key must be 32 bytes, got {len(key)}")
        else:
            raise EvalFailed(f"unknown AEAD {kind!r}")
        self.key, self.kind = key, kind
        self.label = f"{kind}({len(key)}-byte key)"

    def _pydecomp_call(self, attr, args, kwargs):
        nonce = bytes(args[0]) if args else kwargs.get("nonce", b"")
        data = bytes(args[1]) if len(args) > 1 else kwargs.get("data", b"")
        aad = b""
        if len(args) > 2 and args[2] is not None:
            aad = bytes(args[2])
        elif kwargs.get("associated_data"):
            aad = bytes(kwargs["associated_data"])
        if attr == "decrypt":
            if self.kind == "aesgcm":
                return Val(gcm_decrypt(self.key, nonce, data, aad),
                           [f"aes-gcm({len(self.key) * 8})"])
            return Val(chacha20poly1305_open(self.key, nonce, data, aad),
                       ["chacha20-poly1305"])
        if attr == "encrypt":
            if self.kind == "aesgcm":
                return Val(gcm_encrypt(self.key, nonce, data, aad),
                           [f"aes-gcm({len(self.key) * 8})"])
            return Val(chacha20poly1305_seal(self.key, nonce, data, aad),
                       ["chacha20-poly1305"])
        raise EvalUnsafe(f".{attr} on {self.label}")

class _StreamCipher(_CipherObject):
    """RC4 / ChaCha20 — decrypt and encrypt are the same operation."""

    def __init__(self, key, kind="rc4", nonce=b"", counter=0):
        self.key = bytes(key) if not isinstance(key, str) else key.encode()
        self.kind, self.nonce, self.counter = kind, bytes(nonce or b""), counter
        self.label = f"{kind}({len(self.key)}-byte key)"

    def _pydecomp_call(self, attr, args, kwargs):
        if attr not in ("decrypt", "encrypt", "update"):
            raise EvalUnsafe(f".{attr} on {self.label}")
        data = bytes(args[0]) if args else b""
        if self.kind == "rc4":
            return Val(rc4(self.key, data), ["rc4"])
        if self.kind == "chacha20":
            if len(self.nonce) not in (8, 12):
                raise EvalFailed("chacha20 needs an 8- or 12-byte nonce")
            return Val(chacha20_xor(self.key, self.nonce, data, self.counter),
                       ["chacha20"])
        raise EvalFailed(f"unknown stream cipher {self.kind!r}")

class _BlockCipher(_CipherObject):
    """pycryptodome style: `AES.new(key, AES.MODE_CBC, iv).decrypt(data)`."""

    def __init__(self, key, mode, iv=b"", nonce=b"", tag=b""):
        if isinstance(key, str):
            key = key.encode("latin-1")
        self.key = bytes(key)
        self.mode = int(mode)
        self.iv = bytes(iv) if iv else b""
        self.nonce = bytes(nonce) if nonce else b""
        self.tag = bytes(tag) if tag else b""
        self.label = f"aes-{self.mode}-cipher"

    def _open(self, data, iv):
        cipher = AES(self.key)
        if self.mode == MODE_ECB:
            return ecb_decrypt(self.key, data, unpad=False), "aes-ecb"
        if self.mode == MODE_CBC:
            return cbc_decrypt(self.key, iv, data, unpad=False), "aes-cbc"
        if self.mode == MODE_CFB:
            return cfb_decrypt(cipher, iv, data), "aes-cfb"
        if self.mode == MODE_OFB:
            return ofb_decrypt(cipher, iv, data), "aes-ofb"
        if self.mode == MODE_CTR:
            return ctr_block_xor(cipher, iv, data), "aes-ctr"
        if self.mode == MODE_GCM:
            return gcm_decrypt(self.key, self.nonce or iv, data), "aes-gcm"
        raise EvalFailed(f"unsupported AES mode {self.mode}")

    def _pydecomp_call(self, attr, args, kwargs):
        if attr in ("decrypt", "encrypt", "update"):
            data = bytes(args[0]) if args else b""
            plain, label = self._open(data, self.iv)
            return Val(plain, [label])
        if attr in ("decrypt_and_verify", "verify"):
            data = bytes(args[0]) if args else b""
            tag = bytes(args[1]) if len(args) > 1 else self.tag
            if self.mode != MODE_GCM:
                raise EvalFailed("decrypt_and_verify is GCM only")
            nonce = self.nonce or self.iv
            return Val(gcm_decrypt(self.key, nonce, data + tag), ["aes-gcm"])
        if attr in ("iv", "nonce", "digest"):
            return Val(self.iv if attr == "iv" else self.nonce, [])
        raise EvalUnsafe(f".{attr} on {self.label}")

class _CryptoCipher(_CipherObject):
    """cryptography low level: Cipher(algorithms.AES(k), modes.CBC(iv))."""

    def __init__(self, key, scheme, iv=b"", nonce=b"", tag=b""):
        self.inner = _BlockCipher(key, scheme, iv=iv, nonce=nonce, tag=tag)
        self.label = f"cipher({self.inner.label})"

    def _pydecomp_call(self, attr, args, kwargs):
        if attr in ("decryptor", "encryptor"):
            return Val(_CryptoDecryptor(self.inner), [])
        if attr == "decrypt":
            return self.inner._pydecomp_call("decrypt", args, kwargs)
        raise EvalUnsafe(f".{attr} on {self.label}")

class _CryptoDecryptor(_CipherObject):
    label = "decryptor"

    def __init__(self, inner):
        self.inner = inner
        self.buffer = bytearray()

    def _pydecomp_call(self, attr, args, kwargs):
        if attr == "update":
            self.buffer += bytes(args[0]) if args else b""
            return Val(b"", [])
        if attr == "finalize":
            plain, label = self.inner._open(bytes(self.buffer), self.inner.iv)
            self.buffer = bytearray()
            return Val(plain, [label])
        if attr == "authenticate_tag":
            return Val(b"", [])
        raise EvalUnsafe(f".{attr} on decryptor")

class _FernetObject(_CipherObject):
    label = "Fernet"

    def __init__(self, key):
        self.key = key

    def _pydecomp_call(self, attr, args, kwargs):
        if attr == "decrypt":
            token = args[0] if args else kwargs.get("token", b"")
            if isinstance(token, str):
                token = token.encode()
            return Val(fernet_decrypt(token, self.key), ["fernet"])
        raise EvalUnsafe(f".{attr} on Fernet")

class _BlowfishCipher(_CipherObject):
    """Blowfish in the two modes a loader would use."""

    def __init__(self, key, mode, iv=b""):
        self.key = to_bytes(key)
        self.mode = mode
        self.iv = to_bytes(iv)

    def _pydecomp_call(self, attr, args, kwargs):
        if attr in ("decrypt", "update", "finalize"):
            data = to_bytes(args[0]) if args else b""
            try:
                if self.mode == MODE_ECB:
                    return Val(blowfish_ecb_decrypt(self.key, data), [])
                return Val(blowfish_cbc_decrypt(self.key, self.iv, data), [])
            except Exception as exc:                 # noqa: BLE001
                raise EvalFailed(f"blowfish: {exc}") from exc
        raise EvalFailed(f"blowfish has no .{attr}")

class _DesCipher(_CipherObject):
    """DES / 3DES in the two modes obfuscators actually use."""

    def __init__(self, key, scheme, mode, iv=b""):
        self.key = bytes(key) if isinstance(key, (bytes, bytearray)) else bytes(key, "latin-1")
        self.scheme = scheme
        self.mode = mode
        self.iv = bytes(iv) if isinstance(iv, (bytes, bytearray)) else b""

    def _open(self, data: bytes) -> bytes:
        ecb = self.mode in (getattr(sys.modules[__name__], "MODE_ECB", -1), 1)
        if self.scheme == "des":
            if ecb:
                return des_ecb_decrypt(self.key, data)
            return des_cbc_decrypt(self.key, self.iv, data)
        if ecb:
            sub = self.key + (self.key[:8] if len(self.key) == 16 else b"")
            sub = (sub + b"\x00" * 24)[:24]
            k1, k2, k3 = (_des_subkeys(sub[:8]), _des_subkeys(sub[8:16]),
                          _des_subkeys(sub[16:24]))
            out = bytearray()
            for offset in range(0, len(data) - len(data) % 8, 8):
                step = _des_block(data[offset:offset + 8], k3, True)
                step = _des_block(step, k2, False)
                out.extend(_des_block(step, k1, True))
            return _unpad(bytes(out))
        return des3_cbc_decrypt(self.key, self.iv, data)

    def _pydecomp_call(self, attr, args, kwargs):
        if attr in ("decrypt", "update", "finalize"):
            data = to_bytes(args[0]) if args else b""
            try:
                return Val(self._open(data), [])
            except Exception as exc:                 # noqa: BLE001
                raise EvalFailed(f"des: {exc}") from exc
        raise EvalFailed(f"des cipher has no .{attr}")

class _Instance:
    """A statically built instance of a loader class.

    Attributes live in ``attrs``; a method call is simulated by the evaluator
    with ``self`` bound to this object, so `self.data` and `Loader(data).run()`
    resolve without ever creating a real object.
    """

    def __init__(self, class_name, attrs=None):
        self.class_name = class_name
        self.attrs = dict(attrs or {})

    def __repr__(self):
        return f"<{self.class_name} instance>"

class _HashObject(_CipherObject):
    def __init__(self, name, data=b""):
        self.name = name
        self.data = bytes(data) if not isinstance(data, str) else data.encode()
        self.label = f"{name} hash"

    def _pydecomp_call(self, attr, args, kwargs):
        if attr == "update":
            chunk = args[0] if args else b""
            self.data += bytes(chunk) if not isinstance(chunk, str) else chunk.encode()
            return Val(None, [])
        if attr == "digest":
            return Val(hashlib.new(self.name, self.data).digest(), [f"{self.name}-digest"])
        if attr == "hexdigest":
            return Val(hashlib.new(self.name, self.data).hexdigest(), [f"{self.name}-hexdigest"])
        if attr == "copy":
            return Val(_HashObject(self.name, self.data), [])
        raise EvalUnsafe(f".{attr} on {self.label}")

CIPHER_CONSTANTS = {}

for _mod in ("Crypto.Cipher.AES", "Cryptodome.Cipher.AES"):
    CIPHER_CONSTANTS[f"{_mod}.MODE_ECB"] = MODE_ECB
    CIPHER_CONSTANTS[f"{_mod}.MODE_CBC"] = MODE_CBC
    CIPHER_CONSTANTS[f"{_mod}.MODE_CFB"] = MODE_CFB
    CIPHER_CONSTANTS[f"{_mod}.MODE_OFB"] = MODE_OFB
    CIPHER_CONSTANTS[f"{_mod}.MODE_CTR"] = MODE_CTR
    CIPHER_CONSTANTS[f"{_mod}.MODE_GCM"] = MODE_GCM
    CIPHER_CONSTANTS[f"{_mod}.block_size"] = 16
    CIPHER_CONSTANTS[f"{_mod}.key_size"] = (16, 24, 32)

def _factory_aead(key, kind="aesgcm"):
    return Val(_Aead(key, kind), [])

def _factory_fernet(key):
    return Val(_FernetObject(key), [])

def _factory_stream(key, kind):
    def build(*args, **kwargs):
        nonce = kwargs.get("nonce", b"")
        counter = int(kwargs.get("counter", 0) or 0)
        if len(args) > 1 and not nonce:
            nonce = args[1]
        return Val(_StreamCipher(key, kind, nonce=nonce, counter=counter), [])
    return build

def _factory_pycryptodome_new(module, name):
    """`AES.new(key, mode, iv)` / `ARC4.new(key)` / `ChaCha20.new(...)`."""

    def build(*args, **kwargs):
        key = args[0] if args else kwargs.get("key", b"")
        if name == "AES":
            mode = args[1] if len(args) > 1 else kwargs.get("mode", MODE_CBC)
            iv = args[2] if len(args) > 2 else kwargs.get("iv", b"")
            nonce = kwargs.get("nonce", b"")
            tag = kwargs.get("tag", b"")
            return Val(_BlockCipher(key, mode, iv=iv or nonce,
                                    nonce=nonce or iv, tag=tag), [])
        if name == "ARC4":
            return Val(_StreamCipher(key, "rc4"), [])
        if name == "Blowfish":
            from types import SimpleNamespace
            mode = args[1] if len(args) > 1 else kwargs.get("mode", MODE_CBC)
            iv = args[2] if len(args) > 2 else kwargs.get("iv", b"")
            return Val(_BlowfishCipher(key, mode, iv), [])
        if name in ("DES", "DES3"):
            mode = args[1] if len(args) > 1 else kwargs.get("mode", MODE_CBC)
            iv = args[2] if len(args) > 2 else kwargs.get("iv", b"")
            scheme = "des" if name == "DES" else "des3"
            return Val(_DesCipher(key, scheme, mode, iv=iv or kwargs.get("nonce", b"")), [])
        if name == "ChaCha20":
            nonce = args[1] if len(args) > 1 else kwargs.get("nonce", b"")
            return Val(_StreamCipher(key, "chacha20", nonce=nonce,
                                     counter=int(kwargs.get("counter", 0) or 0)), [])
        raise EvalFailed(f"unsupported cipher module {module}.{name}")

    return build

def _factory_cryptography_cipher(algorithm, mode):
    return Val(_CryptoCipher(algorithm, mode), [])

def _factory_mode(scheme):
    def build(*args, **kwargs):
        iv = args[0] if args else kwargs.get("iv", kwargs.get("nonce", b""))
        return Val({"iv": iv, "nonce": kwargs.get("nonce", b""),
                    "tag": kwargs.get("tag", b"")}, [])
    return build

def _factory_algorithm(key):
    return Val(bytes(key) if not isinstance(key, str) else key.encode(), [])

CIPHER_SCHEMES = {"ECB": MODE_ECB, "CBC": MODE_CBC, "CFB": MODE_CFB,
                  "OFB": MODE_OFB, "CTR": MODE_CTR, "GCM": MODE_GCM}

def _factory_cipher_final(algorithm, mode):
    """`Cipher(algorithms.AES(key), modes.CTR(iv))`."""
    key = algorithm
    if isinstance(key, Val):
        key = key.value
    if not isinstance(mode, dict) or "scheme" not in mode:
        raise EvalFailed("Cipher() needs a mode made by pydecomp's modes.*")
    return Val(_CryptoCipher(key, mode["scheme"], iv=mode.get("iv", b""),
                             nonce=mode.get("nonce", b""), tag=mode.get("tag", b"")), [])

def _factory_algorithms_aes(key, *a, **k):
    return Val(bytes(key) if not isinstance(key, str) else key.encode(), [])

def _make_mode_factory(name):
    def build(*args, **kwargs):
        iv = b""
        if args:
            iv = bytes(args[0]) if not isinstance(args[0], str) else args[0].encode()
        elif "iv" in kwargs:
            iv = bytes(kwargs["iv"])
        nonce = bytes(kwargs.get("nonce", b"")) or (iv if name == "GCM" else b"")
        return Val({"scheme": CIPHER_SCHEMES[name], "iv": iv if name != "GCM" else b"",
                    "nonce": nonce, "tag": bytes(kwargs.get("tag", b""))}, [])
    return build

FACTORIES = {
    "cryptography.hazmat.primitives.ciphers.Cipher": _factory_cipher_final,
    "cryptography.hazmat.primitives.ciphers.algorithms.AES": _factory_algorithms_aes,
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM":
        lambda key, *a, **k: Val(_Aead(key, "aesgcm"), []),
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305":
        lambda key, *a, **k: Val(_Aead(key, "chacha20poly1305"), []),
    "cryptography.fernet.Fernet": lambda key, *a, **k: Val(_FernetObject(key), []),
}

for _name in CIPHER_SCHEMES:
    FACTORIES[f"cryptography.hazmat.primitives.ciphers.modes.{_name}"] = \
        _make_mode_factory(_name)

for _mod in ("Crypto.Cipher", "Cryptodome.Cipher"):
    FACTORIES[f"{_mod}.Blowfish.new"] = _factory_pycryptodome_new(_mod, "Blowfish")
    CIPHER_CONSTANTS[f"{_mod}.Blowfish.MODE_ECB"] = MODE_ECB
    CIPHER_CONSTANTS[f"{_mod}.Blowfish.MODE_CBC"] = MODE_CBC
    CIPHER_CONSTANTS[f"{_mod}.Blowfish.block_size"] = 8
    FACTORIES[f"{_mod}.DES.new"] = _factory_pycryptodome_new(_mod, "DES")
    FACTORIES[f"{_mod}.DES3.new"] = _factory_pycryptodome_new(_mod, "DES3")
    CIPHER_CONSTANTS[f"{_mod}.DES.MODE_ECB"] = MODE_ECB
    CIPHER_CONSTANTS[f"{_mod}.DES.MODE_CBC"] = MODE_CBC
    CIPHER_CONSTANTS[f"{_mod}.DES3.MODE_ECB"] = MODE_ECB
    CIPHER_CONSTANTS[f"{_mod}.DES3.MODE_CBC"] = MODE_CBC
    CIPHER_CONSTANTS[f"{_mod}.DES.block_size"] = 8
    CIPHER_CONSTANTS[f"{_mod}.DES3.block_size"] = 8
    FACTORIES[f"{_mod}.AES.new"] = _factory_pycryptodome_new(_mod, "AES")
    FACTORIES[f"{_mod}.ARC4.new"] = _factory_pycryptodome_new(_mod, "ARC4")
    FACTORIES[f"{_mod}.ChaCha20.new"] = _factory_pycryptodome_new(_mod, "ChaCha20")
    FACTORIES[f"{_mod}.AES.MODE_ECB"] = _factory_pycryptodome_new(_mod, "AES")

FACTORIES.update({
    "hashlib.md5": lambda d=b"", *a, **k: Val(_HashObject("md5", d), []),
    "hashlib.sha1": lambda d=b"", *a, **k: Val(_HashObject("sha1", d), []),
    "hashlib.sha256": lambda d=b"", *a, **k: Val(_HashObject("sha256", d), []),
    "hashlib.sha512": lambda d=b"", *a, **k: Val(_HashObject("sha512", d), []),
    "hashlib.sha3_256": lambda d=b"", *a, **k: Val(_HashObject("sha3_256", d), []),
    "hashlib.blake2b": lambda d=b"", *a, **k: Val(_HashObject("blake2b", d), []),
})

class _ExprCipher:
    """A pycryptodome-shaped cipher whose methods hand back plain bytes.

    The Val-based cipher objects speak the evaluator's own value type; the
    expression engine needs ``bytes`` back so a sample's own arithmetic keeps
    working (``c.decrypt(x)[::-1]`` and friends).
    """

    def __init__(self, inner, kind="block"):
        self._inner = inner
        self._kind = kind
        self._buffer = b""
        self._tag = getattr(inner, "tag", b"")

    @staticmethod
    def _raw(value):
        return getattr(value, "value", value)

    def decrypt(self, data=b"", *args, **kwargs):
        try:
            return self._raw(self._inner._pydecomp_call("decrypt", [to_bytes(data)], {}))
        except _ExprRefuse:
            raise
        except Exception as exc:                     # noqa: BLE001
            raise _ExprRefuse(f"cipher: {exc}") from exc

    def update(self, data=b"", *args, **kwargs):
        return self.decrypt(data)

    def finalize(self, *args, **kwargs):
        return b""

    def encrypt(self, data=b"", *args, **kwargs):
        raise _ExprRefuse("encryption")

    def verify(self, tag, *args, **kwargs):
        return None

    def digest(self):
        return b""

    def hexdigest(self):
        return ""

    def __getattr__(self, item):
        raise _ExprRefuse(f"cipher.{item}")

class _BlowfishAdapter:
    """`Blowfish.new(key, mode, iv)` speaking plain bytes."""

    def __init__(self, key, mode, iv=b""):
        self.key = to_bytes(key)
        self.mode = mode
        self.iv = to_bytes(iv)

    def decrypt(self, data=b"", *args, **kwargs):
        data = to_bytes(data)
        if self.mode == MODE_ECB:
            return blowfish_ecb_decrypt(self.key, data)
        return blowfish_cbc_decrypt(self.key, self.iv, data)

    def update(self, data=b"", *args, **kwargs):
        return self.decrypt(data)

    def finalize(self, *args, **kwargs):
        return b""

    def __getattr__(self, item):
        raise _ExprRefuse(f"blowfish.{item}")

def _expr_cipher_new(kind):
    """`AES.new(key, mode, iv)` / `DES3.new(...)` / `ARC4.new(key)`."""
    def build(*args, **kwargs):
        key = args[0] if args else kwargs.get("key", b"")
        mode = args[1] if len(args) > 1 else kwargs.get("mode", MODE_CBC)
        iv = args[2] if len(args) > 2 else kwargs.get("iv", b"")
        try:
            if kind in ("ARC4", "RC4"):
                return _ExprCipher(_StreamCipher(to_bytes(key), "rc4"), "stream")
            if kind == "ChaCha20":
                nonce = args[1] if len(args) > 1 else kwargs.get("nonce", b"")
                return _ExprCipher(_StreamCipher(to_bytes(key), "chacha20",
                                                 nonce=to_bytes(nonce),
                                                 counter=int(kwargs.get("counter", 0) or 0)),
                                   "stream")
            if kind == "Blowfish":
                return _BlowfishAdapter(key, mode, iv)
            if kind in ("DES", "DES3"):
                scheme = "des" if kind == "DES" else "des3"
                return _ExprCipher(_DesCipher(to_bytes(key), scheme, mode,
                                              iv=to_bytes(iv) or to_bytes(
                                                  kwargs.get("nonce", b""))))
            if mode == MODE_GCM:
                return _ExprCipher(_Aead(to_bytes(key)), "aead")
            return _ExprCipher(_BlockCipher(to_bytes(key), mode, iv=to_bytes(iv),
                                            nonce=to_bytes(kwargs.get("nonce", iv)),
                                            tag=to_bytes(kwargs.get("tag", b""))),
                               "block")
        except Exception as exc:                     # noqa: BLE001
            raise _ExprRefuse(f"{kind}.new: {exc}") from exc

    return build
