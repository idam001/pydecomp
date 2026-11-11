"""pydecomp - namespace."""
from __future__ import annotations

import sys

from ..core.util import to_bytes
from ..crypto.modes import MODE_CBC, MODE_CFB, MODE_CTR, MODE_ECB, MODE_GCM, MODE_OFB
from ..crypto.shims import _BlockCipher, _ExprCipher, _expr_cipher_new
from ..eval.builtins import _safe_builtin
from ..exceptions import _ExprRefuse

class _NameSpace:
    """``globals()`` / ``__builtins__`` / ``vars()`` as a live dict-like view.

    Obfuscators hide the entry point behind a computed subscript -
    ``globals()['ex'+'ec']``, ``__builtins__['\x65xec']`` - and a plain dict
    would simply raise ``KeyError``.  This view resolves those names against
    the engine namespace and the defused builtin table.
    """

    def __init__(self, engine, label: str = "globals") -> None:
        self._engine = engine
        self._label = label
        self._data: dict = {}

    # -- resolution -------------------------------------------------------
    def _resolve(self, key):
        if isinstance(key, (bytes, bytearray)):
            key = key.decode("utf-8", "replace")
        if not isinstance(key, str):
            raise _ExprRefuse("non-string key")
        if key in self._data:
            return self._data[key]
        if key in self._engine.ns:
            return self._engine.ns[key]
        return _safe_builtin(key, self._engine)

    # -- dict protocol ----------------------------------------------------
    def __getitem__(self, key):
        return self._resolve(key)

    def __setitem__(self, key, value):
        if isinstance(key, (bytes, bytearray)):
            key = key.decode("utf-8", "replace")
        self._data[key] = value

    def __delitem__(self, key):
        self._data.pop(key, None)

    def __contains__(self, key):
        try:
            self._resolve(key)
        except Exception:
            return False
        return True

    def __iter__(self):
        return iter(dict.fromkeys(list(self._data) + list(self._engine.ns)))

    def __len__(self):
        return len(set(self._data) | set(self._engine.ns))

    def __getattr__(self, item):
        if item.startswith("_"):
            raise AttributeError(item)
        try:
            return self._resolve(item)
        except _ExprRefuse as exc:
            raise AttributeError(item) from exc

    def get(self, key, default=None):
        try:
            return self._resolve(key)
        except Exception:
            return default

    def keys(self):
        return list(iter(self))

    def values(self):
        return [self.get(k) for k in self.keys()]

    def items(self):
        return [(k, self.get(k)) for k in self.keys()]

    def setdefault(self, key, default=None):
        if key not in self._data:
            self._data[key] = default
        return self._data[key]

    def update(self, other=(), **kwargs):
        if hasattr(other, "items"):
            other = other.items()
        for key, value in other:
            self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    def pop(self, key, *default):
        if key in self._data:
            return self._data.pop(key)
        if default:
            return default[0]
        raise KeyError(key)

    def copy(self):
        out = {}
        out.update(self._data)
        for key in self._engine.ns:
            out.setdefault(key, self._engine.ns[key])
        return out

    def __repr__(self) -> str:
        return f"<pydecomp {self._label} {self._data!r}>"

class _CryptoModule:
    """`Crypto.Cipher.AES` and `cryptography.hazmat.primitives.ciphers`."""

    def __init__(self, engine, path=""):
        self._engine = engine
        self._path = path

    _CIPHERS = ("AES", "DES", "DES3", "ARC4", "ChaCha20", "Blowfish", "CAST", "Salsa20")

    def __getattr__(self, item):
        if item.startswith("_"):
            raise AttributeError(item)
        if item == "new" and self._path in self._CIPHERS:
            return _expr_cipher_new(self._path)
        if item in self._CIPHERS:
            return _CryptoModule(self._engine, item)
        if item.startswith("MODE_"):
            value = getattr(sys.modules[__name__], item, None)
            if value is None:
                raise _ExprRefuse(f"mode {item}")
            return value
        if item in ("block_size", "key_size"):
            return 8 if self._path in ("DES", "DES3") else 16
        if item == "Cipher":
            return self._cipher_factory
        if item in ("algorithms", "modes", "primitives", "hazmat", "ciphers"):
            return _CryptoModule(self._engine, self._path + "." + item)
        if item == "import_module":
            return self._engine.import_module
        if self._path.endswith("algorithms") and item in ("AES", "TripleDES", "ARC4"):
            return _AlgorithmHandle(item, self._engine)
        if self._path.endswith("modes") and item in ("CBC", "ECB", "CTR", "OFB", "CFB", "GCM"):
            return _ModeHandle(item, self._engine)
        raise _ExprRefuse(f"crypto.{item}")

    def _cipher_factory(self, algorithm, mode):
        try:
            return _DecryptorFactory(algorithm, mode)
        except Exception as exc:                     # noqa: BLE001
            raise _ExprRefuse(f"Cipher: {exc}") from exc

    def __call__(self, *args, **kwargs):
        raise _ExprRefuse("crypto call")

class _AlgorithmHandle:
    def __init__(self, name, engine):
        self.name = name
        self.engine = engine

    def __call__(self, key, *args, **kwargs):
        return ("alg", self.name, to_bytes(key))

class _ModeHandle:
    def __init__(self, name, engine):
        self.name = name
        self.engine = engine

    def __call__(self, iv=b"", *args, **kwargs):
        return ("mode", self.name, to_bytes(iv) or to_bytes(kwargs.get("nonce", b"")))

class _DecryptorFactory:
    """`Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()`."""

    def __init__(self, algorithm, mode):
        kind, _name, key = algorithm
        _tag, mode_name, iv = mode
        inner = _BlockCipher(key, {"CBC": MODE_CBC, "ECB": MODE_ECB, "CTR": MODE_CTR,
                                   "OFB": MODE_OFB, "CFB": MODE_CFB,
                                   "GCM": MODE_GCM}.get(mode_name, MODE_CBC), iv=iv)
        self._cipher = _ExprCipher(inner)

    def decryptor(self, *args, **kwargs):
        return self._cipher

    def encryptor(self, *args, **kwargs):
        raise _ExprRefuse("encryption")

    def __getattr__(self, item):
        raise _ExprRefuse(f"Cipher.{item}")

class _BuiltinsModule:
    """`import builtins` — a view where exec/eval are capture sentinels."""

    def __init__(self, engine):
        self._engine = engine

    def __getattr__(self, item):
        if item.startswith("__") and item not in ("__dict__", "__name__"):
            raise AttributeError(item)
        if item == "__dict__":
            return self._engine._builtins_view
        return _safe_builtin(item, self._engine)

    def __getitem__(self, item):
        return _safe_builtin(item, self._engine)

    def __repr__(self):
        return "<pydecomp builtins>"

class _ImportlibModule:
    """A stand-in for the importlib entry points samples use."""

    def __init__(self, engine):
        self._engine = engine

    def import_module(self, name, *args, **kwargs):
        return self._engine.import_module(name)

    def reload(self, module, *args, **kwargs):
        return module

    def __getattr__(self, item):
        if item in ("import_module", "reload"):
            return getattr(self, item)
        if item in ("util", "machinery", "abc", "sys"):
            return _CryptoModule(self._engine, item)
        raise _ExprRefuse(f"importlib.{item}")

class _FakeSys:
    """A ``sys`` that reports the interpreter an obfuscator gates on.

    ``str(sys.version[0:4]) == '3.14'`` is the cheapest anti-analysis trick
    there is; emulating the target version is honest static work - nothing of
    the sample is executed.
    """

    version = "3.14.0 (main, Oct  7 2025, 00:00:00) [GCC 13.2.0]"
    version_info = (3, 14, 0, "final", 0)
    platform = "linux"
    maxsize = 2 ** 63 - 1
    byteorder = "little"
    hexversion = 0x030E00F0

    def getrecursionlimit(self):
        return 1000

    def getdefaultencoding(self):
        return "utf-8"
