"""pydecomp - whitelist."""
from __future__ import annotations

from typing import Any, Iterable
import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import hmac
import json
import lzma
import zlib

from ..core.util import _cap, _inflate, to_bytes
from ..decoders.base45_codec import b45decode
from ..decoders.base58_codec import b58decode
from ..decoders.base91_codec import b91decode
from ..exceptions import EvalFailed
from ..limits import MAX_DECOMPRESSED

def _mk_whitelist() -> dict[str, tuple[Any, str]]:
    w: dict[str, tuple[Any, str]] = {}

    def add(names: Iterable[str], fn: Any, label: str) -> None:
        for n in names:
            w[n] = (fn, label)

    def _b64_any(s, *a, **k):
        """b64, url-safe b64, with or without padding.

        Loaders are sloppy in exactly three ways, and all three used to make the
        static evaluator give up on a chain it could have finished: they use the
        url-safe alphabet and call the plain decoder, they call the url-safe
        decoder on plain text, and they strip the '=' padding (often to fit the
        blob on one line).  Accepting all of it costs an alphabet swap and a
        pad; refusing it loses the payload.
        """
        data = to_bytes(s).strip()
        data = data.replace(b"-", b"+").replace(b"_", b"/")
        data += b"=" * (-len(data) % 4)
        return base64.b64decode(data, validate=False)

    add(["base64.b64decode", "base64.standard_b64decode",
         "base64.urlsafe_b64decode", "binascii.a2b_base64"], _b64_any, "base64")

    def _b32_any(s, *a, **k):
        data = to_bytes(s).strip()
        return base64.b32decode(data + b"=" * (-len(data) % 8))

    add(["base64.b32decode", "base64.b32hexdecode", "binascii.a2b_base32"],
        _b32_any, "base32")
    add(["base64.b16decode", "binascii.a2b_hex", "binascii.unhexlify"],
        lambda s, *a, **k: base64.b16decode(to_bytes(s).upper()),
        "base16")
    add(["base64.b85decode"], lambda s, *a, **k: base64.b85decode(to_bytes(s)),
        "base85")
    add(["base64.a85decode", "base64.ascii85decode"],
        lambda s, *a, **k: base64.a85decode(to_bytes(s)),
        "ascii85")
    def _zlib_any(s, wbits=15, *a, **k):
        """zlib, raw deflate and gzip all hide behind `zlib.decompress`."""
        data = to_bytes(s)
        attempts = []
        if isinstance(wbits, int) and wbits not in (15, 0):
            attempts.append(wbits)
        attempts += [15, -15, 47, 31]
        last = None
        for bits in attempts:
            try:
                obj = zlib.decompressobj(bits)
                out = obj.decompress(data, MAX_DECOMPRESSED + 1)
                if len(out) > MAX_DECOMPRESSED or obj.unconsumed_tail:
                    raise EvalFailed("zlib output exceeds size cap")
                return _cap(out + obj.flush())
            except Exception as exc:                 # noqa: BLE001 - try the next window
                last = exc
        raise EvalFailed(f"zlib: {last}")

    add(["zlib.decompress", "zlib.decompressobj.decompress"], _zlib_any, "zlib")
    add(["bz2.decompress"], lambda s, *a, **k: _inflate(bz2, s), "bz2")
    def _lzma_any(s, *a, **k):
        """xz, lzma-alone and raw streams all show up in the wild."""
        data = to_bytes(s)
        attempts = [None, lzma.FORMAT_ALONE, lzma.FORMAT_XZ]
        for fmt in attempts:
            try:
                if fmt is None:
                    return _inflate(lzma, data)
                return _cap(lzma.LZMADecompressor(fmt).decompress(data, MAX_DECOMPRESSED + 1))
            except Exception:                        # noqa: BLE001 - try the next format
                continue
        for dict_size in (1 << 16, 1 << 20, 1 << 23):
            filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3,
                        "lp": 0, "pb": 2}]
            try:
                return _cap(lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
                            .decompress(data, MAX_DECOMPRESSED + 1))
            except Exception:                        # noqa: BLE001 - try the next filter
                continue
        raise EvalFailed("lzma: no format matched")

    add(["lzma.decompress"], _lzma_any, "lzma")
    add(["gzip.decompress"], lambda s, *a, **k: _inflate(gzip, s), "gzip")

    def _codecs_decode(v, enc="utf-8", *a, **k):
        # codecs.decode() on a str uses the codec's text->text path (rot13 et al.)
        if isinstance(v, str):
            return _cap(codecs.decode(v, enc))
        return _cap(codecs.decode(to_bytes(v), enc))

    add(["codecs.decode"], _codecs_decode, "codecs")

    def _fromhex(s, *a, **k):
        if isinstance(s, str):
            return bytes.fromhex(s)
        raise EvalFailed("fromhex on non-str")

    add(["bytes.fromhex", "bytearray.fromhex"], _fromhex, "hexstr")

    def _rot13(s, *a, **k):
        return codecs.encode(s if isinstance(s, str) else to_bytes(s).decode("latin-1"), "rot13")

    add(["codecs.encode"], _rot13, "rot13")
    add(["base64.b58decode", "base58.b58decode", "base58.b58decode_check"],
        lambda s, *a, **k: b58decode(s), "base58")
    add(["base64.b45decode"], lambda s, *a, **k: b45decode(s), "base45")
    add(["base91.b91decode"], lambda s, *a, **k: b91decode(s), "base91")
    add(["base64.b64encode", "base64.standard_b64encode"],
        lambda s, *a, **k: base64.b64encode(to_bytes(s)), "b64encode")
    add(["base64.urlsafe_b64encode"],
        lambda s, *a, **k: base64.urlsafe_b64encode(to_bytes(s)), "b64urlencode")
    add(["base64.b32encode"], lambda s, *a, **k: base64.b32encode(to_bytes(s)), "b32encode")
    add(["base64.b85encode"], lambda s, *a, **k: base64.b85encode(to_bytes(s)), "b85encode")
    add(["binascii.hexlify"], lambda s, *a, **k: binascii.hexlify(to_bytes(s)), "hexlify")
    add(["binascii.unhexlify"], lambda s, *a, **k: binascii.unhexlify(to_bytes(s)), "unhexlify")

    def _pbkdf2(hash_name, password, salt, iterations=100000, dklen=None, *a, **k):
        if not isinstance(hash_name, str):
            raise EvalFailed("pbkdf2 hash name must be a string")
        return hashlib.pbkdf2_hmac(hash_name, to_bytes(password), to_bytes(salt),
                                   min(int(iterations), 4_000_000),
                                   int(dklen or 0) or None)

    add(["hashlib.pbkdf2_hmac"], _pbkdf2, "pbkdf2")

    def _hmac_new(key, msg=b"", digestmod=None, *a, **k):
        name = digestmod if isinstance(digestmod, str) else "sha256"
        return hmac.new(to_bytes(key), to_bytes(msg), name).digest()

    add(["hmac.new", "hmac.HMAC"], _hmac_new, "hmac")
    add(["json.loads"], lambda s, *a, **k: json.loads(s if isinstance(s, str)
                                                      else to_bytes(s).decode()), "json")
    add(["zlib.crc32"], lambda s, *a, **k: zlib.crc32(to_bytes(s)), "crc32")
    add(["int.from_bytes"], lambda b, order="big", *a, **k: int.from_bytes(to_bytes(b), order),
        "from_bytes")
    return w

WHITELIST = _mk_whitelist()

MODULE_NAMES = {"base64", "binascii", "zlib", "bz2", "lzma", "gzip", "codecs",
                "marshal", "builtins", "os", "sys", "hashlib", "hmac", "json",
                "base58", "base91", "operator", "struct", "itertools"}

def _builtin_chr(value):
    return chr(int(value))

def _builtin_ord(value):
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 1:
            raise EvalFailed("ord() wants exactly one byte")
        return value[0]
    return ord(value)

def _builtin_bytes(value=0, *args, **kwargs):
    if isinstance(value, str):
        return value.encode(args[0] if args else "utf-8")
    if isinstance(value, int):
        return bytes(value if not args else [0] * value)
    return bytes(value)

def _builtin_map(func, seq, *rest):
    if not rest:
        return [func(item) for item in seq]
    return [func(*items) for items in zip(seq, *rest)]

def _builtin_int(value, *args, **kwargs):
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(bytes(value), args[0] if args else "big")
    return int(value, *args)

def _from_bytes(value, byteorder="big", **kwargs):
    return int.from_bytes(bytes(value), byteorder)

def _int_to_bytes(value, length=None, byteorder="big"):
    if length is None:
        length = max(1, (int(value).bit_length() + 7) // 8)
    return int(value).to_bytes(length, byteorder)

def _builtin_compile(source, filename="<string>", mode="exec", *a, **k):
    """Static `compile(src, name, 'exec')` -> the source itself.

    Attack scripts compile the payload and exec the code object a few lines
    later.  Following the string instead of the code object keeps every check
    in this file honest: nothing is ever compiled or executed here.
    """
    if mode not in ("exec", "eval", "single"):
        raise EvalFailed(f"compile mode {mode!r}")
    return source

BUILTINS = {
    "compile": _builtin_compile,
    "chr": _builtin_chr,
    "ord": _builtin_ord,
    "bytes": _builtin_bytes,
    "bytearray": lambda v=b"", *a, **k: bytearray(_builtin_bytes(v, *a, **k)),
    "int": _builtin_int,
    "len": len,
    "sum": lambda seq, start=0, **k: sum(seq, start),
    "list": lambda seq=(), **k: list(seq),
    "tuple": lambda seq=(), **k: tuple(seq),
    "range": lambda *a, **k: range(*[int(x) for x in a]),
    "map": _builtin_map,
    "filter": lambda f, seq: [x for x in seq if f(x)],
    "reversed": lambda seq: list(reversed(seq)),
    "enumerate": lambda seq, start=0: list(enumerate(seq, start)),
    "zip": lambda *seq: [list(t) for t in zip(*seq)],
    "sorted": lambda seq, **k: sorted(seq),
    "min": min,
    "max": max,
    "abs": abs,
    "str": lambda v="", *a, **k: str(v),
    "repr": repr,
    "bool": bool,
    "all": all,
    "any": any,
    "hex": lambda v: hex(int(v)),
    "oct": lambda v: oct(int(v)),
    "bin": lambda v: bin(int(v)),
    "pow": pow,
    "divmod": divmod,
    "dict": lambda *a, **k: dict(*a, **k),
    "set": lambda seq=(): list(dict.fromkeys(seq)),
    "frozenset": lambda seq=(): list(dict.fromkeys(seq)),
}

METHOD_NAMES_EXTRA = {
    "to_bytes": _int_to_bytes,
    "from_bytes": _from_bytes,
    # a base-N loader computes its own byte length from the number it built:
    # `n.to_bytes((n.bit_length() + 7) // 8, "big")` is the standard spelling, and
    # refusing `.bit_length()` stopped the chain one call short of the payload
    "bit_length": lambda v: int(v).bit_length(),
    "bit_count": lambda v: int(v).bit_count(),
}
