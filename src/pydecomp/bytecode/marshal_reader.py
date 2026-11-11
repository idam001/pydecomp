"""pydecomp - marshal_reader."""
from __future__ import annotations

from dataclasses import dataclass, field
import marshal
import struct

from ..bytecode.codeobj import CodeObj
from ..bytecode.version_score import _version_score

FLAG_REF = 0x80

class MarshalReader:
    """Reads marshal streams written by any CPython 3.8 – 3.15."""

    def __init__(self, data: bytes, version: tuple = (3, 13)):
        self.d = data
        self.i = 0
        self.refs: list = []
        self.version = version

    # -- primitives ------------------------------------------------------
    def byte(self) -> int:
        if self.i >= len(self.d):
            raise ValueError("truncated stream")
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n: int) -> bytes:
        v = self.d[self.i:self.i + n]
        if len(v) != n:
            raise ValueError("truncated stream")
        self.i += n
        return v

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    # -- object graph ----------------------------------------------------
    def object(self):
        start = self.i
        flag = self.byte()
        slot = None
        if flag & FLAG_REF:
            slot = len(self.refs)
            self.refs.append(None)
        tag = chr(flag & ~FLAG_REF)
        if tag in ("0", "N"):
            obj = None
        elif tag == "F":
            obj = False
        elif tag == "T":
            obj = True
        elif tag == "S":
            obj = StopIteration
        elif tag == ".":
            obj = Ellipsis
        elif tag == "i":
            obj = self.i32()
        elif tag == "I":
            obj = self.i64()
        elif tag == "l":
            n = self.i32()
            neg = n < 0
            val = 0
            for k in range(abs(n)):
                val |= struct.unpack("<H", self.take(2))[0] << (15 * k)
            obj = -val if neg else val
        elif tag == "g":
            obj = struct.unpack("<d", self.take(8))[0]
        elif tag == "y":
            real = struct.unpack("<d", self.take(8))[0]
            imag = struct.unpack("<d", self.take(8))[0]
            obj = complex(real, imag)
        elif tag in ("s", "t"):
            obj = self.take(self.i32())
        elif tag in ("u", "a", "A"):
            obj = self.take(self.i32()).decode("utf-8", "surrogatepass")
        elif tag in ("z", "Z"):
            obj = self.take(self.byte()).decode("utf-8", "surrogatepass")
        elif tag == "r":
            idx = self.i32()
            obj = self.refs[idx] if 0 <= idx < len(self.refs) else None
        elif tag == ")":
            obj = tuple(self.object() for _ in range(self.byte()))
        elif tag == "(":
            obj = tuple(self.object() for _ in range(self.i32()))
        elif tag == "[":
            obj = [self.object() for _ in range(self.i32())]
        elif tag == "{":
            obj = {}
            while self.i < len(self.d):
                if self.d[self.i] == ord("0"):
                    self.i += 1
                    break
                key = self.object()
                obj[key] = self.object()
        elif tag in ("<", ">"):
            vals = [self.object() for _ in range(self.i32())]
            obj = set(vals) if tag == "<" else frozenset(vals)
        elif tag == "c":
            obj = self.read_code()
        elif tag == ":":
            obj = ("slice", self.object(), self.object(), self.object())
        else:
            raise ValueError(f"unknown marshal tag {tag!r} at offset {start}")
        if slot is not None:
            self.refs[slot] = obj
        return obj

    def read_code(self) -> CodeObj:
        c = CodeObj()
        minor = self.version[1]
        c.argcount = self.i32()
        if minor >= 8:
            c.posonly = self.i32()
        c.kwonly = self.i32()
        if minor < 11:
            self.i32()                                   # nlocals
        c.stacksize = self.i32()
        c.flags = self.i32()
        c.code = self.object()
        c.consts = self.object()
        c.names = self.object()
        if minor >= 11:
            c.varnames = self.object()
            c.kinds = self.object()
        else:
            c.varnames = self.object()
            self.object()                                # cellvars
            self.object()                                # freevars
        c.filename = self.object()
        c.name = self.object()
        if minor >= 11:
            c.qualname = self.object()
        c.firstlineno = self.i32()
        c.linetable = self.object()
        if minor >= 11:
            c.exceptiontable = self.object()
        # identifiers are always text, whichever tag the writer chose
        for table in ("names", "varnames"):
            values = getattr(c, table, None)
            if isinstance(values, (list, tuple)):
                setattr(c, table, tuple(
                    bytes(item).decode("utf-8", "surrogateescape")
                    if isinstance(item, (bytes, bytearray)) else item
                    for item in values))
        for field in ("name", "qualname", "filename"):
            value = getattr(c, field, None)
            if isinstance(value, (bytes, bytearray)):
                setattr(c, field, bytes(value).decode("utf-8", "surrogateescape"))
        return c

def parse_marshal_blob(data: bytes):
    """Decode a bare marshal stream and work out which CPython wrote it."""
    candidates = []
    layouts = [(3, 15), (3, 14), (3, 13), (3, 12), (3, 11), (3, 10), (3, 9), (3, 8)]
    for version in layouts:
        try:
            reader = MarshalReader(data, version)
            obj = reader.object()
        except Exception:
            continue
        if not isinstance(obj, CodeObj):
            continue
        layout_ok = reader.i / max(len(data), 1)
        if layout_ok < 0.999:
            continue
        candidates.append((version, obj, layout_ok))
    if not candidates:
        return None, None, 0.0
    scored = [(obj, layout_ok, _version_score(obj, version), version)
              for version, obj, layout_ok in candidates]
    scored.sort(key=lambda item: (item[2], item[1]), reverse=True)
    obj, layout_ok, bytecode_score, version = scored[0]
    if len(scored) > 1 and abs(scored[0][2] - scored[1][2]) < 1e-9:
        version = scored[0][3]
    clean = bytecode_score > -10
    if not clean and len(scored) > 1 and scored[0][2] - scored[1][2] > 50:
        clean = True                                 # clearly the best decode
    if not clean:
        return None, None, 0.0
    return version, obj, layout_ok

def iter_code(code: CodeObj):
    """Depth-first walk over a code object and every nested code object."""
    yield code
    for const in code.consts:
        if isinstance(const, CodeObj):
            yield from iter_code(const)

class _MarshalProxy:
    """``marshal`` that also understands streams from *other* CPython versions."""

    def __init__(self):
        self.version = None

    def loads(self, data, *args, **kwargs):
        try:
            return marshal.loads(data)
        except Exception:                            # noqa: BLE001 - other version
            pass
        blob = bytes(data) if isinstance(data, (bytes, bytearray)) else None
        if blob is not None:
            version, code, _share = parse_marshal_blob(blob)
            if code is not None:
                self.version = version
                return code
        raise ValueError("not marshal data")

    def load(self, handle, *args, **kwargs):
        return self.loads(handle.read())

    def dumps(self, obj, *args, **kwargs):
        return marshal.dumps(obj)
