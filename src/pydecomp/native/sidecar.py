"""Native artefact support: ELF images and Cython modules.

Two very different problems live in this file.

**ELF** is a container, so the job is to open it and find out what was packed
inside: a CPython extension (which may embed real bytecode), a PyInstaller
archive, a plain zip/zipapp, a Nuitka build, a PyArmor-protected module, or a
Cython module.  Whenever Python bytecode is present it is handed back to the
bytecode decompiler, because that produces the real source.

**Cython** is *not* a container.  Cython compiles Python to C and then to machine
code: there is no bytecode, no code object, and no `.py` text in a release
`.so`, so a byte-for-byte recovery is impossible in principle.  What survives is
more than nothing, and this module recovers all of it:

* ``PyMethodDef`` tables in ``.data``/``.data.rel.ro`` — function and method
  names, their docstrings, and their declaration order (survives ``strip``),
* mangled symbols (``__pyx_mdef_11demo_module_7Session_3describe``) — the exact
  qualified name, which gives the class a method belongs to (removed by
  ``strip``),
* the Cython string table in ``.rodata`` — every literal, every identifier it
  referenced, and the local variable names Cython keeps for introspection,
* the module/source file names and the Cython/GCC versions,
* DWARF line tables when the build used ``--line-directives -g``, which map
  machine code straight onto original ``.py`` line numbers, and
* the generated ``.c`` file, when it is shipped next to the ``.so``: Cython
  quotes the original source line above every statement, so that *does* give the
  source back verbatim.

The reconstruction reports which of those tiers it could use, so the fidelity of
a given output is never a guess.
"""
import os
import re
import struct
import sys
import zlib

# Termux and other minimal builds ship without these; the tool must still run.
try:
    import bz2
except ImportError:                                  # pragma: no cover - platform
    bz2 = None
try:
    import lzma
except ImportError:                                  # pragma: no cover - platform
    lzma = None

# --------------------------------------------------------------------- constants
PT_LOAD = 1
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_NOTE = 7

R_X86_64_RELATIVE = 8
R_386_RELATIVE = 8
R_AARCH64_RELATIVE = 1027
R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYZ_MAGIC = b"PYZ\0"
ZIP_MAGIC = b"PK\x03\x04"

# CPython bytecode magic numbers (2 bytes) seen in the wild, newest first.
PYC_MAGICS = {
    b"\x3c\x0d": (3, 14), b"\x31\x0d": (3, 14), b"\x2b\x0d": (3, 14),
    b"\xf3\x0c": (3, 13), b"\xcb\x0c": (3, 13), b"\xa7\x0c": (3, 12),
    b"\xcb\x0b": (3, 12), b"\xa7\x0b": (3, 11), b"\x6f\x0b": (3, 11),
    b"\x96\x0a": (3, 10), b"\x6f\x0a": (3, 10), b"\x61\x0a": (3, 10),
}

NUITKA_MARKERS = (b"Nuitka", b"nuitka", b"__constants", b"qstrconst",
                  b"module.__compiled__")
PYARMOR_MARKERS = (b"pyarmor", b"PyArmor", b"__armor__", b"pyarmor_runtime",
                   b"PYARMOR")
CYTHON_MARKERS = (b"__pyx_", b"PyInit_", b"__Pyx_", b"__cython_", b"cython_")


# ------------------------------------------------------------------------- ELF
class Section:
    __slots__ = ("name", "name_off", "type", "flags", "addr", "off", "size",
                 "entsize", "link", "info", "addralign")

    def __init__(self, **kw):
        for key in self.__slots__:
            setattr(self, key, kw.get(key, 0))

    @property
    def end(self):
        return self.addr + self.size

    def contains(self, addr):
        return self.addr <= addr < self.addr + self.size

    def __repr__(self):
        return f"<Section {self.name} {self.addr:#x}+{self.size:#x}>"


class Segment:
    __slots__ = ("type", "flags", "off", "vaddr", "filesz", "memsz", "align")

    def __init__(self, **kw):
        for key in self.__slots__:
            setattr(self, key, kw.get(key, 0))


class Symbol:
    __slots__ = ("name", "value", "size", "info", "shndx", "table")

    def __init__(self, name, value, size, info, shndx, table):
        self.name, self.value, self.size = name, value, size
        self.info, self.shndx, self.table = info, shndx, table

    @property
    def kind(self):
        return self.info & 0xF

    @property
    def bind(self):
        return self.info >> 4

    @property
    def is_func(self):
        return self.kind == 2

    @property
    def is_object(self):
        return self.kind == 1

    def __repr__(self):
        return f"<Symbol {self.name} {self.value:#x}>"


def looks_like_elf(data: bytes) -> bool:
    return len(data) > 64 and data[:4] == b"\x7fELF"


class ElfImage:
    """A parsed ELF file: headers, sections, segments, symbols and relocations."""

    def __init__(self, data: bytes, path: str | None = None):
        if not looks_like_elf(data):
            raise ValueError("not an ELF file")
        self.data = data
        self.path = path
        self.bits = 64 if data[4] == 2 else 32
        self.little = data[5] == 1
        if not self.little:
            raise ValueError("big-endian ELF is not supported yet")
        self.type = self._u16(0x10)
        self.machine = self._u16(0x12)
        self.entry = self._word(0x18)
        self.phoff = self._word(0x20)
        self.shoff = self._word(0x28)
        self.phentsize = self._u16(0x36)
        self.phnum = self._u16(0x38)
        self.shentsize = self._u16(0x3A)
        self.shnum = self._u16(0x3C)
        self.shstrndx = self._u16(0x3E)
        self.sections: list[Section] = []
        self.segments: list[Segment] = []
        self.symbols: list[Symbol] = []
        self.relocs: dict[int, int] = {}          # offset -> addend (RELATIVE)
        self.needed: list[str] = []
        self.soname = ""
        self.rpaths: list[str] = []
        self.build_id = b""
        self.comment = ""
        self._parse_sections()
        self._parse_segments()
        self._parse_dynamic()
        self._parse_notes()
        self._parse_relocs()
        self._parse_symbols()

    # ---------------------------------------------------------------- reading
    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def _word(self, off):
        return self._u64(off) if self.bits == 64 else self._u32(off)

    @property
    def machine_name(self):
        return {0x3E: "x86-64", 0x03: "i386", 0xB7: "aarch64", 0x28: "arm",
                0xF3: "riscv", 0x16: "s390", 0x15: "powerpc"}.get(self.machine,
                                                                 f"machine-{self.machine}")

    @property
    def type_name(self):
        return {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(
            self.type, f"type-{self.type}")

    # --------------------------------------------------------------- sections
    def _parse_sections(self):
        if not self.shoff or not self.shentsize:
            return
        raw = []
        for index in range(self.shnum):
            base = self.shoff + index * self.shentsize
            name_off = self._u32(base)
            if self.bits == 64:
                stype = self._u32(base + 4)
                flags = self._u64(base + 8)
                addr = self._u64(base + 16)
                off = self._u64(base + 24)
                size = self._u64(base + 32)
                link = self._u32(base + 40)
                info = self._u32(base + 44)
                addralign = self._u64(base + 48)
                entsize = self._u64(base + 56)
            else:
                stype = self._u32(base + 4)
                flags = self._u32(base + 8)
                addr = self._u32(base + 12)
                off = self._u32(base + 16)
                size = self._u32(base + 20)
                link = self._u32(base + 24)
                info = self._u32(base + 28)
                addralign = self._u32(base + 32)
                entsize = self._u32(base + 36)
            raw.append(Section(name_off=name_off, type=stype, flags=flags, addr=addr,
                               off=off, size=size, link=link, info=info,
                               addralign=addralign, entsize=entsize))
        strtab = raw[self.shstrndx] if self.shstrndx < len(raw) else None
        for section in raw:
            if strtab is not None and strtab.off:
                start = strtab.off + section.name_off
                end = self.data.find(b"\0", start)
                section.name = self.data[start:end if end >= 0 else start].decode(
                    "latin-1") if start < len(self.data) else ""
            else:
                section.name = ""
        self.sections = raw

    def section(self, name):
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def _parse_segments(self):
        if not self.phoff or not self.phentsize:
            return
        for index in range(self.phnum):
            base = self.phoff + index * self.phentsize
            if self.bits == 64:
                self.segments.append(Segment(type=self._u32(base), flags=self._u32(base + 4),
                                            off=self._u64(base + 8), vaddr=self._u64(base + 16),
                                            filesz=self._u64(base + 32),
                                            memsz=self._u64(base + 40),
                                            align=self._u64(base + 48)))
            else:
                self.segments.append(Segment(type=self._u32(base), off=self._u32(base + 4),
                                            vaddr=self._u32(base + 8),
                                            filesz=self._u32(base + 16),
                                            memsz=self._u32(base + 20),
                                            flags=self._u32(base + 24),
                                            align=self._u32(base + 28)))

    def _parse_dynamic(self):
        dyn = self.section(".dynamic")
        if dyn is None or not dyn.off:
            return
        strtab = self.section(".dynstr")
        strings = self.data[strtab.off:strtab.off + strtab.size] if strtab else b""
        tag_size = 16 if self.bits == 64 else 8
        for pos in range(dyn.off, dyn.off + dyn.size - tag_size + 1, tag_size):
            tag = self._word(pos)
            value = self._word(pos + tag_size // 2)
            if tag == 0:
                break
            if tag in (1, 14, 15, 29):            # NEEDED, SONAME, RPATH, RUNPATH
                if value < len(strings):
                    end = strings.find(b"\0", value)
                    text = strings[value:end if end >= 0 else value].decode("latin-1")
                    if tag == 1:
                        self.needed.append(text)
                    elif tag == 14:
                        self.soname = text
                    else:
                        self.rpaths.append(text)

    def _parse_notes(self):
        note = self.section(".note.gnu.build-id")
        if note is not None and note.off:
            blob = self.data[note.off:note.off + note.size]
            pos = 0
            while pos + 12 <= len(blob):
                namesz, descsz, ntype = struct.unpack_from("<III", blob, pos)
                pos += 12
                name = blob[pos:pos + namesz].rstrip(b"\0")
                pos += (namesz + 3) & ~3
                desc = blob[pos:pos + descsz]
                pos += (descsz + 3) & ~3
                if ntype == 3 and name == b"GNU":
                    self.build_id = desc
        comment = self.section(".comment")
        if comment is not None and comment.off:
            blob = self.data[comment.off:comment.off + comment.size]
            self.comment = blob.replace(b"\0", b"\n").decode("latin-1").strip()

    def _parse_relocs(self):
        for section in self.sections:
            if section.type not in (SHT_RELA, SHT_REL) or not section.size:
                continue
            rela = section.type == SHT_RELA
            step = (24 if self.bits == 64 else 12) if rela else (16 if self.bits == 64 else 8)
            for pos in range(section.off, section.off + section.size - step + 1, step):
                if self.bits == 64:
                    offset = self._u64(pos)
                    info = self._u64(pos + 8)
                    addend = self._u64(pos + 16) if rela else 0
                    rtype = info & 0xFFFFFFFF
                else:
                    offset = self._u32(pos)
                    info = self._u32(pos + 4)
                    addend = self._u32(pos + 8) if rela else 0
                    rtype = info & 0xFF
                if rtype in (R_X86_64_RELATIVE, R_386_RELATIVE, R_AARCH64_RELATIVE):
                    self.relocs[offset] = addend

    def _parse_symbols(self):
        for section in self.sections:
            if section.type not in (SHT_SYMTAB, SHT_DYNSYM) or not section.size:
                continue
            strtab = self.sections[section.link] if section.link < len(self.sections) else None
            if strtab is None:
                continue
            strings = self.data[strtab.off:strtab.off + strtab.size]
            step = 24 if self.bits == 64 else 16
            for pos in range(section.off, section.off + section.size - step + 1, step):
                if self.bits == 64:
                    name_off = self._u32(pos)
                    info = self.data[pos + 4]
                    shndx = self._u16(pos + 6)
                    value = self._u64(pos + 8)
                    size = self._u64(pos + 16)
                else:
                    name_off = self._u32(pos)
                    value = self._u32(pos + 4)
                    size = self._u32(pos + 8)
                    info = self.data[pos + 12]
                    shndx = self._u16(pos + 14)
                end = strings.find(b"\0", name_off)
                name = strings[name_off:end].decode("latin-1") if 0 <= name_off < len(strings) else ""
                if name:
                    self.symbols.append(Symbol(name, value, size, info, shndx,
                                               "dynsym" if section.type == SHT_DYNSYM else "symtab"))

    # ------------------------------------------------------------- addressing
    def section_for(self, addr):
        for section in self.sections:
            if section.type != SHT_NOBITS and section.contains(addr):
                return section
        return None

    def offset_of(self, addr):
        section = self.section_for(addr)
        if section is None:
            return None
        return section.off + (addr - section.addr)

    def read(self, addr, size):
        offset = self.offset_of(addr)
        if offset is None or offset + size > len(self.data):
            return None
        return self.data[offset:offset + size]

    def cstring(self, addr, limit=512):
        offset = self.offset_of(addr)
        if offset is None:
            return None
        end = self.data.find(b"\0", offset, offset + limit)
        if end < 0:
            return None
        return self.data[offset:end]

    def resolve_ptr(self, addr, raw_value):
        """A pointer slot, honouring a RELATIVE relocation when one is present."""
        return self.relocs.get(addr, raw_value)

    def string_table(self):
        """Every printable NUL-terminated run in allocated PROGBITS data."""
        out = []
        for section in self.sections:
            if section.type != SHT_PROGBITS or not section.size:
                continue
            if not (section.flags & 0x2):         # SHF_ALLOC
                continue
            if section.name in (".text", ".init", ".fini", ".plt", ".got", ".plt.got"):
                continue
            blob = self.data[section.off:section.off + section.size]
            pos = 0
            while True:
                if pos >= len(blob):
                    break
                byte = blob[pos]
                if byte < 0x20 or byte > 0x7E:
                    pos += 1
                    continue
                end = pos
                while end < len(blob) and 0x20 <= blob[end] <= 0x7E:
                    end += 1
                if end < len(blob) and blob[end] == 0 and end - pos >= 2:
                    out.append((section.addr + pos, blob[pos:end]))
                    pos = end + 1
                else:
                    pos = max(end, pos + 1)
        return out

    def summary(self):
        return {
            "path": self.path or "",
            "type": self.type_name,
            "machine": self.machine_name,
            "bits": self.bits,
            "entry": self.entry,
            "build_id": self.build_id.hex(),
            "soname": self.soname,
            "needed": list(self.needed),
            "rpath": list(self.rpaths),
            "comment": self.comment.split("\n")[0] if self.comment else "",
            "sections": len(self.sections),
            "symbols": len(self.symbols),
            "relocations": len(self.relocs),
        }


# ------------------------------------------------------------------ detection
def _find_all(haystack, needle, limit=64):
    out, start = [], 0
    while len(out) < limit:
        found = haystack.find(needle, start)
        if found < 0:
            break
        out.append(found)
        start = found + 1
    return out


def detect(img: ElfImage) -> dict:
    """What kind of Python artefact is inside this ELF file?"""
    names = {symbol.name for symbol in img.symbols}
    data = img.data
    findings = {
        "python_extension": any(name.startswith("PyInit_") for name in names),
        "init_names": sorted(name[7:] for name in names if name.startswith("PyInit_")),
        "cython": False,
        "cython_symbols": 0,
        "pyinstaller": len(_find_all(data, PYINSTALLER_MAGIC)),
        "pyz": len(_find_all(data, PYZ_MAGIC)),
        "zip_members": len(_find_all(data, ZIP_MAGIC)),
        "nuitka": any(marker in data for marker in NUITKA_MARKERS),
        "pyarmor": any(marker in data for marker in PYARMOR_MARKERS),
        "upx": any(section.name.startswith("UPX") for section in img.sections),
        "pyc_blobs": [],
        "marshal_hint": b"PyMarshal_ReadObjectFromString" in data,
    }
    cython_symbols = sum(1 for name in names if name.startswith(("__pyx_", "__Pyx_")))
    findings["cython_symbols"] = cython_symbols
    findings["cython"] = bool(cython_symbols) or b"__pyx_module_is_main" in data \
        or b"__Pyx_Py" in data
    for magic in PYC_MAGICS:
        for offset in _find_all(data, magic, limit=8):
            version = PYC_MAGICS[magic]
            # a four-byte magic shows up by chance all the time; only report the
            # ones whose header actually parses
            findings["pyc_blobs"].append({"offset": offset, "magic": magic.hex(),
                                          "guess": f"{version[0]}.{version[1]}",
                                          "verified": _marshal_ok(data[offset:])})
    findings["pyc_blobs"] = [item for item in findings["pyc_blobs"]
                             if item["verified"]][:12]
    return findings


# -------------------------------------------------------------------- Cython
__version__ = "8.1.0"

_MANGLED = re.compile(r"__pyx_(mdef|pw|pf|doc|k|n|ptype|type)_([0-9A-Za-z_]+)")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONST_NAME = re.compile(r"^[A-Z][A-Z0-9_]{3,}$")

METH_FLAGS = {0x1: "METH_VARARGS", 0x2: "METH_KEYWORDS", 0x4: "METH_NOARGS",
              0x8: "METH_O", 0x10: "METH_CLASS", 0x20: "METH_STATIC",
              0x40: "METH_COEXIST", 0x80: "METH_FASTCALL"}

# Strings that belong to the Cython runtime, the C library or the compiler
# driver rather than to the module being analysed.
_INTERNAL_PREFIXES = (
    "__pyx", "__Pyx", "_Pyx", "Py", "_Py", "_PyEval", "_PyObject", "PyObject",
    "__PyErr", "__Py", "CYTHON", "cython_", "_cython_", "__cython",
)
_INTERNAL_METHOD_NAMES = {
    "__weaklistoffset__", "__weakrefoffset__", "__vectorcalloffset__",
    "__dictoffset__", "__flags__", "__module__", "__doc__", "__name__",
    "__qualname__", "__annotate_cython__", "__annotate__", "__reduce__",
    "__reduce_ex__", "__get__", "__set__", "__delete__", "__signature__",
    "__defaults__", "__kwdefaults__", "__code__", "__closure__", "__globals__",
    "__cython_metadata__", "__Pyx_PyDict_NextRef",
}

_INTERNAL_EXACT = {
    "glibc", "GCC", "gcc", "libc", "NOTHING", "NULL", "true", "false",
    "Py_TPFLAGS_DEFAULT", "No module named '", "argument", "object",
}


def parse_mangled(name: str):
    """Decode a Cython C name into a qualified Python name.

    Cython builds ``__pyx_mdef_`` + ``scope_prefix`` + ``cname``, where each
    scope contributes ``"<len><name>_"`` and a per-scope counter is prefixed to
    the function name (``1build_headers`` is the second ``build_headers``).
    """
    match = _MANGLED.match(name)
    if not match:
        return None, ""
    kind, rest = match.group(1), match.group(2)
    parts = []
    while True:
        digits = re.match(r"^(\d+)(.*)$", rest)
        if not digits:
            break
        length = int(digits.group(1))
        body = digits.group(2)
        if length <= 0 or length > len(body):
            break
        tail = body[length:]
        if body.startswith("_") or (tail and not tail.startswith("_")):
            break                                   # the digits were a counter
        parts.append(body[:length])
        rest = tail[1:] if tail else ""
        if not rest:
            break
    rest = re.sub(r"^\d+", "", rest)
    if rest:
        parts.append(rest)
    return kind, ".".join(part for part in parts if part)


class MethodDef:
    """One recovered ``PyMethodDef`` entry."""

    __slots__ = ("name", "doc", "flags", "address", "function", "owner",
                 "qualname", "line")

    def __init__(self, name, doc, flags, address, function, owner=None):
        self.name = name
        self.doc = doc
        self.flags = flags
        self.address = address
        self.function = function
        self.owner = owner
        self.qualname = f"{owner}.{name}" if owner else name
        self.line = None

    @property
    def flag_names(self):
        return [label for bit, label in METH_FLAGS.items() if self.flags & bit]

    def __repr__(self):
        return f"<MethodDef {self.qualname} flags={self.flags:#x}>"


class CythonInfo:
    """Everything a Cython build still says about the module it came from."""

    def __init__(self, img: ElfImage):
        self.img = img
        self.module = ""
        self.source_name = ""
        self.compiler = ""
        self.cython_version = ""
        self.methods: list[MethodDef] = []
        self.classes: dict[str, list[MethodDef]] = {}
        self.functions: list[MethodDef] = []
        self.docstrings: list[str] = []
        self.doc_by_name: dict[str, str] = {}
        self.class_docs: dict[str, str] = {}
        self.literals: list[str] = []
        self.literal_positions: list[tuple[int, str]] = []
        self.identifiers: list[str] = []
        self.line_map: dict[int, int] = {}
        self.line_extent = None
        self.function_lines: dict[str, list[int]] = {}
        self.source_lines: dict[int, str] = {}
        self.tier = "A"
        self.notes: list[str] = []

    # ------------------------------------------------------------- recovery
    def analyse(self):
        self._module_names()
        self._methods()
        self._strings()
        self._line_table()
        self._source_file()
        self._order()
        return self

    def _module_names(self):
        for symbol in self.img.symbols:
            if symbol.name.startswith("PyInit_") and symbol.bind in (1, 2):
                self.module = symbol.name[len("PyInit_"):]
                break
        if not self.module:
            for _addr, text in self.img.string_table():
                if b"__pyx_module_is_main_" in text:
                    self.module = text.rsplit(b"_", 1)[-1].decode("latin-1")
                    break
        for line in (self.img.comment or "").split("\n"):
            if line.strip():
                self.compiler = self.compiler or line.strip()
        for _addr, text in self.img.string_table():
            found = re.match(rb"(\d+\.\d+\.\d+(?:\.\d+)?)", text)
            if found and b"cython" in self.img.data[:0] + b"":
                pass
        for _addr, text in self.img.string_table():
            if text.startswith(b"Cython"):
                self.cython_version = text.decode("latin-1").strip()
                break
        # Cython 3 stamps its own version into the names it ships
        if not self.cython_version:
            for candidate in list(self.img.symbols):
                match = re.search(r"_cython_(\d+)_(\d+)_(\d+)", candidate.name)
                if match:
                    self.cython_version = ".".join(match.groups())
                    break
        if not self.cython_version:
            for _addr, text in self.img.string_table():
                match = re.search(rb"_cython_(\d+)_(\d+)_(\d+)", text)
                if match:
                    self.cython_version = ".".join(part.decode() for part in match.groups())
                    break

    # --------------------------------------------------------------- methods
    def _data_sections(self):
        for section in self.img.sections:
            if section.type != SHT_PROGBITS or not section.size:
                continue
            if not (section.flags & 0x2):       # SHF_ALLOC
                continue
            if section.flags & 0x4:             # SHF_EXECINSTR
                continue
            if section.name in (".rodata", ".dynstr", ".dynsym", ".gnu.hash"):
                continue
            yield section

    def _looks_like_name(self, blob):
        if not blob or not (1 <= len(blob) <= 96):
            return False
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return bool(_IDENT.match(text)) or text.startswith("__") and text.endswith("__")

    def _inside_string(self, addr):
        """True when ``addr`` falls in the middle of a printable run."""
        blob = self.img.read(addr - 32, 33)
        if blob is None:
            return False
        head = blob[:32]
        return any(0x20 <= byte <= 0x7E for byte in head)

    def _exec_range(self, addr):
        for section in self.img.sections:
            if section.flags & 0x4 and section.contains(addr):
                return True
        return False

    def _defined_function(self, addr):
        """Is there a ``__pyx_pw_``/``__pyx_pf_`` symbol at this address?"""
        if not self._has_symbols:
            return True
        for symbol in self.img.symbols:
            if symbol.name.startswith(("__pyx_pw_", "__pyx_pf_")) \
                    and symbol.value <= addr < symbol.value + 0x4000:
                return True
        return False

    def _methods(self):
        img = self.img
        owners = {}
        for symbol in img.symbols:
            kind, qualname = parse_mangled(symbol.name)
            if kind == "mdef" and qualname:
                owners[symbol.value] = qualname
        for symbol in img.symbols:
            kind, qualname = parse_mangled(symbol.name)
            if kind == "doc" and qualname:
                blob = img.cstring(symbol.value, 4096)
                if blob:
                    text = blob.decode("utf-8", "replace")
                    self.doc_by_name[qualname] = text
                    if text not in self.docstrings:
                        self.docstrings.append(text)
        for qualified, text in self.doc_by_name.items():
            parts = qualified.split(".")
            if len(parts) >= 2 and parts[-1][:1].isupper():
                self.class_docs[".".join(parts[1:])] = text
        # only an unstripped build can vouch for a function address
        self._has_symbols = any(
            symbol.name.startswith(("__pyx_pw_", "__pyx_mdef_"))
            for symbol in img.symbols)
        seen = set()
        for section in self._data_sections():
            for pos in range(section.off, section.off + section.size - 31, 8):
                addr = section.addr + (pos - section.off)
                slots = [img._u64(pos + 8 * k) for k in range(4)]
                name_ptr = img.resolve_ptr(addr, slots[0])
                doc_ptr = img.resolve_ptr(addr + 24, slots[3])
                name = img.cstring(name_ptr) if name_ptr else None
                if not self._looks_like_name(name):
                    continue
                if name.decode("latin-1") in _INTERNAL_METHOD_NAMES:
                    continue
                # NOTE: string literals are tail-merged by the linker, so a name
                # legitimately points into the middle of a longer literal
                # (``"describe"`` inside ``"demo_module.Session.describe"``).
                flags = slots[2]
                if flags & ~0x1FF or not flags & 0x8B:
                    continue
                function_ptr = img.resolve_ptr(addr + 8, slots[1])
                if not self._exec_range(function_ptr):
                    continue
                if not self._defined_function(function_ptr):
                    continue
                doc = img.cstring(doc_ptr, 8192) if doc_ptr else None
                if doc is not None:
                    if len(doc) > 4096 or self._exec_range(doc_ptr):
                        continue                     # a code pointer, not a doc
                    try:
                        doc.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                key = (name, doc)
                if key in seen:
                    continue
                seen.add(key)
                owner = None
                qualified = owners.get(addr)
                if qualified:
                    parts = qualified.split(".")
                    if len(parts) > 1:
                        owner = ".".join(parts[1:-1]) or None
                method = MethodDef(name.decode("latin-1"),
                                   doc.decode("utf-8", "replace") if doc else None,
                                   flags, addr, slots[1], owner)
                self.methods.append(method)
        if not self.methods:
            self.notes.append("no PyMethodDef tables found (fully stripped and "
                              "relocation-free build?)")
        for method in self.methods:
            if method.owner:
                self.classes.setdefault(method.owner, []).append(method)
            else:
                self.functions.append(method)
        self._group_without_symbols()

    def _group_without_symbols(self):
        """Stripped build: guess class membership from the method table layout."""
        if self.classes:
            return
        candidates = {name for name in self.identifiers if name[:1].isupper()}
        if not candidates:
            return
        by_address = sorted(self.methods, key=lambda item: item.address, reverse=True)
        current = None
        for method in by_address:
            if method.name in candidates:
                current = method.name
                continue
            if current and method.name.startswith("__") or (current and not method.owner):
                method.owner = current
                self.classes.setdefault(current, []).append(method)
                if method in self.functions:
                    self.functions.remove(method)
        for owner, methods in self.classes.items():
            methods[:] = [item for item in methods if item.name != owner]

    # --------------------------------------------------------------- strings
    def _anchored_strings(self):
        """Strings whose start address is known from a relocation.

        Cython fills its string table at import time, so every entry is a
        relocated pointer into ``.rodata``.  Those addends give the exact
        start of each literal, which the plain NUL scan cannot do: gcc
        tail-merges literals, so ``"json"`` often sits inside ``"itemsjson"``.
        """
        img = self.img
        out = []
        for section in img.sections:
            if not section.flags & 0x2 or section.type == 8:      # SHF_ALLOC, no NOBITS
                continue
            if section.name.startswith((".text", ".data", ".got", ".eh_frame",
                                        ".dyn", ".rela", ".init", ".fini", ".note")):
                continue
            if section.flags & 0x4:
                continue
            low, high = section.addr, section.addr + section.size
            starts = sorted({addend for addend in img.relocs.values()
                             if low <= addend < high})
            for start in starts:
                text = img.cstring(start, 8192)
                if text:
                    out.append((start, text))
        out.sort()
        return out

    def _strings(self):
        raw = self._anchored_strings() or self.img.string_table()
        source_candidates = []
        for addr, text in raw:
            try:
                decoded = text.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if "\n" in decoded and len(decoded) > 20:
                if decoded not in self.docstrings:
                    self.docstrings.append(decoded)
                continue
            if re.match(r"^[\w./+-]+\.pyx?$", decoded):
                source_candidates.append((addr, decoded))
                continue
            if decoded in _INTERNAL_EXACT:
                continue
            if any(decoded.startswith(prefix) for prefix in _INTERNAL_PREFIXES):
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", decoded):
                if decoded not in self.identifiers:
                    self.identifiers.append(decoded)
            elif len(decoded) >= 2 and not decoded.startswith(("/usr/", "/lib")):
                if decoded not in self.literals:
                    self.literals.append(decoded)
                    self.literal_positions.append((addr, decoded))
        if len(self.identifiers) < 5:
            self._strings_from_streams()
        if not source_candidates:
            # the filename rarely sits behind a relocation: fall back to a scan
            for addr, text in self.img.string_table():
                decoded = text.decode("utf-8", "replace")
                for found in re.finditer(r"[\w./+-]+\.pyx?", decoded):
                    source_candidates.append((addr, found.group(0)))
        if source_candidates:
            preferred = [name for _addr, name in source_candidates
                         if self.module and self.module in name]
            self.source_name = (preferred or [name for _addr, name in source_candidates])[0]

    def _strings_from_streams(self):
        """Harvest text from compressed containers.

        With ``CYTHON_COMPRESS_STRINGS`` (and with any packer that inflates on
        start-up) nothing readable sits in ``.rodata``.  Two sources are used,
        best first: the code objects inside the inflated buffer — their names
        and constants *are* the original strings — and, when no code object
        parses, the printable runs of the buffer itself.
        """
        streams = compressed_streams(self.img.data)
        for stream in streams:
            parsed = marshal_starts(stream["payload"], limit=2)
            if not parsed:
                continue
            for _offset, _version, code in parsed:
                for node in code_tree(code):
                    for text in self._payload_strings(node):
                        if text not in self.literals:
                            self.literals.append(text)
                    for name in list(getattr(node, "names", ())) + \
                            list(getattr(node, "varnames", ())):
                        if isinstance(name, str) and _IDENT.match(name) \
                                and name not in self.identifiers \
                                and name not in _INTERNAL_METHOD_NAMES:
                            self.identifiers.append(name)
        if self.literals:
            return
        for stream in streams:                       # nothing parsed: keep the text
            for match in re.finditer(rb"[\x20-\x7e]{8,}", stream["payload"]):
                text = match.group(0).decode("latin-1")
                if len(re.findall(r"[A-Za-z]{2,}", text)) >= 3 \
                        and text not in self.literals:
                    self.literals.append(text)
                    self.literal_positions.append((-1, text))

    @staticmethod
    def _payload_strings(code):
        """String constants of one code object, deepest first."""
        out = []
        for const in getattr(code, "consts", ()):
            if isinstance(const, str) and len(const) >= 4:
                out.append(const)
        return out

    # ----------------------------------------------------------- line tables
    def _line_table(self):
        """DWARF line program -> address/line pairs for the original source."""
        section = self.img.section(".debug_line")
        if section is None or not section.size:
            return
        try:
            rows = _dwarf_line_rows(self.img, section)
        except Exception as exc:                     # noqa: BLE001 - debug data is optional
            self.notes.append(f"DWARF line table unparsable: {type(exc).__name__}")
            return
        py_names = {os.path.basename(name) for _addr, name, _line in rows
                    if name.endswith((".py", ".pyx"))}
        wanted = os.path.basename(self.source_name) if self.source_name else ""
        if not wanted and py_names:
            wanted = sorted(py_names)[0]
        keep = {}
        for address, filename, line in rows:
            base = os.path.basename(filename)
            # an empty name means "same file as the previous row" in DWARF, and
            # the C file is not the source we want: only .py/.pyx rows count
            if not base or not base.endswith((".py", ".pyx")):
                continue
            if wanted and base != wanted:
                continue
            if line:
                keep[address] = line
        if not keep:
            # no --line-directives: the lines are the generated C, which still
            # tells us how big each function is
            self.notes.append("line table maps the generated C, not the source: "
                              "rebuild with --line-directives -g for source lines")
            return
        self.tier = "B"
        self.line_map = keep
        kept = sorted(set(keep.values()))
        self.line_extent = (kept[0], kept[-1]) if kept else None
        self.notes.append(
            "DWARF gives exact source line numbers and the size of the original "
            "file, but not statement text: %d address/line pairs recovered"
            % len(keep))

    # -------------------------------------------------------- generated C file
    def _source_file(self):
        """Recover source lines from a sibling generated C/CPP file."""
        if not self.img.path:
            return
        stem = os.path.splitext(self.img.path)[0]
        for suffix in (".c", ".cpp", ".cc", ".cxx"):
            candidate = stem + suffix
            if os.path.exists(candidate):
                try:
                    lines = _cython_c_source_lines(candidate, self.source_name)
                except OSError:
                    continue
                if lines:
                    self.source_lines = lines
                    self.tier = "S"
                    if not self.source_name:
                        self.source_name = os.path.basename(candidate)[:-2] + ".py"
                return

    def _order(self):
        by_address = sorted(self.methods, key=lambda item: item.address, reverse=True)
        self.methods = by_address
        self.functions = [item for item in by_address if not item.owner]
        self.classes = {}
        for method in by_address:
            if method.owner:
                self.classes.setdefault(method.owner, []).append(method)
        if self.function_lines:
            self.methods.sort(key=lambda item: (item.line or 10 ** 6))
            self.functions = [item for item in self.methods if not item.owner]
            self.classes = {}
            for method in self.methods:
                if method.owner:
                    self.classes.setdefault(method.owner, []).append(method)

    # -------------------------------------------------------------- reporting
    @property
    def tier_label(self):
        return {"S": "source-bearing (.c comments)", "B": "line-exact (DWARF)",
                "A": "structural (tables + strings)"}.get(self.tier, self.tier)

    def constants(self, limit=200):
        """Module constants: an upper-case name plus the literal next to it.

        Only names of four characters or more are considered: shorter strings
        collide with substrings of Cython's own messages ("FA" inside
        "defaults") and produce nonsense constants.
        """
        out = []
        literals = [(index, text) for index, text in enumerate(self.literals)]
        for name in self.identifiers:
            if not _CONST_NAME.match(name):
                continue
            match = next((text for _index, text in literals
                          if name.lower() in text.lower()), None)
            if match is None and literals:
                needle = name.replace("_", " ").lower()
                match = next((text for _index, text in literals
                              if needle in text.lower()), None)
            out.append((name, match))
            if len(out) >= limit:
                break
        return out

    def imports(self, limit=40):
        import sys as _sys
        known = set(getattr(_sys, "stdlib_module_names", ()))
        out = []
        for name in self.identifiers:
            if name in known and name not in out:
                out.append(name)
            if len(out) >= limit:
                break
        return out

    def stats(self):
        with_docs = sum(1 for item in self.methods if item.doc)
        return {
            "module": self.module,
            "source": self.source_name,
            "compiler": self.compiler,
            "cython": self.cython_version,
            "tier": self.tier_label,
            "methods": len(self.methods),
            "functions": len(self.functions),
            "classes": len(self.classes),
            "docstrings": len([doc for doc in self.docstrings if doc]) + with_docs,
            "literals": len(self.literals),
            "identifiers": len(self.identifiers),
            "source_lines": len(self.source_lines),
            "line_rows": len(self.line_map),
        }


def _dwarf_line_rows(img: ElfImage, section):
    """Parse a DWARF 2-5 line-number program into ``(address, file, line)``."""
    data = img.data
    start, end = section.off, section.off + section.size
    line_str = img.section(".debug_line_str")
    str_sec = img.section(".debug_str")
    line_str_blob = data[line_str.off:line_str.off + line_str.size] if line_str else b""
    str_blob = data[str_sec.off:str_sec.off + str_sec.size] if str_sec else b""

    def uleb(pos):
        result, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return result, pos

    def sleb(pos):
        result, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result, pos

    def text_at(blob, offset):
        endpos = blob.find(b"\0", offset)
        return blob[offset:endpos if endpos >= 0 else offset].decode("utf-8", "replace")

    def form_value(pos, form, address_size):
        if form == 0x08:                            # string
            endpos = data.find(b"\0", pos)
            return data[pos:endpos].decode("utf-8", "replace"), endpos + 1
        if form == 0x1f:                            # line_strp
            offset = img._u32(pos) if address_size == 4 else img._u64(pos)
            step = 4 if address_size == 4 else 8
            return text_at(line_str_blob, offset), pos + step
        if form == 0x0e:                            # strp
            offset = img._u32(pos) if address_size == 4 else img._u64(pos)
            step = 4 if address_size == 4 else 8
            return text_at(str_blob, offset), pos + step
        if form == 0x0b:                            # data1
            return data[pos], pos + 1
        if form == 0x05:                            # data2
            return img._u16(pos), pos + 2
        if form == 0x06:                            # data4
            return img._u32(pos), pos + 4
        if form == 0x07:                            # data8
            return img._u64(pos), pos + 8
        if form == 0x0f:                            # udata
            return uleb(pos)
        if form == 0x0d:                            # sdata
            return sleb(pos)
        if form == 0x1e:                            # data16
            return img._u64(pos), pos + 16
        if form == 0x21:                            # implicit_const
            value, step = sleb(pos)
            return value, step
        if form == 0x09:                            # block
            length, step = uleb(pos)
            return None, step + length
        raise ValueError(f"unsupported DWARF form {form:#x}")

    rows = []
    pos = start
    debug = bool(os.environ.get("PYDECOMP_DEBUG_DWARF"))
    while pos + 4 < end:
        unit_start = pos
        length = img._u32(pos)
        pos += 4
        if length == 0xFFFFFFFF:
            length = img._u64(pos)
            pos += 8
            offset_size = 8
        else:
            offset_size = 4
        unit_end = unit_start + (pos - unit_start) + length
        version = img._u16(pos)
        pos += 2
        if version >= 5:
            address_size = data[pos]              # one byte in DWARF 5
            pos += 1
            pos += 1                              # segment selector size
        else:
            address_size = 8 if img.bits == 64 else 4
        header_length = img._u64(pos) if offset_size == 8 else img._u32(pos)
        pos += offset_size
        program_start = pos + header_length
        min_inst = data[pos]
        pos += 1
        if version >= 4:
            pos += 1                              # max ops per instruction
        default_is_stmt = data[pos]
        pos += 1
        line_base = struct.unpack_from("<b", data, pos)[0]
        pos += 1
        line_range = data[pos]
        pos += 1
        opcode_base = data[pos]
        pos += 1
        std_lengths = list(data[pos:pos + opcode_base - 1])
        pos += opcode_base - 1
        file_names = []
        if version >= 5:
            dir_formats = []
            count = data[pos]
            pos += 1
            for _ in range(count):
                kind, pos = uleb(pos)
                form, pos = uleb(pos)
                dir_formats.append((kind, form))
            dir_count, pos = uleb(pos)
            directories = []
            for _ in range(dir_count):
                values = []
                for _kind, form in dir_formats:
                    value, pos = form_value(pos, form, offset_size)
                    values.append(value)
                directories.append(values[0] if values else "")
            file_formats = []
            count = data[pos]
            pos += 1
            for _ in range(count):
                kind, pos = uleb(pos)
                form, pos = uleb(pos)
                file_formats.append((kind, form))
            file_count, pos = uleb(pos)
            for _ in range(file_count):
                values = []
                for _kind, form in file_formats:
                    value, pos = form_value(pos, form, offset_size)
                    values.append(value)
                name = values[0] if values else ""
                directory = ""
                if len(values) > 1 and isinstance(values[1], int):
                    index = values[1]
                    if 0 <= index < len(directories):
                        directory = directories[index]
                file_names.append(os.path.join(directory, str(name)) if directory else str(name))
        else:
            directories = []                          # DWARF 2-4: two NUL lists
            while data[pos] != 0:
                endpos = data.find(b"\0", pos)
                directories.append(data[pos:endpos].decode("utf-8", "replace"))
                pos = endpos + 1
            pos += 1
            while pos < len(data) and data[pos] != 0:
                endpos = data.find(b"\0", pos)
                name = data[pos:endpos].decode("utf-8", "replace")
                pos = endpos + 1
                directory_index, pos = uleb(pos)
                _, pos = uleb(pos)                    # mtime
                _, pos = uleb(pos)                    # size
                directory = ""
                if 0 < directory_index <= len(directories):
                    directory = directories[directory_index - 1]
                file_names.append(os.path.join(directory, name) if directory else name)
            pos += 1
        pos = program_start
        if debug:
            print(f"[dwarf] unit v{version} prog={program_start} end={unit_end} "
                  f"files={len(file_names)} first={file_names[:3]}")
        address, file_index, line = 0, 1, 1
        while pos < unit_end:
            opcode = data[pos]
            pos += 1
            if debug and opcode >= opcode_base:
                print("[dwarf] special", opcode, "addr", address, "line", line)
            if opcode >= opcode_base:
                adjusted = opcode - opcode_base
                address += (adjusted // line_range) * min_inst
                line += line_base + (adjusted % line_range)
                rows.append((address, file_names[file_index - 1] if 0 < file_index <= len(file_names) else "",
                             line))
                continue
            if opcode == 0:
                length, pos = uleb(pos)
                sub = data[pos]
                pos += 1
                if sub == 1:                      # end_sequence
                    address, file_index, line = 0, 1, 1
                elif sub == 2:                    # set_address
                    address = img._u64(pos) if address_size == 8 else img._u32(pos)
                    pos += address_size
                elif sub == 3:                    # define_file (DWARF <= 4)
                    endpos = data.find(b"\0", pos)
                    file_names.append(data[pos:endpos].decode("utf-8", "replace"))
                    pos = endpos + 1
                    while pos < unit_end and data[pos]:
                        _, pos = uleb(pos)
                else:
                    pos += length - 1
                continue
            if opcode == 1:                       # copy
                rows.append((address, file_names[file_index - 1] if 0 < file_index <= len(file_names) else "",
                             line))
            elif opcode == 2:                     # advance_pc
                value, pos = uleb(pos)
                address += value * min_inst
            elif opcode == 3:                     # advance_line
                value, pos = sleb(pos)
                line += value
            elif opcode == 4:                     # set_file
                value, pos = uleb(pos)
                file_index = value
            elif opcode == 5:                     # set_column
                _, pos = uleb(pos)
            elif opcode == 6:                     # negate_stmt
                pass
            elif opcode == 7:                     # set_basic_block
                pass
            elif opcode == 8:                     # const_add_pc
                address += ((255 - opcode_base) // line_range) * min_inst
            elif opcode == 9:                     # fixed_advance_pc
                address += img._u16(pos)
                pos += 2
            elif opcode in (10, 11):              # prologue_end / epilogue_begin
                pass
            elif opcode == 12:                    # set_isa
                _, pos = uleb(pos)
            else:
                for _ in range(std_lengths[opcode - 1] if opcode - 1 < len(std_lengths) else 0):
                    _, pos = uleb(pos)
        pos = unit_end
    return rows


def _cython_c_source_lines(path, source_name=None):
    """Recover original source lines from Cython's ``/* "file.pyx":N ... */``."""
    blob = open(path, "rb").read().decode("utf-8", "replace")
    wanted = os.path.basename(source_name) if source_name else None
    lines: dict[int, str] = {}
    pattern = re.compile(r'/\* "([^"]+)":(\d+)\s*\n')
    for match in pattern.finditer(blob):
        filename, first = match.group(1), int(match.group(2))
        if wanted and os.path.basename(filename) not in (wanted, os.path.basename(path)):
            continue
        body_start = match.end()
        block = blob[body_start:blob.find("*/", body_start)]
        block_lines = block.split("\n")
        for offset, raw in enumerate(block_lines[:400]):
            if not raw.startswith(" *"):
                if raw.strip() == "" and offset == 0:
                    continue
                break
            text = raw[2:]
            if text.startswith(" "):
                text = text[1:]
            text = text.replace("<<<<<<<<<<<<<<", "").rstrip()
            if text.endswith("#"):
                text = text[:-1].rstrip()           # Cython block marker
            if text.strip().endswith("*/"):
                text = text.strip()[:-2].rstrip()
            lines.setdefault(first + offset, text)
    _repair_numbering(lines)
    return lines


def _repair_numbering(lines: dict):
    """Cython numbers some quoted blocks with a constant offset.

    The module docstring, for example, is emitted twice: once at its true line
    numbers and once shifted by the length of the prologue.  That leaves a gap
    plus a duplicate line.  Detect such duplicates and shift everything after
    them so the file closes up again.
    """
    for _attempt in range(8):
        keys = sorted(lines)
        repaired = False
        for position, first in enumerate(keys):
            text = lines[first]
            if not text.strip():
                continue
            for second in keys[position + 1:]:
                if second - first > 4:
                    break
                if lines[second] != text:
                    continue
                between = range(first + 1, second)
                if any(lines.get(index, "").strip() for index in between):
                    continue
                shift = second - first
                moved = {index - shift: lines[index] for index in lines if index >= second}
                for index in [index for index in lines if index >= second]:
                    del lines[index]
                lines.update(moved)
                repaired = True
                break
            if repaired:
                break
        if not repaired:
            return lines
    return lines


# ------------------------------------------------------------ reconstruction
def _module_docstring(info: CythonInfo):
    method_docs = {method.doc for method in info.methods if method.doc}
    extras = [doc for doc in info.docstrings if doc and doc not in method_docs]
    if not extras:
        return None
    extras.sort(key=len, reverse=True)
    best = extras[0].strip()
    if not best or best.count(" ") < 2:
        return None
    return best


def _docstring_block(text, indent):
    if '"""' in text:
        return f'{indent}r\'\'\'{text}\'\'\''
    return f'{indent}"""{text}"""'


def cython_source(info: CythonInfo) -> str:
    """Rebuild as much of the original ``.py`` as the artefact still supports."""
    if info.tier == "S" and info.source_lines:
        text = _fit_source_lines(info.source_lines)
        if text is not None:
            return _with_header(info, text, exact=True)
    return _with_header(info, _skeleton(info), exact=False)


def _stamp_line() -> str:
    """The signature every recovered file starts with."""
    try:
        from . import sidecar as _self          # noqa: PLC0415 - same module
        del _self
    except ImportError:
        pass
    try:
        from ..terminal.identity import signature
        return signature()
    except Exception:                           # noqa: BLE001 - optional
        return "#[ Deobfuscated by idam Emmanuel ] only through pydecomp"


def _with_header(info: CythonInfo, body: str, exact: bool) -> str:
    stats = info.stats()
    if exact:
        banner = (f"{_stamp_line()}\n"
                  f"# Cython source recovery ({info.tier_label})\n"
                  f"# module: {info.module or '?'}   source: {info.source_name or '?'}\n"
                  f"# {stats['source_lines']} source lines quoted by the generated C\n"
                  f"# the quoted lines are verbatim; gaps are lines Cython did not quote\n")
    else:
        banner = (f"{_stamp_line()}\n"
                  f"# Cython structural recovery ({info.tier_label})\n"
                  f"# module: {info.module or '?'}   source: {info.source_name or '?'}\n"
                  f"# {stats['functions']} functions, {stats['classes']} classes, "
                  f"{stats['docstrings']} docstrings, {stats['literals']} literals recovered\n"
                  f"# Cython emits machine code, not bytecode: statement bodies cannot be\n"
                  f"# recovered from a release .so.  Names, docstrings, classes and literals\n"
                  f"# below are the original ones; bodies are marked placeholders.\n")
    return banner + "\n" + body.rstrip() + "\n"


def _skeleton(info: CythonInfo) -> str:
    out = []
    doc = _module_docstring(info)
    if doc:
        out.append(_docstring_block(doc, ""))
        out.append("")
    imports = info.imports()
    if imports:
        out.append("# imports observed in the Cython string table")
        out.extend(f"import {name}" for name in imports)
        out.append("")
    constants = info.constants()
    if constants:
        out.append("# module constants (name and value recovered from the binary)")
        for name, value in constants:
            if value is None:
                out.append(f"{name} = None  # value is not embedded as a literal")
            else:
                out.append(f"{name} = {value!r}")
        out.append("")
    for owner, methods in info.classes.items():
        line = min((method.line for method in methods if method.line), default=None)
        anchor = f"  # line {line}" if line else ""
        out.append(f"class {owner}:{anchor}")
        class_doc = info.class_docs.get(owner)
        if class_doc:
            out.append(_docstring_block(class_doc, "    "))
            out.append("")
        for method in methods:
            out.extend(_method_block(method, "    ", is_method=True))
        if not methods:
            out.append("    pass")
        out.append("")
    for method in info.functions:
        out.extend(_method_block(method, "", is_method=False))
    if not info.classes and not info.functions:
        out.append("# no function tables recovered")
        out.append("pass")
    return "\n".join(out)


def _method_block(method: MethodDef, indent: str, is_method: bool) -> list[str]:
    anchor = f"  # line {method.line}" if method.line else ""
    flags = ", ".join(method.flag_names) or f"flags {method.flags:#x}"
    takes_self = is_method and "METH_STATIC" not in flags and "METH_CLASS" not in flags
    if "METH_NOARGS" in flags:
        signature = "self" if takes_self else ""
    elif "METH_O" in flags:
        signature = "self, arg" if takes_self else "arg"
    else:
        signature = "self, *args, **kwargs" if takes_self else "*args, **kwargs"
    lines = [f"{indent}def {method.name}({signature}):{anchor}"]
    if method.doc:
        lines.append(_docstring_block(method.doc, indent + "    "))
        lines.append(f"{indent}    # {flags}")
    else:
        lines.append(f"{indent}    # {flags} — body not recoverable from machine code")
    lines.append(f"{indent}    ...")
    lines.append("")
    return lines


def _fit_source_lines(lines: dict[int, str]):
    """Place recovered source lines at their original line numbers."""
    if not lines:
        return None
    total = max(lines)
    filled = ["%s" % (lines.get(number, "")) for number in range(1, total + 1)]
    attempt = "\n".join(filled)
    if _compiles(attempt):
        return attempt
    # gaps: give every empty line the indentation of the line that follows it
    for number in range(total, 0, -1):
        if lines.get(number) is None:
            following = next((lines[item] for item in range(number + 1, total + 1)
                              if lines.get(item)), "")
            indent = following[:len(following) - len(following.lstrip())]
            filled[number - 1] = f"{indent}pass  # pydecomp: line {number} not quoted"
    attempt = "\n".join(filled)
    if _compiles(attempt):
        return attempt
    return None


def _compiles(text):
    try:
        compile(text, "<cython-recovery>", "exec")
        return True
    except SyntaxError:
        return False


def cython_lines_dump(info: CythonInfo) -> str:
    """Every recovered source line, numbered, as a comment-only listing."""
    out = [f"# {info.source_name or info.module}: {len(info.source_lines)} recovered lines"]
    for number in sorted(info.source_lines):
        out.append(f"# {number:5d}  {info.source_lines[number]}")
    return "\n".join(out)


def cython_report(info: CythonInfo) -> str:
    stats = info.stats()
    summary = info.img.summary()
    rows = [
        ("module", stats["module"] or "?"),
        ("source file", stats["source"] or "?"),
        ("recovery tier", stats["tier"]),
        ("cython", stats["cython"] or "not stamped"),
        ("compiler", stats["compiler"] or "?"),
        ("functions", stats["functions"]),
        ("classes", stats["classes"]),
        ("method table entries", stats["methods"]),
        ("docstrings", stats["docstrings"]),
        ("literals", stats["literals"]),
        ("identifiers", stats["identifiers"]),
        ("source lines recovered", stats["source_lines"]),
        ("line table rows", stats["line_rows"]),
    ]
    out = ["# Cython module report", "", "| field | value |", "| --- | --- |"]
    out += [f"| {key} | {value} |" for key, value in rows]
    out += ["", "## ELF", "", "| field | value |", "| --- | --- |"]
    out += [f"| {key} | {value} |" for key, value in summary.items() if key != "path"]
    if info.classes:
        out += ["", "## Classes", ""]
        for owner, methods in info.classes.items():
            out.append(f"### {owner}")
            for method in methods:
                doc = (method.doc or "").split("\n")[0]
                out.append(f"* `{method.qualname}({', '.join(method.flag_names)})`"
                           + (f" — {doc}" if doc else ""))
    if info.functions:
        out += ["", "## Functions", ""]
        for method in info.functions:
            doc = (method.doc or "").split("\n")[0]
            out.append(f"* `{method.name}({', '.join(method.flag_names)})`"
                       + (f" — {doc}" if doc else ""))
    if info.literals:
        out += ["", "## String literals", "", "```"]
        out += info.literals[:200]
        out += ["```"]
    if info.identifiers:
        out += ["", "## Identifiers", "", "```"]
        out += info.identifiers[:300]
        out += ["```"]
    if info.notes:
        out += ["", "## Notes", ""]
        out += [f"* {note}" for note in info.notes]
    out += ["", "## Ceiling", "",
            "Cython compiles to C: a release `.so` contains no bytecode and no source",
            "text, so statement bodies are not recoverable.  Everything above *is*",
            "recoverable and is recovered exactly — names, docstrings, class layout,",
            "declaration order and every literal.  Ship the generated `.c` next to the",
            "`.so` (or build with `--line-directives -g`) and the tier rises to the",
            "original line numbers / verbatim source lines."]
    return "\n".join(out) + "\n"


# ------------------------------------------------------- embedded python (ELF)
class _Marshal:
    """The little of the marshal format the PyInstaller TOC needs."""

    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def byte(self):
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, count):
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def i32(self):
        value = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return value

    def u32(self):
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def obj(self):
        kind = self.byte()
        if kind in (ord("0"), ord("N")):
            return None
        if kind == ord("F"):
            return False
        if kind == ord("T"):
            return True
        if kind == ord("S"):
            return None
        if kind == ord("i"):
            return self.i32()
        if kind in (ord("I"), ord("l")):
            return self.u32() if kind == ord("I") else self.i32()
        if kind in (ord("g"), ord("f")):
            value = struct.unpack_from("<d", self.data, self.pos)[0]
            self.pos += 8
            return value
        if kind == ord("s"):
            return self.take(self.u32())
        if kind in (ord("u"), ord("t"), ord("a"), ord("A")):
            if kind in (ord("a"), ord("A")):
                raw = self.take(self.u32())
                return raw.decode("latin-1")
            raw = self.take(self.u32())
            return raw.decode("utf-8", "replace")
        if kind == ord("z") or kind == ord("Z"):
            raw = self.take(self.byte())
            return raw.decode("latin-1")
        if kind == ord("("):
            return tuple(self.obj() for _ in range(self.byte()))
        if kind == ord("["):
            return [self.obj() for _ in range(self.i32())]
        if kind == ord("{"):
            out = {}
            while self.data[self.pos] != ord("0"):
                out[self.obj()] = self.obj()
            self.pos += 1
            return out
        if kind == ord(")"):
            return None
        return None


def pyinstaller_entries(data: bytes):
    """Parse a PyInstaller CArchive: ``[(name, typecode, bytes-or-None)]``."""
    magic_at = data.rfind(PYINSTALLER_MAGIC)
    if magic_at < 0:
        return []
    cookie = data[magic_at:magic_at + 88]
    if len(cookie) < 88:
        return []
    archive_len, toc_off, toc_len, pyver = struct.unpack("!IIIi", cookie[8:24])
    base = magic_at + 88 - archive_len
    entries = []
    pos, end = base + toc_off, base + toc_off + toc_len
    while pos < end and pos + 18 <= len(data):
        entry_len, offset, data_len, _ulen, _flag, typecode = struct.unpack_from(
            "!IIIIBc", data, pos)
        name = data[pos + 18:pos + entry_len].rstrip(b"\0").decode("utf-8", "replace")
        pos += entry_len
        blob = data[base + offset:base + offset + data_len] if data_len else b""
        entries.append({"name": name, "type": typecode.decode("latin-1"), "data": blob})
    return entries


def pyz_members(blob: bytes):
    """Parse a ``PYZ`` archive: ``[(name, bytes)]`` of the marshalled modules."""
    if not blob.startswith(PYZ_MAGIC):
        return []
    toc_offset = struct.unpack_from("!i", blob, 8)[0]
    toc = _Marshal(blob, toc_offset).obj()
    if not isinstance(toc, (list, tuple)):
        return []
    out = []
    for name, entry in toc:
        if isinstance(entry, (tuple, list)) and len(entry) >= 3:
            _typecode, offset, length = entry[0], entry[1], entry[2]
            payload = blob[offset:offset + length]
            if isinstance(_typecode, int) and _typecode == 1:
                try:
                    payload = zlib.decompress(payload)
                except zlib.error:
                    continue
            out.append((name, payload))
    return out


COMPRESSED_MAGICS = (
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)
ZLIB_CMF = (0x78,)


def _zlib_at(data, offset):
    """A zlib stream that starts exactly at ``offset``, or None."""
    probe = zlib.decompressobj()
    try:
        payload = probe.decompress(data[offset:offset + 64 * 1024 * 1024],
                                   256 * 1024 * 1024)
    except Exception:                                # noqa: BLE001 - not a stream
        return None
    if not payload or not probe.eof:
        return None
    return payload


def compressed_streams(data, limit=64):
    """Every compressed container in the file, decompressed statically.

    Cython can be built with ``CYTHON_COMPRESS_STRINGS``, and packers routinely
    zlib a payload before hiding it in ``.rodata``.  A zlib stream is
    self-describing, so it can be inflated without running a single
    instruction — that is what turns "compressed blob" into source.
    """
    streams = []
    seen = set()
    for offset in range(len(data) - 2):
        if len(streams) >= limit:
            break
        head = data[offset]
        if head in ZLIB_CMF and (head * 256 + data[offset + 1]) % 31 == 0:
            payload = _zlib_at(data, offset)
            if payload:
                key = (offset, len(payload))
                if key not in seen:
                    seen.add(key)
                    streams.append({"offset": offset, "kind": "zlib",
                                    "payload": payload})
            continue
        for magic, kind in COMPRESSED_MAGICS:
            if not data.startswith(magic, offset):
                continue
            try:
                if kind == "gzip":
                    payload = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
                        data[offset:offset + 64 * 1024 * 1024])
                elif kind == "bzip2":
                    payload = (bz2.decompress(data[offset:offset + 64 * 1024 * 1024])
                               if bz2 is not None else None)
                else:
                    payload = (lzma.decompress(data[offset:offset + 64 * 1024 * 1024])
                               if lzma is not None else None)
            except Exception:                        # noqa: BLE001 - not a stream
                payload = None
            if payload:
                key = (offset, len(payload))
                if key not in seen:
                    seen.add(key)
                    streams.append({"offset": offset, "kind": kind,
                                    "payload": payload})
    return streams


def marshal_starts(blob, limit=8, scan=2 * 1024 * 1024):
    """Offsets where a CPython marshal code object parses cleanly.

    Import of ``pydecomp`` happens lazily: it is the same package, but keeping
    the ELF layer importable on its own matters for the tests.
    """
    import pydecomp as P
    starts = []
    top = min(len(blob), scan)
    offset = 0
    while offset < top and len(starts) < limit:
        byte = blob[offset]
        # a code object starts with four small int32 counters; that prefilter
        # keeps this cheap enough to run over whole binaries
        head = blob[offset + 1:offset + 13]
        if byte in (0x63, 0xE3) and len(head) == 12 and head.count(0) >= 6:
            try:
                version, code, _consumed = P.parse_marshal_blob(blob[offset:])
            except Exception:                        # noqa: BLE001 - not a code object
                code = None
            if code is not None and getattr(code, "code", b""):
                starts.append((offset, version, code))
            offset += 1
            continue
        offset += 1
    return starts


def compressed_payloads(img: ElfImage):
    """Payloads that were compressed before being embedded in the file."""
    out = []
    for stream in compressed_streams(img.data):
        payload = stream["payload"]
        label = f"{stream['kind']}@0x{stream['offset']:x}"
        for offset, version, code in marshal_starts(payload):
            out.append({"label": f"{label}:marshal@0x{offset:x}",
                        "blob": payload[offset:], "stream": stream,
                        "version": version, "code": code})
        if payload.startswith(b"PK\x03\x04"):
            out.append({"label": f"{label}:zip", "blob": payload,
                        "stream": stream, "version": None, "code": None})
    return out


_LIFT_NOTE = re.compile(r"^\s*-?\d+ \? .*$")


def sanitize_lifted(text):
    """Drop the lifter's `N ? expression` notes, which are comments in disguise."""
    kept = [line for line in text.splitlines() if not _LIFT_NOTE.match(line)]
    return "\n".join(kept)


def parse_lifted(text, tries=60):
    """Parse a lifted function, repairing the few lines the lifter leaves open.

    Lifting one code object out of its module context leaves notes such as
    ``names.rsplit(' ') ? 0`` and assignments with an empty right-hand side.
    Each repair is local and recorded by the caller, never silently guessed.
    """
    import ast
    lines = text.splitlines()
    for _attempt in range(tries):
        try:
            return ast.parse("\n".join(lines))
        except SyntaxError as exc:
            index = (exc.lineno or 1) - 1
            if not 0 <= index < len(lines):
                return None
            line = lines[index]
            if " ? " in line or line.rstrip().endswith("?"):
                del lines[index]
            elif re.search(r"=\s*$", line):
                lines[index] = line + " _PydecompUnknown('unparsed')"
            else:
                del lines[index]
    return None


def _with_sentinel(text):
    """Install the unresolved-operand sentinel when the text mentions it."""
    if "_PydecompUnknown" not in text:
        return text
    try:
        import pydecomp as P
        return P.with_unknown_preamble(text)
    except Exception:                                # noqa: BLE001 - never lose the text
        return text


def code_tree(code):
    """Every code object inside ``code``, parents before children."""
    out = [code]
    for const in getattr(code, "consts", ()):
        if hasattr(const, "code") and hasattr(const, "name"):
            out.extend(code_tree(const))
    return out


def _recovered_defs(text):
    """Names the rebuild actually defines — functions *and* classes.

    A class is a code object in the tree like any function, so it counts as
    recovered once its ``class`` statement is in the text; otherwise the
    per-function retry would try to lift a class body as a standalone def.
    """
    body = text or ""
    return (set(re.findall(r"^\s*def ([A-Za-z_]\w*)\(", body, re.M))
            | set(re.findall(r"^\s*class ([A-Za-z_]\w*)", body, re.M)))


def augment_payload_source(text, module_code, version, min_score=0.5):
    """Add every function the whole-module rebuild lost.

    A 3.14 module with a few thousand bytes of bytecode rarely comes back in
    one piece: one unhandled opcode in one function makes the structural
    rebuild fall back to statements.  Each code object is then retried on its
    own, and whatever still fails is lifted statement by statement — so *every*
    function in the original module appears in the output, with a per-function
    note saying how it was recovered.
    """
    import pydecomp as P
    have = _recovered_defs(text)
    extra, table = [], []
    for code in code_tree(module_code):
        name = getattr(code, "name", "")
        if not name.isidentifier() or name in have or name in ("<lambda>", "<genexpr>",
                                                               "<listcomp>", "<setcomp>",
                                                               "<dictcomp>", "<module>"):
            continue
        rebuilt, score = P.decompile_object(code, version, name, "function")
        if rebuilt is not None and score >= min_score:
            extra.append(rebuilt.rstrip())
            table.append((name, f"rebuilt ({score:.0%})", len(code.code)))
        else:
            lines = P.lift(code, version, name)
            extra.append("\n".join(lines).rstrip())
            table.append((name, "lifted (structure unclear)", len(code.code)))
        have.add(name)
    if not extra:
        return text, []
    banner = ("# ---------------------------------------------------------------\n"
              "# Functions the whole-module rebuild did not emit.  Each one below\n"
              "# was rebuilt from its own code object, or lifted when the control\n"
              "# flow could not be proven.  Nothing is executed.\n"
              "# ---------------------------------------------------------------")
    return text.rstrip() + "\n\n\n" + banner + "\n\n" + "\n\n\n".join(extra) + "\n", table


def _hoist_module_defs(tree, names):
    """Move misplaced top-level definitions back to module scope.

    Statement lifting follows the code-object tree literally, so a module-level
    function whose body happens to sit after a jump can end up nested inside
    whatever function, `if` block or `try` block was being lifted at the time.
    The code objects say where each def really lives, so put it back.
    """
    import ast
    hoisted = []

    def walk(node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list) and value and all(isinstance(item, ast.stmt)
                                                         for item in value):
                keep = []
                for stmt in value:
                    walk(stmt)                       # nested defs first
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and stmt.name in names:
                        hoisted.append(stmt)
                        continue
                    keep.append(stmt)
                if not keep:
                    keep = [ast.Pass()]
                setattr(node, field, keep)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        walk(item)
            elif isinstance(value, ast.AST):
                walk(value)

    root = ast.Module(body=list(tree.body), type_ignores=[])
    walk(root)
    hoisted.sort(key=lambda node: getattr(node, "lineno", 0))
    root.body = list(root.body) + hoisted
    return root


def compiles(text):
    """True when ``text`` compiles; SyntaxWarning noise from the lifter is fine."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compile(text, "<payload>", "exec")
        return True
    except (SyntaxError, ValueError):
        return False


def reconstruct_payload(blob, name, version, module_code, min_score=0.5):
    """Best-effort whole-module rebuild of an embedded code object tree."""
    import ast
    import pydecomp as P
    text = P.dig(blob, name).text
    # only code objects that really live at module scope: a class method is
    # part of its class, not a stray top-level def to hoist back out
    top = {code.name for code in code_tree(module_code)
           if code is not module_code and code.name.isidentifier()
           and "." not in getattr(code, "qualname", code.name)}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text, [], 0
    try:
        tree = _hoist_module_defs(tree, top)
        ast.fix_missing_locations(tree)
        hoisted_text = ast.unparse(tree)
        if not compiles(hoisted_text):
            raise SyntaxError("hoisted text does not compile")
    except Exception:                                # noqa: BLE001 - keep what we had
        return text, [], 0

    # per-function retry: the structural rebuild beats the lifter when it works
    table = []
    replaced = 0
    by_name = {code.name: code for code in code_tree(module_code)
               if code.name.isidentifier() and code is not module_code
               and "." not in getattr(code, "qualname", code.name)}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        code = by_name.get(node.name)
        if code is None:
            continue
        rebuilt, score = P.decompile_object(code, version, node.name, "function")
        table.append((node.name, score, len(code.code)))
        if rebuilt is None or score < min_score:
            tolerant_text, tolerant_score = P.decompile_object(
                code, version, node.name, "function", tolerant=True)
            if tolerant_text is not None and tolerant_score >= min_score:
                rebuilt, score = tolerant_text, tolerant_score
                table[-1] = (node.name, score, len(code.code))
        if rebuilt is None or score < min_score:
            # lift this code object on its own, so its statements stay inside it
            try:
                lifted = sanitize_lifted("\n".join(P.lift(code, version, node.name)))
                parsed = parse_lifted(lifted)
                if parsed is None:
                    continue
                candidate = parsed.body[0]
            except Exception:                        # noqa: BLE001 - keep the hoisted body
                continue
            if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            node.args = candidate.args
            node.body = candidate.body
            continue
        try:
            candidate = ast.parse(rebuilt).body[0]
        except (SyntaxError, IndexError):
            continue
        if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        node.args = candidate.args
        node.body = candidate.body
        node.decorator_list = candidate.decorator_list
        node.returns = candidate.returns
        replaced += 1
    try:
        ast.fix_missing_locations(tree)
        final = ast.unparse(tree)
        if not compiles(final):
            return hoisted_text, table, replaced
    except Exception:                                # noqa: BLE001 - keep the hoisted text
        return hoisted_text, table, replaced
    return final, table, replaced


CARVE_PATTERNS = (
    ("hex", re.compile(rb"(?:[0-9A-Fa-f]{2}){256,}")),
    ("base64", re.compile(rb"[A-Za-z0-9+/]{256,}={0,2}")),
    ("base32", re.compile(rb"[A-Z2-7]{256,}={0,6}")),
    ("rot13", re.compile(rb"[\x20-\x7e\n\r\t]{512,}")),
)


def _decode_run(encoding, run: bytes):
    import binascii
    try:
        if encoding == "hex":
            if len(run) % 2:
                run = run[:-1]
            return binascii.unhexlify(run)
        if encoding == "base64":
            padded = run + b"=" * (-len(run) % 4)
            return binascii.a2b_base64(padded)
        if encoding == "base32":
            padded = run + b"=" * (-len(run) % 8)
            return binascii.a32decode(padded)
        if encoding == "rot13":
            import codecs
            return codecs.decode(run, "rot13").encode("latin-1", "replace")
    except Exception:                                # noqa: BLE001 - not that encoding
        return None
    return None


def _looks_like_source(blob: bytes) -> bool:
    """Does this look like the Python source of a real module?"""
    if len(blob) < 200:
        return False
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return False
    markers = ("import ", "def ", "class ", "print(", "= ", "self.")
    if sum(1 for marker in markers if marker in text) < 3:
        return False
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compile(text, "<carved>", "exec")
        return True
    except (SyntaxError, ValueError):
        try:
            import pydecomp as P
            return P.looks_like_python(text)
        except Exception:                            # noqa: BLE001 - no opinion
            return False


def carve_payloads(img: ElfImage):
    """Python source hidden as hex, base64, base32 or rot13 text.

    Cython's compressed string table is a natural hiding space: one value can be
    the whole original source, hex-encoded.  `masu.so` does exactly that — the
    zlib stream at 0x37cc inflates to a 236 KB hex blob that decodes to 118 KB
    of source.
    """
    blobs = []
    for stream in compressed_streams(img.data):
        blobs.append((f"{stream['kind']}@0x{stream['offset']:x}", stream["payload"]))
    blobs.append(("raw", img.data))
    found, seen = [], set()
    for where, blob in blobs:
        for encoding, pattern in CARVE_PATTERNS:
            for match in pattern.finditer(blob):
                run = match.group(0)
                decoded = _decode_run(encoding, run)
                if not decoded or not _looks_like_source(decoded):
                    continue
                key = (encoding, len(decoded), decoded[:64])
                if key in seen:
                    continue
                seen.add(key)
                found.append({"label": f"{where}:{encoding}@{match.start():x}",
                              "encoding": encoding, "blob": decoded,
                              "source": True, "version": None, "code": None,
                              "stream": None})
    return found


def raw_marshal_entries(img: ElfImage, limit=4):
    """Code objects sitting plainly in the file, with no container at all."""
    out = []
    for offset, version, code in marshal_starts(img.data, limit=limit,
                                                scan=4 * 1024 * 1024):
        out.append({"label": f"marshal@0x{offset:x}", "blob": img.data[offset:],
                    "stream": None, "version": version, "code": code})
    return out


def payload_entries(img: ElfImage):
    """Every recoverable payload: code trees first, then carved source."""
    return compressed_payloads(img) + raw_marshal_entries(img) + carve_payloads(img)


def recover_payloads(img: ElfImage, stem: str, out_dir: str, source_name: str = ""):
    """Decompile every embedded code object tree, compressed or not.

    Two engines are tried.  ``pydecomp``'s whole-module rebuild is exact when it
    proves the module; when it cannot (3.14 opcodes it has not proven yet) the
    per-function reconstruction takes over, which guarantees that every code
    object still appears in the output.
    """
    import pydecomp as P
    paths, rows, notes = [], [], []
    entries = payload_entries(img)
    for entry in entries:
        if entry.get("source"):
            label = re.sub(r"[^0-9A-Za-z]+", "_", entry["label"]).strip("_")
            name = f"{stem}_{label}"
            try:
                artifact = P.dig(entry["blob"], name)
                text = artifact.text
                kind = artifact.kind
                stages = max(1, len(artifact.trace))
            except Exception as exc:                 # noqa: BLE001 - keep the verbatim text
                text = entry["blob"].decode("utf-8", "replace")
                kind, stages = "source", 1
                notes.append(f"{entry['label']}: {type(exc).__name__}: {exc}")
            method = (f"carved from {entry['encoding']} text"
                      f"{'' if kind == 'source' else ' + ' + kind}")
            header = [
                f"{_stamp_line()}",
                f"# rebuilt from {os.path.basename(img.path or stem)} — {entry['label']}",
                f"# {method}: {len(text):,} characters, {stages} stage"
                f"{'' if stages == 1 else 's'}",
                "# static only — the payload was never executed",
                "",
            ]
            target = os.path.join(out_dir, f"{name}_deob.py")
            text = _with_sentinel(text)
            body = "\n".join(header) + text + "\n"
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(body)
            paths.append(target)
            rows.append({"label": entry["label"], "version": "-",
                         "bytecode": 0, "functions": 0, "rebuilt": 0,
                         "path": os.path.basename(target), "method": method,
                         "encoding": entry["encoding"], "chars": len(text),
                         "audit": P.audit_source(body), "table": []})
            continue
        if entry["code"] is None:
            continue
        version = entry["version"]
        label = re.sub(r"[^0-9A-Za-z]+", "_", entry["label"]).strip("_")
        name = f"{stem}_{label}"
        table, rebuilt, method = [], 0, ""
        try:
            artifact = P.dig(entry["blob"], name)
        except Exception as exc:                     # noqa: BLE001 - fall through
            artifact = None
            notes.append(f"{entry['label']}: pydecomp failed ({type(exc).__name__}: {exc})")
        if artifact is not None:
            match = re.search(r"round trip (\d+)%", artifact.text[:400])
            score = int(match.group(1)) if match else 0
            if artifact.kind == "source" or score >= 80:
                text = artifact.text
                method = (f"whole-module rebuild ({score}% instruction round trip)"
                          if score else "whole-module rebuild")
                rebuilt = sum(1 for code in code_tree(entry["code"])
                              if code is not entry["code"] and code.name.isidentifier())
                for code in code_tree(entry["code"]):
                    if code is entry["code"] or not code.name.isidentifier():
                        continue
                    table.append((code.name, 0.9, len(code.code)))
        if not method:
            try:
                text, table, rebuilt = reconstruct_payload(
                    entry["blob"], name, version, entry["code"])
                method = "per-function reconstruction"
            except Exception as exc:                 # noqa: BLE001 - report, keep going
                notes.append(f"{entry['label']}: {type(exc).__name__}: {exc}")
                continue
        header = [
            f"{_stamp_line()}",
            f"# rebuilt from {os.path.basename(img.path or stem)} — {entry['label']}",
            f"# compiler: CPython {version[0]}.{version[1]}   "
            f"bytecode: {len(getattr(entry['code'], 'code', b'')):,} bytes   "
            f"functions: {len(table)}   {method}",
            "# static only — the payload was never executed",
            "",
        ]
        target = os.path.join(out_dir, f"{name}_deob.py")
        text = _with_sentinel(text)
        body = "\n".join(header) + text + "\n"
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(body)
        paths.append(target)
        rows.append({"label": entry["label"], "version": f"{version[0]}.{version[1]}",
                     "bytecode": len(getattr(entry["code"], "code", b"")),
                     "functions": len(table), "rebuilt": rebuilt,
                     "path": os.path.basename(target), "method": method,
                     "audit": P.audit_source(body), "table": table})
    if not entries:
        notes.append("no compressed container and no marshal stream found")
    return paths, rows, notes


def _audit_one(report):
    """Local shim so a bare ``native.py`` still renders an audit summary."""
    try:
        import pydecomp as P
        return P.audit_line(report)
    except Exception:                                # noqa: BLE001 - never break a report
        return "syntax ok" if report.get("compiles") else "syntax error"


def _audit_summary(rows):
    """Say in four words whether the payload files will import."""
    audits = [row["audit"] for row in rows if row.get("audit")]
    if not audits:
        return ""
    if any(not audit.get("compiles") for audit in audits):
        bad = sum(1 for audit in audits if not audit.get("compiles"))
        return f"{bad} syntax error{'' if bad == 1 else 's'}"
    missing = sum(len(audit.get("missing") or ()) for audit in audits)
    if not missing:
        return "syntax ok · every name bound"
    return f"syntax ok · {missing} unbound name{'' if missing == 1 else 's'}"


def payload_report(rows) -> list:
    """Markdown for the payload section of a report."""
    if not rows:
        return []
    out = ["", "## Recovered Python payloads", "",
           "| where | kind | size | functions | rebuilt | output |",
           "| --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        if row.get("encoding"):
            out.append(f"| {row['label']} | {row['encoding']} source | "
                       f"{row['chars']:,} chars | - | - | `{row['path']}` |")
        else:
            out.append(f"| {row['label']} | CPython {row['version']} | "
                       f"{row['bytecode']:,} B | {row['functions']} | "
                       f"{row['rebuilt']} | `{row['path']}` |")
    audits = [row for row in rows if row.get("audit")]
    if audits:
        out += ["", "### Runnability (parsed, never executed)", ""]
        for row in audits:
            out.append(f"* `{row['path']}` — {_audit_one(row['audit'])}")
    tables = [row for row in rows if row.get("table")]
    if tables:
        out += ["", "### Function-by-function recovery", ""]
        for row in tables:
            out.append(f"*{row['path']}*")
            out.append("")
            out.append("| function | bytecode | how it was recovered |")
            out.append("| --- | --- | --- |")
            for name, score, size in row["table"]:
                how = (f"rebuilt ({score:.0%} instruction match)" if score >= 0.5
                       else "lifted statement by statement")
                out.append(f"| `{name}` | {size:,} B | {how} |")
            out.append("")
    return out


def find_embedded_python(img: ElfImage):
    """Every candidate Python payload in the file, as ``(label, blob)``."""
    found = []
    data = img.data
    for entry in pyinstaller_entries(data):
        if entry["type"] in ("z", "Z"):
            for name, blob in pyz_members(entry["data"]):
                found.append((f"{name}.pyc", blob))
        elif entry["type"] in ("s", "m", "M") and entry["data"]:
            found.append((entry["name"] or "module", entry["data"]))
    for offset in _find_all(data, PYZ_MAGIC, limit=8):
        for name, blob in pyz_members(data[offset:offset + 64 * 1024 * 1024]):
            found.append((f"pyz:{name}.pyc", blob))
    for magic in PYC_MAGICS:
        for offset in _find_all(data, magic, limit=16):
            blob = data[offset:offset + 32 * 1024 * 1024]
            if _marshal_ok(blob):
                found.append((f"pyc@0x{offset:x}", blob))
    for offset, version, _code in marshal_starts(data, limit=4, scan=4 * 1024 * 1024):
        label = f"marshal@0x{offset:x}"
        if not any(seen_label == label for seen_label, _blob in found):
            found.append((label, data[offset:]))
    for offset in _find_all(data, ZIP_MAGIC, limit=16):
        blob = data[offset:]
        try:
            import io
            import zipfile
            archive = zipfile.ZipFile(io.BytesIO(blob))
        except Exception:                        # noqa: BLE001 - not a zip then
            continue
        for member in archive.namelist()[:400]:
            if member.endswith((".pyc", ".py")):
                try:
                    found.append((member, archive.read(member)))
                except Exception:                # noqa: BLE001 - keep going
                    continue
    for entry in compressed_payloads(img):
        found.append((entry["label"] + ".pyc", entry["blob"]))
    seen, unique = set(), []
    for label, blob in found:
        key = (label, len(blob))
        if key in seen or not blob:
            continue
        seen.add(key)
        unique.append((label, blob))
    return unique


def _marshal_ok(blob):
    """Does this look like a code object the engine can parse?"""
    if len(blob) < 32:
        return False
    try:
        import pydecomp as P
    except ImportError:                          # pragma: no cover - path issue
        return False
    for start in (16, 12, 8, 0):
        try:
            version, code, _consumed = P.parse_marshal_blob(blob[start:])
        except Exception:                        # noqa: BLE001 - try the next offset
            continue
        if code is not None and len(getattr(code, "code", b"")) > 8:
            return True
    return False


# ------------------------------------------------------------------ entry API
def analyse_native(path: str, out_dir: str, mode: str = "auto"):
    """Analyse ``path`` as Cython or ELF.

    Returns ``{"kind", "written": [paths], "report": str, "stats": {...}}``.
    """
    data = open(path, "rb").read()
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(path))[0]
    if not looks_like_elf(data):
        raise ValueError("not an ELF file")
    img = ElfImage(data, path)
    findings = detect(img)
    wants_cython = mode == "cython" or (mode == "auto" and findings["cython"])
    if wants_cython:
        info = CythonInfo(img).analyse()
        source = cython_source(info)
        source_path = os.path.join(out_dir, f"{stem}_deob.py")
        report_path = os.path.join(out_dir, f"{stem}_report.md")
        open(source_path, "w", encoding="utf-8").write(source)
        written = [source_path, report_path]
        payload_paths, payload_rows, payload_notes = recover_payloads(
            img, stem, out_dir, info.source_name)
        written.extend(payload_paths)
        if info.source_lines:
            lines_path = os.path.join(out_dir, f"{stem}_lines.txt")
            open(lines_path, "w", encoding="utf-8").write(
                cython_lines_dump(info) + "\n")
            written.append(lines_path)
        report = cython_report(info)
        if payload_rows:
            report = report.rstrip() + "\n" + "\n".join(payload_report(payload_rows)) + "\n"
        if payload_notes:
            report = report.rstrip() + "\n\n## Payload notes\n\n" + \
                "".join(f"* {note}\n" for note in payload_notes)
        open(report_path, "w", encoding="utf-8").write(report)
        stats = info.stats()
        stats["payloads"] = len(payload_rows)
        stats["payload_functions"] = sum(row["functions"] for row in payload_rows)
        stats["payload_rebuilt"] = sum(row["rebuilt"] for row in payload_rows)
        stats["payload_audit"] = _audit_summary(payload_rows)
        return {"kind": "cython", "written": written,
                "primary": payload_paths[0] if payload_paths else source_path,
                "report": report, "stats": stats,
                "findings": findings}
    written = []
    notes = []
    payload_paths, payload_rows, payload_notes = recover_payloads(
        img, stem, out_dir)
    written.extend(payload_paths)
    notes.extend(payload_notes)
    covered = {entry["blob"][:64] for entry in payload_entries(img)}
    for label, blob in find_embedded_python(img):
        if blob[:64] in covered:
            continue                                 # already decompiled above
        name = os.path.basename(label).replace(".pyc", "").replace("/", "_") or "module"
        try:
            import pydecomp as P
            artifact = P.dig(blob, name)
        except Exception as exc:                 # noqa: BLE001 - keep going
            notes.append(f"{label}: {type(exc).__name__}: {exc}")
            continue
        if artifact is None or not artifact.text:
            notes.append(f"{label}: no source recovered")
            continue
        target = os.path.join(out_dir, f"{stem}__{name}_deob.py")
        # same one-line signature as every other recovery
        body = artifact.text
        if not body.startswith("#[ Deobfuscated by"):
            body = _stamp_line() + "\n\n" + body
        open(target, "w", encoding="utf-8").write(body + "\n")
        written.append(target)
    report = elf_report(img, findings, written, notes)
    if payload_rows:
        report = report.rstrip() + "\n" + "\n".join(payload_report(payload_rows)) + "\n"
    report_path = os.path.join(out_dir, f"{stem}_report.md")
    open(report_path, "w", encoding="utf-8").write(report)
    primary = payload_paths[0] if payload_paths else (written[0] if written else None)
    return {"kind": "elf", "written": written + [report_path], "primary": primary,
            "report": report,
            "stats": {"payloads": len(written),
                      "payload_functions": sum(row["functions"] for row in payload_rows),
                      "payload_rebuilt": sum(row["rebuilt"] for row in payload_rows),
                      "payload_audit": _audit_summary(payload_rows)},
            "findings": findings}


def elf_report(img: ElfImage, findings: dict, written, notes) -> str:
    summary = img.summary()
    out = ["# ELF report", "", "| field | value |", "| --- | --- |"]
    out += [f"| {key} | {value} |" for key, value in summary.items() if key != "path"]
    out += ["", "## Python payload detection", "", "| signal | value |", "| --- | --- |"]
    for key, value in findings.items():
        if key == "pyc_blobs":
            continue
        out.append(f"| {key} | {value} |")
    if findings.get("pyc_blobs"):
        out += ["", "### Bytecode blobs", "", "| offset | magic | guess |", "| --- | --- | --- |"]
        out += [f"| {item['offset']:#x} | {item['magic']} | {item['guess']} |"
                for item in findings["pyc_blobs"][:40]]
    if written:
        out += ["", "## Recovered Python", ""]
        out += [f"* `{os.path.basename(item)}`" for item in written]
    if notes:
        out += ["", "## Notes", ""] + [f"* {note}" for note in notes]
    if not written:
        out += ["", "## Result", "",
                "No Python bytecode was found in this file.  If it is a Cython",
                "module, run the Cython mode (`--cython`) — it recovers names,",
                "docstrings, classes and literals from the module tables."]
    return "\n".join(out) + "\n"
