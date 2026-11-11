"""pydecomp - codeobj."""
from __future__ import annotations


class CodeObj:
    """Version-neutral stand-in for a CPython code object."""

    __slots__ = ("argcount", "posonly", "kwonly", "stacksize", "flags", "code", "consts",
                 "names", "varnames", "kinds", "filename", "name", "qualname",
                 "firstlineno", "linetable", "exceptiontable")

    def __init__(self):
        self.argcount = self.posonly = self.kwonly = self.stacksize = self.flags = 0
        self.code = b""
        self.consts = ()
        self.names = ()
        self.varnames = ()
        self.kinds = b""
        self.filename = ""
        self.name = ""
        self.qualname = ""
        self.firstlineno = 0
        self.linetable = b""
        self.exceptiontable = b""

    def __repr__(self):
        return (f"<code {self.qualname or self.name} "
                f"consts={len(self.consts)} names={len(self.names)}>")

    @property
    def varnames_list(self):
        return list(self.varnames)

def codeobj_from_host(compiled) -> CodeObj:
    """Mirror a live code object into the reader's own structure."""
    code = CodeObj()
    code.argcount = compiled.co_argcount
    code.posonly = getattr(compiled, "co_posonlyargcount", 0)
    code.kwonly = compiled.co_kwonlyargcount
    code.stacksize = compiled.co_stacksize
    code.flags = compiled.co_flags
    code.code = compiled.co_code
    code.consts = tuple(codeobj_from_host(item) if hasattr(item, "co_code") else item
                        for item in compiled.co_consts)
    code.names = tuple(compiled.co_names)
    code.varnames = tuple(compiled.co_varnames)
    code.filename = compiled.co_filename
    code.name = compiled.co_name
    code.qualname = getattr(compiled, "co_qualname", compiled.co_name)
    code.firstlineno = compiled.co_firstlineno
    return code

_last_module_code = None
