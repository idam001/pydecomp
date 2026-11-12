"""pydecomp - roundtrip."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj, codeobj_from_host
from ..bytecode.decompiler6 import _operand_key
from ..bytecode.disassembler import disassemble
from ..bytecode.magic import host_version

def _stream_pairs(code, version):
    """(offset, opcode, operand-key) for one code object, jumps excluded."""
    pairs = []
    for offset, opname, arg, _text in disassemble(code, version):
        if opname in ("RESUME", "CACHE", "NOP", "EXTENDED_ARG", "NOT_TAKEN",
                      "EXTENDED_OP"):
            continue
        if "JUMP" in opname or opname in ("FOR_ITER", "SEND"):
            continue                      # layout differs, structure is compared
        pairs.append((opname, _operand_key(code, opname, arg)))
    return pairs

def exact_match(code: CodeObj, text: str, version: tuple):
    """Recompile ``text`` and diff its instruction stream against ``code``.

    Returns ``(matched, total, first_diff)``.  When ``matched == total`` the
    reconstruction is instruction-for-instruction identical to the original for
    this interpreter - the strongest statement static recovery allows.
    """
    try:
        compiled = compile(text, "<identity>", "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return 0, 1, "does not compile"
    mine = codeobj_from_host(compiled)
    host = host_version()
    if version != host:
        return 0, 1, f"original is {version[0]}.{version[1]}, host is {host[0]}.{host[1]}"
    left = _stream_pairs(code, version)
    right = _stream_pairs(mine, version)
    matched = 0
    first = None
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None
        if a == b:
            matched += 1
        elif first is None:
            first = f"#{index}: original {a} vs rebuilt {b}"
    return matched, max(len(left), len(right)), first

def _recorded():
    """Where the lifter actually records the module it rebuilt."""
    from ..bytecode import codeobj as _codeobj
    from ..lift import module as _lift
    code = (getattr(_lift, "_last_module_code", None)
            or getattr(_codeobj, "_last_module_code", None))
    return code, getattr(_lift, "_last_module_version", None)


def identity_report(text: str, version: tuple, limit: int = 6) -> list:
    """Per-function instruction identity of a whole-module reconstruction."""
    module_code, module_version = _recorded()
    if module_version is not None:
        version = module_version
    if module_code is None:
        return ["no module code object recorded yet"]
    host = host_version()[:2]
    if tuple(version[:2]) != tuple(host):
        return [f"cross-version sample: original is {version[0]}.{version[1]}, host "
                f"is {host[0]}.{host[1]} - instruction streams cannot be compared "
                f"across interpreter versions"]
    try:
        compiled = compile(text, "<identity>", "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return ["does not compile"]
    rebuilt = codeobj_from_host(compiled)
    lines = []
    total = matched = 0
    for name, orig, mine in _paired_functions(module_code, rebuilt):
        left = _stream_pairs(orig, version)
        right = _stream_pairs(mine, version)
        same = 0
        detail = ""
        for index in range(max(len(left), len(right))):
            a = left[index] if index < len(left) else None
            b = right[index] if index < len(right) else None
            if a == b:
                same += 1
            elif not detail:
                detail = f"{a} != {b}"
        total += max(len(left), len(right))
        matched += same
        if same != max(len(left), len(right)) and len(lines) < limit:
            lines.append(f"{name}: {same}/{max(len(left), len(right))}  {detail}")
    share = matched / total if total else 0.0
    return [f"instruction identity: {matched}/{total} ({share:.1%})"] + lines

def _paired_functions(original, rebuilt):
    """Pair code objects by qualified name, in the order the original has them."""
    def walk(code, out):
        out.append(code)
        for const in code.consts:
            if isinstance(const, CodeObj):
                walk(const, out)
        return out

    mine = {}
    for node in walk(rebuilt, []):
        mine.setdefault(getattr(node, "qualname", None) or node.name, []).append(node)
    for node in walk(original, []):
        key = getattr(node, "qualname", None) or node.name
        bucket = mine.get(key)
        if bucket:
            yield key, node, bucket.pop(0)
