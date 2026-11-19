"""Bounded, version-aware textual dump of a .pyc without executing it."""
from __future__ import annotations

from ..bytecode.codeobj import CodeObj
from ..bytecode.disassembler import disassemble
from ..bytecode.magic import parse_pyc

MAX_CODE_OBJECTS = 10_000
MAX_INSTRUCTIONS = 2_000_000


def dump_pyc(data: bytes) -> str:
    """Return a readable instruction/constants dump, or raise ValueError.

    Parsing is performed by pydecomp's bounded marshal reader. No Python code
    from the input is imported, compiled, or executed.
    """
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("input exceeds the 64 MiB disassembly limit")
    version, module = parse_pyc(data)
    if version is None:
        raise ValueError("unknown or unsupported CPython .pyc magic")
    if module is None:
        raise ValueError(f"recognized CPython {version[0]}.{version[1]} magic, "
                         "but its marshal code object could not be parsed")
    lines = [f"pyc-disassembly: CPython {version[0]}.{version[1]}",
             f"input-bytes: {len(data)}", "execution: none", ""]
    pending = [(module, "<module>", 0)]
    object_count = 0
    instruction_count = 0
    while pending:
        code, path, depth = pending.pop()
        object_count += 1
        if object_count > MAX_CODE_OBJECTS:
            lines.append("[truncated: code-object limit reached]")
            break
        indent = "  " * min(depth, 32)
        name = code.qualname or code.name or path
        lines += [f"{indent}code-object {name!r}  firstlineno={code.firstlineno} "
                  f"bytes={len(code.code)}", f"{indent}  names={list(code.names)!r}"]
        children = []
        for index, const in enumerate(code.consts if isinstance(code.consts, (list, tuple)) else ()):
            if isinstance(const, CodeObj):
                children.append((const, f"{path}.{const.qualname or const.name or index}", depth + 1))
        for offset, opname, arg, detail in disassemble(code, version):
            instruction_count += 1
            if instruction_count > MAX_INSTRUCTIONS:
                lines.append(f"{indent}  [truncated: instruction limit reached]")
                pending.clear()
                break
            suffix = f"  {detail}" if detail else ""
            lines.append(f"{indent}  {offset:06d}  {opname:<32} {arg:>6}{suffix}")
        pending.extend(reversed(children))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
