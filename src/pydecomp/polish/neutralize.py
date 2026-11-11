"""pydecomp - neutralize."""
from __future__ import annotations

from ..decoders.emoji import parses_as_python
from ..polish.demangle import _ast
from ..terminal.banner import banner, header

_GUARD_MARKERS = ("vmware", "virtualbox", "vbox", "qemu", "sandboxie", "cuckoo",
                  "any.run", "IsDebuggerPresent", "ptrace", "TracerPid",
                  "being_debugged", "procmon", "wireshark", "x64dbg", "ollydbg",
                  "SbieDll", "VBoxService", "wine_get_unix", "hypervisor")

def _is_guard(test) -> bool:
    """Does this condition look like an anti-analysis or expiry check?"""
    try:
        text = _ast.unparse(test)
    except Exception:                                # noqa: BLE001
        return False
    low = text.lower()
    if any(marker.lower() in low for marker in _GUARD_MARKERS):
        return True
    for pattern in ("datetime.now", "date.today", "time.time()", "expir",
                    "machine_id", "hwid", "getnode", "uuid.getnode"):
        if pattern in low:
            return True
    return False

def neutralize_source(text: str) -> tuple[str, list[str]]:
    """Disable anti-VM / anti-debug / expiry guards in a recovered file."""
    notes: list[str] = []
    header, body = "", text
    if text.startswith("#"):
        split = text.find("\n\n")
        if 0 < split < 8000:
            header, body = text[:split + 2], text[split + 2:]
    try:
        tree = _ast.parse(body)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return text, notes
    disabled = 0
    exits = 0
    for node in _ast.walk(tree):
        for field_name in ("body", "orelse", "finalbody"):
            block = getattr(node, field_name, None)
            if not isinstance(block, list):
                continue
            for index, stmt in enumerate(list(block)):
                if not isinstance(stmt, _ast.If) or not _is_guard(stmt.test):
                    continue
                # count the exits we are about to make unreachable
                for inner in _ast.walk(stmt):
                    if isinstance(inner, _ast.Call):
                        try:
                            name = _ast.unparse(inner.func)
                        except Exception:            # noqa: BLE001
                            name = ""
                        if name in ("sys.exit", "os._exit", "quit", "exit"):
                            exits += 1
                # a guard that is not taken must fall through to its own else
                block[index] = _ast.If(
                    test=_ast.Constant(value=False),
                    body=[_ast.Pass()],
                    orelse=stmt.orelse or [],
                )
                disabled += 1
    if not disabled and not exits:
        return text, notes
    try:
        out = _ast.unparse(tree)
    except Exception:                                # noqa: BLE001
        return text, []
    if not parses_as_python(out):
        return text, []
    if disabled:
        notes.append(f"neutralised {disabled} anti-analysis/expiry guard(s)")
    if exits:
        notes.append(f"made {exits} exit call(s) unreachable")
    banner = ("# NEUTRALISED by pydecomp: " + "; ".join(notes) +
              "\n# guards were rewritten as `if False:` - review before running.\n\n")
    return header + banner + out + "\n", notes
