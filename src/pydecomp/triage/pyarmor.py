"""pydecomp - pyarmor."""
from __future__ import annotations


_PYARMOR_MARKERS = ("__pyarmor__", "pyarmor_runtime", "CO_PYARMOR_OBFUSCATED",
                    "PyArmor", "pyarmor")

def pyarmor_markers(source: str) -> list[str]:
    hits = [marker for marker in _PYARMOR_MARKERS if marker in source]
    return hits

def pyarmor_note(source: str, siblings: list[str] | None = None) -> str | None:
    """One honest line about PyArmor protection, or None."""
    hits = pyarmor_markers(source)
    if not hits:
        return None
    runtime = [name for name in (siblings or []) if name.startswith("pyarmor_runtime")]
    if runtime:
        return ("PyArmor wrapper detected · runtime library present "
                f"({runtime[0]}) · payload is AES-CTR encrypted per code object; "
                "plaintext needs the matching key table - extract it with "
                "'--artifacts' and analyse the runtime separately")
    return ("PyArmor wrapper detected · the guarded code objects stay encrypted "
            "without the matching pyarmor_runtime library; what is recovered here "
            "is the wrapper and its constants")

def extract_pyarmor_blobs(data: bytes) -> list[bytes]:
    """Carve the long binary runs a PyArmor wrapper hides its payload in."""
    blobs = []
    run = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            if len(run) >= 96:
                blobs.append(bytes(run))
            run = bytearray()
        else:
            run.append(byte)
    if len(run) >= 96:
        blobs.append(bytes(run))
    return blobs[:8]
