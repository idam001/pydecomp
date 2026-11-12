"""pydecomp - payload intelligence.

When a packer seals its payload, the code object we *can* read still carries
fingerprints: a name table, source filenames, string constants, and the library
calls the sealed program is built from.  This module harvests them so a sealed
sample still produces something an analyst can act on instead of a shrug.

It is deliberately *not* an unpacker.  Ciphertext stays ciphertext; everything
here is structure that survived packaging.
"""
from __future__ import annotations

import re

from .sealed import classify as classify_sealed
from .sealed import render as render_sealed
from .sealed import summary as sealed_summary

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,40}$")
HEXISH = re.compile(r"^[0-9a-fA-F]{8,}$")
FILENAME = re.compile(r"^[\w./\\-]+\.(?:py|pyc|pyw|so|pyd|txt|json|csv)$", re.I)

# Names every compiled module carries; noise in an intelligence report.
COMMON = frozenset("""
self cls args kwargs none true false not and or if else for while return class def
import from as with try except finally raise pass break continue lambda yield global
nonlocal assert del in is print len str int float list dict set tuple type object
value values name names file files data key keys item items result results index
count total main run start end init new next self_
""".split())

# What an analyst actually wants to know about a sealed payload: does it reach
# for the network, the disk, a subprocess, or another decode layer?
CAPABILITY = {
    "network": ("socket", "connect", "recv", "send", "urlopen", "requests", "http",
                "urllib", "urlretrieve", "smtplib", "ftplib", "paramiko"),
    "subprocess": ("subprocess", "Popen", "system", "spawn", "check_output", "pty",
                   "os.exec", "CreateProcess"),
    "filesystem": ("open", "read", "write", "remove", "unlink", "mkdir", "makedirs",
                   "listdir", "walk", "shutil", "rename", "chmod"),
    "dynamic-code": ("exec", "eval", "compile", "marshal", "loads", "import_module",
                     "__import__", "globals", "setattr"),
    "decode-layers": ("b64decode", "b85decode", "a85decode", "decompress", "zlib",
                      "bz2", "lzma", "fromhex", "unhexlify", "xor"),
    "anti-analysis": ("gettrace", "settrace", "getframe", "currentframe", "f_trace",
                      "inspect", "atexit", "signal", "ptrace", "IsDebuggerPresent"),
    "persistence": ("registry", "winreg", "crontab", "systemd", "startup", "schtasks",
                    "launchd", "rc.local"),
    "credentials": ("password", "passwd", "token", "apikey", "secret", "cookie",
                    "wallet", "seed", "private_key", "keychain"),
}

MIN_STRING = 4
MAX_IDENTIFIERS = 400
MAX_STRINGS = 60
SEALED_FLOOR = 8192          # same floor the engine uses to call a payload sealed


def _printable(text: str) -> bool:
    if len(text) < MIN_STRING:
        return False
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return good >= len(text) * 0.92


def _tokens(name: str) -> set[str]:
    """Identifier -> the call target it names: ``__import__`` -> ``import``.

    Only the whole name (minus leading/trailing underscores) counts.  Splitting
    further turns ``_walk_tb_with_full_positions`` into an ``os.walk`` claim.
    """
    bare = name.strip("_").lower()
    return {bare} if bare else set()


VOCAB = {bucket: {word.strip("_").lower() for word in words}
         for bucket, words in CAPABILITY.items()}


def _capabilities(pool) -> dict[str, list[str]]:
    """Which capability buckets the name table touches, matched on whole words.

    Substring matching lies: ``system`` inside an unrelated name would claim the
    sample runs a subprocess.  Only an exact identifier word counts.
    """
    found: dict[str, list[str]] = {}
    for name in pool:
        words = _tokens(name)
        for bucket, vocabulary in VOCAB.items():
            if words & vocabulary:
                bucket_names = found.setdefault(bucket, [])
                if name not in bucket_names:
                    bucket_names.append(name)
    return {bucket: sorted(names) for bucket, names in sorted(found.items())}


# A code object reaches us as pydecomp's own wrapper (short attribute names) or
# as the interpreter's real code object (``co_`` names).  Support both, so the
# harvester cannot silently return nothing for a payload it was handed.
ALIASES = {
    "names": ("names", "co_names"),
    "varnames": ("varnames", "co_varnames"),
    "freevars": ("freevars", "co_freevars"),
    "cellvars": ("cellvars", "co_cellvars"),
    "consts": ("consts", "co_consts"),
}


def _attr(unit, field: str, default=None):
    for name in ALIASES[field]:
        if hasattr(unit, name):
            return getattr(unit, name)
    return default if default is not None else []


def _walk(code, depth: int = 0, seen: set | None = None) -> list:
    seen = seen if seen is not None else set()
    if id(code) in seen:
        return []
    seen.add(id(code))
    found = [(depth, code)]
    for const in _attr(code, "consts"):
        if hasattr(const, "code") or hasattr(const, "co_code"):
            found.extend(_walk(const, depth + 1, seen))
    return found


def harvest(code, xor: bool = False) -> dict:
    """Identifiers, filenames, readable strings and capabilities of a payload.

    ``xor`` stays off by default.  A single-byte XOR always yields *some*
    printable text, and on a marshalled payload every candidate we ever measured
    was noise, so shipping it would be a false-positive factory.
    """
    identifiers: dict[str, int] = {}
    filenames: dict[str, int] = {}
    strings: dict[str, int] = {}
    decoded: dict[str, int] = {}
    junk = 0
    blobs = 0
    units = 0
    sealed: list[dict] = []
    names_seen: set[str] = set()

    for _depth, unit in _walk(code):
        units += 1
        pools = [_attr(unit, "names"), _attr(unit, "varnames"),
                 _attr(unit, "freevars"), _attr(unit, "cellvars")]
        for pool in pools:
            for name in pool:
                if not isinstance(name, str):
                    continue
                names_seen.add(name)
                if FILENAME.match(name):
                    filenames[name] = filenames.get(name, 0) + 1
                elif IDENT.match(name) and name.lower() not in COMMON:
                    identifiers[name] = identifiers.get(name, 0) + 1
        for const in _attr(unit, "consts"):
            if isinstance(const, str):
                if FILENAME.match(const):
                    filenames[const] = filenames.get(const, 0) + 1
                elif _printable(const) and not IDENT.match(const):
                    if _looks_like_junk(const):
                        junk += 1                    # counted, never printed
                    else:
                        strings[const] = strings.get(const, 0) + 1
                elif _looks_like_junk(const):
                    junk += 1
            elif isinstance(const, bytes):
                blobs += 1
                if len(const) >= SEALED_FLOOR:
                    sealed.append(classify_sealed(bytes(const)))
                if xor:
                    text = const.decode("utf-8", "replace")
                    inner = b""
                    if HEXISH.match(text):
                        try:
                            inner = bytes.fromhex(text)
                        except ValueError:
                            inner = b""
                    for candidate in _xor_candidates(inner or const):
                        decoded[candidate] = decoded.get(candidate, 0) + 1
                elif _printable(const.decode("utf-8", "replace")):
                    strings[const.decode("utf-8", "replace")] = \
                        strings.get(const.decode("utf-8", "replace"), 0) + 1

    return {
        "identifiers": sorted(identifiers, key=lambda n: (-identifiers[n], n))[:MAX_IDENTIFIERS],
        "filenames": sorted(filenames, key=lambda n: (-filenames[n], n))[:20],
        "strings": sorted(strings, key=lambda s: (-len(s), s))[:MAX_STRINGS],
        "decoded": sorted(decoded, key=lambda s: (-len(s), s))[:MAX_STRINGS],
        "capabilities": _capabilities(names_seen),
        "sealed": sealed,
        "blob_count": blobs,
        "junk_strings": junk,
        "units": units,
        "xor_searched": bool(xor),
    }


def _looks_like_junk(text: str) -> bool:
    """CJK filler is how this family pads names; it is not information."""
    wide = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    return wide >= max(2, len(text) // 2)


# --- single-byte XOR, kept behind a flag until it can be verified ------------
VOWELS = set("aeiouyAEIOUY")
IDENT_ONLY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,40}$")
PATHISH = re.compile(r"^[\w./\\-]{3,120}\.(?:py|pyc|pyw|pyd|so|json|txt|csv|cfg|ini|log|exe|dll|sh|bat)$", re.I)
URLISH = re.compile(r"^(?:https?|ftp)://[^\s]+$|^[\w.-]+\.(?:com|net|org|ru|cn|top|xyz|info|io)(?:/\S*)?$", re.I)
REPRISH = re.compile(r"^[\[({]\s*['\"]")


def _readable_word(word: str) -> bool:
    """A word an author could have typed: it has a vowel and no consonant wall."""
    if len(word) < 3:
        return False
    lowered = word.lower()
    if not any(ch in VOWELS for ch in lowered):
        return False
    run = best = 0
    for ch in lowered:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best < 5


def _alphabet_run(text: str) -> int:
    """Longest run of alphabetically consecutive letters (abc, fedcba, ijklmn)."""
    best = run = 1
    for previous, current in zip(text, text[1:]):
        if previous.isalpha() and current.isalpha() and abs(ord(current.lower()) - ord(previous.lower())) == 1:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best


def _plausible(text: str) -> bool:
    """Precision first: a decoded literal must be a recognisable kind of thing."""
    if not text or any(ord(ch) < 0x20 and ch not in "\t\n" for ch in text):
        return False
    if any(ord(ch) > 0x7E for ch in text):
        return False
    if _alphabet_run(text) >= 4:
        return False
    stripped = text.strip()
    if IDENT_ONLY.match(stripped) or PATHISH.match(stripped) or URLISH.match(stripped):
        return True
    if REPRISH.match(stripped) and stripped.count(",") >= 1:
        return True
    words = [word for word in re.split(r"[^A-Za-z]+", stripped) if len(word) >= 2]
    if len(words) >= 3:
        readable = [word for word in words if _readable_word(word)]
        if len(readable) >= int(len(words) * 0.7) and len(readable) >= 2:
            letters = sum(ch.isalpha() for ch in stripped)
            if letters >= len(stripped) * 0.6:
                return True
    return False


def _xor_candidates(blob: bytes) -> list[str]:
    """Single-byte XOR is the cheapest string cipher there is; try all of them."""
    out: list[str] = []
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in blob)
        if any(byte > 0x7E or (byte < 0x20 and byte not in (9, 10)) for byte in decoded):
            continue
        text = decoded.decode("ascii")
        if _plausible(text):
            out.append(text)
    return out


# --- rendering -------------------------------------------------------------
def _columns(items: list[str], across: int = 4, width: int = 30) -> list[str]:
    rows = []
    for start in range(0, len(items), across):
        chunk = items[start:start + across]
        rows.append("  ".join(item[:width].ljust(width) for item in chunk).rstrip())
    return rows


def summary(intel: dict) -> str:
    """One line for the DONE panel."""
    parts = [f"{len(intel.get('identifiers') or [])} name(s)"]
    caps = intel.get("capabilities") or {}
    if caps:
        parts.append(f"reaches for {', '.join(list(caps)[:2])}"
                     + (f" +{len(caps) - 2}" if len(caps) > 2 else ""))
    if intel.get("filenames"):
        parts.append(f"{len(intel['filenames'])} filename(s)")
    if intel.get("sealed"):
        parts.append(sealed_summary(intel["sealed"]).split(" — ")[0])
    return " · ".join(parts)


def render(name: str, intel: dict) -> str:
    """The text file an analyst opens when the payload is sealed."""
    lines = [f"# payload intelligence — {name}", ""]
    lines.append("Nothing here is recovered code. It is what the sealed payload")
    lines.append("still says about itself: its own name table, the library calls")
    lines.append("it is built from, and any identifiers the author left behind.")
    lines.append("")
    caps = intel.get("capabilities") or {}
    if caps:
        lines.append("## what the sealed payload reaches for")
        for bucket, names in caps.items():
            lines.append(f"  {bucket:<14} {', '.join(names[:12])}"
                         + (f" (+{len(names) - 12})" if len(names) > 12 else ""))
        lines.append("")
    if intel.get("identifiers"):
        lines.append(f"## names still in the name table ({len(intel['identifiers'])})")
        for row in _columns(intel["identifiers"]):
            lines.append("  " + row)
        lines.append("")
    lines.extend(render_sealed(intel.get("sealed") or []))
    if intel.get("filenames"):
        lines.append("## source filenames")
        for entry in intel["filenames"]:
            lines.append("  " + entry)
        lines.append("")
    if intel.get("strings"):
        lines.append(f"## readable literals ({len(intel['strings'])})")
        for entry in intel["strings"]:
            lines.append("  " + entry.replace("\n", "\\n")[:160])
        lines.append("")
    if intel.get("decoded"):
        lines.append(f"## literals opened by a single-byte XOR ({len(intel['decoded'])})")
        for entry in intel["decoded"]:
            lines.append("  " + entry[:160])
        lines.append("")
    lines.append("## method")
    lines.append(f"  code objects walked   {intel.get('units', 0)}")
    lines.append(f"  sealed byte blobs     {intel.get('blob_count', 0)}")
    lines.append(f"  CJK filler strings    {intel.get('junk_strings', 0)}  (dropped)")
    lines.append(f"  single-byte XOR       "
                 + ("searched" if intel.get("xor_searched") else
                    "not reported: every candidate measured was noise"))
    lines.append("")
    lines.append("A name table is shared with the packer's own loader, so some of")
    lines.append("these names belong to the packaging code, not to the original")
    lines.append("script. Treat them as leads, not as the program's source.")
    return "\n".join(lines) + "\n"
