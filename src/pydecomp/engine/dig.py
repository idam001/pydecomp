"""pydecomp - dig."""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import re
import tarfile
import zipfile

from ..bytecode.codeobj import CodeObj
from ..bytecode.harvest import harvest_constants, harvest_inline_text
from ..bytecode.magic import parse_pyc
from ..bytecode.marshal_reader import parse_marshal_blob
from ..core.util import _as_text, _payload_variants, looks_like_python
from ..decoders.emoji import parses_as_python
from ..decoders.pyarmor import describe as pyarmor_describe
from ..decoders.pyarmor import detect as pyarmor_detect
from ..decoders.pyarmor import recovery_note as pyarmor_note
from ..decoders.hyperion import is_hyperion
from ..decoders.hyperion import note as hyperion_note
from ..decoders.hyperion import payload as hyperion_payload
from ..decoders.pyinstaller import (carchive_entries, entry_script, is_carchive,
                                    is_pyz, pyz_modules)
from ..decoders.pyobfuscate_com import decrypt as pyobfuscate_decrypt
from ..decoders.pyobfuscate_com import is_pyobfuscate
from ..decoders.pyobfuscate_com import note as pyobfuscate_note
from ..engine.artifact import Artifact, _score
from ..engine.decode import deep_decode
from ..engine.normalize import normalize, with_unknown_preamble
from ..engine.peel import peel
from ..eval.expr_eval import resolve_expression_payload
from ..lift.module import LIFT_QUALITY, lift_module
from ..limits import MAX_LAYERS

def carve_strings(data: bytes, minimum: int = 6, limit: int = 400) -> list[str]:
    """Pull printable strings out of a binary blob (for pyc/marshal triage)."""
    out: list[str] = []
    for m in re.finditer(rb"[ -~]{%d,}" % minimum, data):
        try:
            sdec = m.group(0).decode("ascii", "ignore")
        except Exception:
            continue
        if sdec not in out:
            out.append(sdec)
        if len(out) >= limit:
            break
    return out

def _from_code(mod: CodeObj, version: tuple, trace: list, depth: int,
               seen: set, max_depth: int) -> Artifact | None:
    """Bytecode in hand: look for a hidden string, then recorded constants."""
    label = mod.qualname or mod.name
    trace.append(f"code object <{label}> 3.{version[1]} · {len(mod.code):,} B bytecode")

    inline = harvest_inline_text(mod)
    if inline and parses_as_python(inline):
        trace.append(f"inline integer stream → source ({len(inline):,} chars)")
        found = _follow_source(inline, trace, depth + 1, seen, max_depth)
        if found is not None:
            return found

    for const in harvest_constants(mod):
        blob = const.encode("utf-8", "surrogateescape") if isinstance(const, str) else const
        digest = hashlib.sha256(blob).digest()
        if digest in seen:
            continue
        seen.add(digest)
        decoded, chain = deep_decode(blob)
        if decoded is None:
            continue
        trace.append(f"constant blob {len(blob):,} B → {'+'.join(chain)}")
        found = _digest_bytes(decoded, trace, depth + 1, seen, max_depth)
        if found is not None and found.is_source:
            return found

    text = lift_module(mod, version)
    if LIFT_QUALITY["proven"]:
        trace.append("no further text layer → rebuilt whole module as source")
        return Artifact(text, "source", trace, _score(text, "source"))
    trace.append("no further text layer → lifting bytecode to readable Python")
    return Artifact(text, "pseudo", trace, _score(text, "pseudo"))

def _follow_source(source: str, trace: list, depth: int, seen: set,
                   max_depth: int) -> Artifact | None:
    """Python source in hand: peel loader chains, recurse into bytecode payloads."""
    if depth > max_depth:
        return None
    layers, _notes = peel(source, MAX_LAYERS)
    for layer in layers:
        recipe = " → ".join(layer.recipe) if layer.recipe else "raw"
        trace.append(f"layer {layer.index}: {recipe} · {layer.size:,} B")
    decoded_any = any(layer.recipe for layer in layers)

    # A sample whose payload is *computed* rather than stored peels to a single
    # "raw" layer - the input itself.  Running the expression engine first is
    # what turns `globals()['ex'+'ec'](...)` into a payload instead of a shrug.
    if not decoded_any:
        found = _follow_expression_payload(source, trace, depth, seen, max_depth)
        if found is not None:
            return found

    if layers:
        last = layers[-1]
        if last.is_source and decoded_any:
            text = normalize(last.data.decode("utf-8", "surrogateescape"), "source", False)
            if parses_as_python(text):
                return Artifact(text, "source", trace, _score(text, "source"))
        if decoded_any:
            found = _digest_bytes(last.data, trace, depth + 1, seen, max_depth)
            if found is not None:
                return found

    found = _follow_expression_payload(source, trace, depth, seen, max_depth)
    if found is not None:
        return found

    if looks_like_python(source):
        text = normalize(source, "source", False)
        if parses_as_python(text):
            return Artifact(text, "source", trace, _score(text, "source"))
    return None

def _follow_expression_payload(source: str, trace: list, depth: int, seen: set,
                               max_depth: int) -> Artifact | None:
    """Obfuscators that *compute* their payload instead of storing it.

    The classic shape is a pile of ``%s``-template lambdas that rebuild names
    like ``__import__``/``exec``, followed by one giant expression that decodes
    a blob and hands it to ``exec``.  ``ExprEval`` follows that expression with
    pure operations only, on the interpreter version the sample targets.
    """
    if depth > max_depth:
        return None
    try:
        resolved = resolve_expression_payload(source)
    except Exception:                                # noqa: BLE001 - never fail a run
        return None
    if resolved is None:
        return None
    kind, value = resolved
    if kind == "code":
        version, code = value
        trace.append(f"runtime expression tree evaluated → code object "
                     f"<{getattr(code, 'name', '?')}> for CPython "
                     f"3.{version[1]} · {len(code.code):,} B bytecode")
        found = _from_code(code, version, trace, depth + 1, seen, max_depth)
        if found is not None:
            return found
        return None
    blob = value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value
    trace.append(f"runtime expression tree evaluated → {kind} payload "
                 f"({len(blob):,} B)")
    if kind == "text":
        digest = hashlib.sha256(blob).digest()
        if digest in seen:
            return None
        seen.add(digest)
        return _follow_source(value, trace, depth + 1, seen, max_depth)
    # let the digester register this digest itself - adding it here made the
    # very next call treat the payload as already visited and return None
    for candidate in _payload_variants(blob):
        found = _digest_bytes(candidate, trace, depth + 1, seen, max_depth)
        if found is not None:
            return found
    return None

def _digest_bytes(data: bytes, trace: list, depth: int, seen: set,
                  max_depth: int) -> Artifact | None:
    """Unknown bytes: container, pyc, marshal stream, text or encoded blob."""
    if depth > max_depth or not data:
        return None
    digest = hashlib.sha256(data).digest()
    if digest in seen:
        return None
    seen.add(digest)

    if is_carchive(data):
        entries = carchive_entries(data)
        readable = [item for item in entries if item[1]]
        trace.append(f"PyInstaller CArchive · {len(entries)} entries, "
                     f"{len(readable)} readable")
        best = None
        # the program itself first, then the embedded module table
        chosen = entry_script(entries)
        ordered = ([chosen] if chosen else []) + [
            (name, blob) for name, blob, typecode in entries[:16]
            if blob and (typecode == "z" or blob[:4] == b"PYZ\x00")]
        for name, blob in ordered:
            if is_pyz(blob):
                modules = pyz_modules(blob)
                trace.append(f"PYZ archive {name} · {len(modules)} module(s)")
                for module_name, module_blob in modules[:16]:
                    inner = _digest_bytes(module_blob, trace, depth + 1, seen,
                                          max_depth)
                    if inner is None:
                        continue
                    if inner.is_source:
                        return inner
                    best = best or inner
                continue
            inner = _digest_bytes(blob, trace, depth + 1, seen, max_depth)
            if inner is None:
                continue
            if inner.is_source:
                return inner
            best = best or inner
        if best is not None:
            return best

    if is_pyz(data):
        modules = pyz_modules(data)
        trace.append(f"PYZ archive · {len(modules)} module(s)")
        best = None
        for module_name, module_blob in modules[:24]:
            inner = _digest_bytes(module_blob, trace, depth + 1, seen, max_depth)
            if inner is None:
                continue
            if inner.is_source:
                return inner
            best = best or inner
        if best is not None:
            return best

    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = [n for n in archive.namelist()
                         if n.endswith((".pyc", ".py", ".pyz", ".pyd"))]
                trace.append(f"zip container · {len(names)} python member(s)")
                best = None
                for name in names[:12]:
                    inner = _digest_bytes(archive.read(name), trace, depth + 1,
                                          seen, max_depth)
                    if inner is None:
                        continue
                    if inner.is_source:
                        return inner
                    if best is None or (inner.kind == "pseudo" and best.kind != "pseudo"):
                        best = inner
                if best is not None:
                    return best
        except Exception:
            pass

    if data[:2] == b"\x1f\x8b" or (data[:2] == b"BZ") or data[:6] == b"\xfd7zXZ\x00":
        try:
            inner = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else (
                bz2.decompress(data) if data[:2] == b"BZ" else lzma.decompress(data))
            trace.append(f"compressed container · {len(inner):,} B")
            found = _digest_bytes(inner, trace, depth + 1, seen, max_depth)
            if found is not None:
                return found
        except Exception:                            # noqa: BLE001
            pass

    try:                                             # .tar / .tar.gz / .whl in disguise
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = [m for m in archive.getmembers()
                       if m.isfile() and m.name.endswith((".py", ".pyc", ".pyz"))]
            if members:
                trace.append(f"tar container · {len(members)} python member(s)")
                best = None
                for member in members[:12]:
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    inner = _digest_bytes(handle.read(), trace, depth + 1, seen, max_depth)
                    if inner is None:
                        continue
                    if inner.is_source:
                        return inner
                    best = best or inner
                if best is not None:
                    return best
    except Exception:                                # noqa: BLE001
        pass

    version, mod = parse_pyc(data)
    if mod is not None:
        trace.append(f"pyc header · CPython {version[0]}.{version[1]} · {len(data):,} B")
        found = _from_code(mod, version, trace, depth, seen, max_depth)
        if found is not None:
            return found

    if len(data) > 40:
        version, obj, consumed = parse_marshal_blob(data)
        if obj is not None:
            trace.append(f"marshal stream · CPython {version[0]}.{version[1]} "
                         f"({consumed:.0%} consumed)")
            found = _from_code(obj, version, trace, depth, seen, max_depth)
            if found is not None:
                return found

    text = _as_text(data)
    if text is not None:
        if looks_like_python(text):
            found = _follow_source(text, trace, depth, seen, max_depth)
            if found is not None:
                return found

    decoded, chain = deep_decode(data)
    if decoded is not None:
        trace.append(f"decoder chain {'+'.join(chain)}")
        found = _digest_bytes(decoded, trace, depth + 1, seen, max_depth)
        if found is not None:
            return found
    return None

def dig(raw: bytes, name: str = "input", max_depth: int = 8) -> Artifact:
    """Universal entry point: figure out what this file is and unpack it."""
    trace: list[str] = []
    # PyArmor: the bootstrap *is* the file, so it is emitted whole.  What the
    # payload hides is described in the report rather than invented into the
    # output.
    early = _as_text(raw)
    if early is None:
        try:
            early = raw.decode("utf-8", "surrogateescape")
        except Exception:                                # noqa: BLE001
            early = None
    if early is not None and is_hyperion(early):
        program, how = hyperion_payload(early)
        if program:
            trace.append(hyperion_note(how))
            found = _follow_source(program, trace, 0, set(), max_depth)
            if found is not None:
                return found
            text = program if program.endswith("\n") else program + "\n"
            return Artifact(text, "source", trace, _score(text, "source"))

    if early is not None and is_pyobfuscate(early):
        plain, facts = pyobfuscate_decrypt(early)
        trace.append(pyobfuscate_note(facts))
        if plain:
            found = _digest_bytes(plain, trace, 1, set(), max_depth)
            if found is not None:
                return found
            text = _as_text(plain)
            if text is not None:
                found = _follow_source(text, trace, 0, set(), max_depth)
                if found is not None:
                    return found
                text = text if text.endswith("\n") else text + "\n"
                return Artifact(text, "source", trace, _score(text, "source"))

    if early is not None:
        armor = (pyarmor_detect(early)
                 if "__pyarmor__" in early or "pyarmor_runtime" in early else None)
        if armor:
            facts = pyarmor_describe(armor["blob"])
            trace.append(pyarmor_note(facts))
            if armor["banner"]:
                trace.append(f"build banner: {armor['banner']}")
            if armor["runtime"]:
                trace.append(f"runtime package: {armor['runtime']}"
                             " (key material lives in its native library)")
            if facts["strings"]:
                trace.append("carved from payload: "
                             + ", ".join(facts["strings"][:6]))
            text = early if early.endswith("\n") else early + "\n"
            return Artifact(text, "source", trace, _score(text, "source"))
    found = _digest_bytes(raw, trace, 0, set(), max_depth)
    if found is None:
        text = _as_text(raw)
        if text is not None and looks_like_python(text):
            text = normalize(text, "source", False)
            return Artifact(text, "source", trace, _score(text, "source"))
        text = ("# no Python layer could be recovered\n"
                f"# input: {name}, {len(raw)} bytes\n"
                f"# sha256 {hashlib.sha256(raw).hexdigest()}\n"
                "# carved strings:\n\n" + "\n".join(carve_strings(raw)) + "\n")
        trace.append("no Python layer recovered → carved printable strings")
        return Artifact(text, "strings", trace, _score(text, "strings"))
    if found.kind in ("source", "pseudo") and not getattr(found, "written", False):
        found.text = with_unknown_preamble(found.text)
    return found
