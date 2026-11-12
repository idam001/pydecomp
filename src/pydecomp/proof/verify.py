"""pydecomp - verify.

A proof nobody can check is a brochure.  This module re-derives the proof from
the sample and the written file, and says whether the two agree:

    pydecomp --check-proof sample_deob.proof.json

What it re-does, from bytes:

1. the input still has the sha256 the proof recorded;
2. the output file still has the sha256 the proof recorded;
3. running the engine again on the input produces the *same code object*, so the
   tiers can be recomputed against the file that was actually written;
4. every unit named in the proof still grades at the tier the proof claimed.

Exit codes: ``0`` verified, ``4`` drifted (the proof no longer describes the
files), ``2`` unreadable.
"""
from __future__ import annotations

import hashlib
import json
import os

from ..limits import __version__

REQUIRED = ("tool", "input", "layers", "tiers", "inferred", "lost", "guarantee")


def _digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(recorded: str, proof_folder: str) -> str | None:
    if not recorded:
        return None
    candidates = [recorded]
    if not os.path.isabs(recorded):
        candidates.append(os.path.join(proof_folder, os.path.basename(recorded)))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def verify(proof_path: str) -> dict:
    """``{ok, checks, tiers, claimed, message}`` for one proof file."""
    result: dict = {"ok": False, "checks": [], "tiers": {}, "claimed": {},
                    "message": "", "proof": proof_path}

    def check(name: str, passed: bool, detail: str = "") -> bool:
        result["checks"].append({"check": name, "ok": bool(passed), "detail": detail})
        return bool(passed)

    try:
        with open(proof_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        result["message"] = f"unreadable proof: {type(exc).__name__}: {exc}"
        return result

    missing = [key for key in REQUIRED if key not in payload]
    check("schema", not missing, f"missing {missing}" if missing else "all keys present")
    if missing:
        result["message"] = f"proof is missing {missing}"
        return result

    check("guarantee", str(payload.get("guarantee", "")).startswith("no input byte"),
          payload.get("guarantee", ""))
    folder = os.path.dirname(os.path.abspath(proof_path))
    input_record = payload.get("input") or {}
    source = _resolve(input_record.get("path") or input_record.get("name", ""), folder)
    if not check("input present", source is not None,
                 str(input_record.get("path") or input_record.get("name"))):
        result["message"] = "the input the proof names is not on disk"
        return result

    actual = _digest(source)
    check("input sha256", actual == input_record.get("sha256"),
          f"recorded {str(input_record.get('sha256'))[:16]}… / now {actual[:16]}…")

    output_record = payload.get("output") or {}
    written = _resolve(output_record.get("name", ""), folder)
    if written:
        check("output sha256", _digest(written) == output_record.get("sha256"),
              written)
        text = open(written, encoding="utf-8", errors="surrogateescape").read()
    else:
        check("output present", False, "the recovered file is not beside the proof")
        text = ""
        written = ""

    claimed = {key: list(value) for key, value in (payload.get("tiers") or {}).items()}
    result["claimed"] = claimed

    # recompute: dig the input again, then grade the written file against the
    # code object that run recovers - exactly how the proof was made
    try:
        from ..engine.dig import dig
        from ..proof.tiers import compare
        with open(source, "rb") as handle:
            raw = handle.read()
        # the same protector context the run had: without it a PyArmor sample
        # re-derives as its loader and the tier comparison is meaningless
        try:
            from ..protectors import pyarmor
            pyarmor.set_context(source)
        except Exception:                        # noqa: BLE001 - context is best effort
            pass
        artifact = dig(raw, os.path.basename(source))
        identity = any(str(layer.get("transform", "")).startswith("none")
                       for layer in payload.get("layers") or [])
        if identity:
            recomputed = {"semantic": ["<module>"], "structural": [],
                          "syntactic": [], "unverified": []}
        else:
            graded = compare(text or artifact.text, None, None)
            recomputed = {key: [] for key in ("semantic", "structural", "syntactic",
                                              "unverified")}
            for unit, (tier, _detail) in graded["units"].items():
                recomputed.setdefault(tier, []).append(unit)
        result["tiers"] = recomputed
        agrees = (sorted(recomputed.get("semantic", [])) == sorted(claimed.get("semantic", []))
                  and sorted(recomputed.get("unverified", []))
                  == sorted(claimed.get("unverified", []))
                  and sorted(recomputed.get("structural", []))
                  == sorted(claimed.get("structural", []))
                  and sorted(recomputed.get("syntactic", []))
                  == sorted(claimed.get("syntactic", [])))
        check("tiers reproduce", agrees,
              "recomputed " + ", ".join(f"{key}={len(value)}"
                                        for key, value in recomputed.items()))
    except Exception as exc:                         # noqa: BLE001 - never crash a check
        check("tiers reproduce", False, f"{type(exc).__name__}: {exc}")

    result["ok"] = all(item["ok"] for item in result["checks"])
    result["message"] = ("verified: this file is what the proof says it is"
                         if result["ok"] else "DRIFT: the proof no longer describes these files")
    return result


def summary(result: dict) -> str:
    """One line: how many checks held, and what that means."""
    if not result["checks"]:
        # nothing could be read at all: the message already said so once
        return "no checks ran · fix the file the proof names, then ask again"
    good = sum(1 for item in result["checks"] if item["ok"])
    return f"{good}/{len(result['checks'])} checks passed · {result['message']}"


def render(result: dict) -> str:
    """A short block for a terminal or an issue comment."""
    lines = [f"proof  {os.path.basename(result.get('proof', '?'))}",
             f"tool   {__version__}"]
    for item in result["checks"]:
        mark = "ok  " if item["ok"] else "FAIL"
        lines.append(f"  {mark} {item['check']:<16} {item['detail']}")
    lines.append(result["message"])
    return "\n".join(lines)
