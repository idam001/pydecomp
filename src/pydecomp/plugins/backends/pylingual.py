"""Optional PyLingual hand-off: plan the command, then import the result.

PyLingual is a strong CPython decompiler, but it lives outside this package and
runs a model.  pydecomp does not run it, and does not weaken its own guarantee to
pretend otherwise: **the package still never spawns a process.**  What lives here
is the two halves an analyst actually needs.

``plan()``
    The exact command, environment and expected output for a local, offline
    PyLingual run against one ``.pyc``.  Nothing is executed; the analyst runs it
    (or copies it into a lab note).  The environment pins every cache to offline
    so a run cannot reach the network.

``ingest()``
    Takes the file PyLingual wrote, bounds its size, validates it with a
    **compile-only** check, and adopts it as ``<stem>_pylingual.py`` with the same
    one-line provenance stamp the recovery carries.  The result is compared with
    pydecomp's own answer (``compare_text``) so the analyst can see which method
    recovered more, and never has to trust either blindly.

Nothing here imports, executes, or uploads a sample.  PyLingual's own accuracy
varies by version and sample; the compile-only check says the text is valid
Python, never that it is faithful.
"""
from __future__ import annotations

import os
from pathlib import Path

from ...bytecode.magic import parse_pyc
from ...limits import __version__

MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024

#: every cache the model stack might consult is pinned off, so a run is offline
OFFLINE_ENV = {
    "UV_OFFLINE": "1",
    "PIP_NO_INDEX": "1",
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
}


def _read_pyc(path: str) -> tuple[bytes | None, tuple | None, str]:
    source = Path(path)
    if source.suffix.lower() != ".pyc":
        return None, None, "PyLingual takes .pyc input only"
    try:
        if source.stat().st_size > MAX_INPUT:
            return None, None, f"input exceeds the {MAX_INPUT}-byte hand-off limit"
        raw = source.read_bytes()
    except OSError as exc:
        return source, None, f"cannot read input: {exc}"
    version, code = parse_pyc(raw)
    if version is None or code is None:
        return source, None, "input is not a CPython .pyc pydecomp can parse"
    return source, version, ""


def plan(path: str, out_dir: str | None = None) -> dict:
    """Describe a local PyLingual run.  Nothing is executed, nothing is uploaded."""
    source, version, problem = _read_pyc(path)
    if source is None or version is None:
        return {"ok": False, "reason": problem}
    destination = Path(out_dir).expanduser() if out_dir else source.parent
    destination = destination / "pylingual"
    command = ["pylingual", "--out-dir", str(destination.resolve()),
               "--version", f"{version[0]}.{version[1]}", str(source.resolve())]
    return {
        "ok": True,
        "tool": f"pydecomp {__version__}",
        "input": {"name": source.name, "bytes": source.stat().st_size},
        "target": f"{version[0]}.{version[1]}",
        "argv": command,
        "cwd": str(destination.resolve()),
        "env": dict(OFFLINE_ENV),
        "shell": False,
        "uploads": "none — the command reads one local .pyc and writes to a local folder",
        "expect": f"one .py file under {destination}",
        "next": f"pydecomp {source.name} --pylingual-import <that.py> -o {destination.parent}",
        "note": ("pydecomp never runs this command. Run it yourself, then import the "
                 "output; the import is compile-checked and diffed, not executed."),
    }


def ingest(output_path: str, pyc_path: str, out_dir: str | None = None) -> tuple[str | None, str]:
    """Adopt a PyLingual output file after a compile-only validation."""
    source, _version, problem = _read_pyc(pyc_path)
    if source is None:
        return None, problem
    produced = Path(output_path).expanduser()
    try:
        if produced.stat().st_size > MAX_OUTPUT:
            return None, f"PyLingual output exceeds the {MAX_OUTPUT}-byte import limit"
        text = produced.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"cannot read PyLingual output: {exc}"
    try:
        compile(text, str(produced) + "<pylingual>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError, TypeError) as exc:
        return None, f"PyLingual output failed the compile-only check: {exc}"
    stamp = from_provenance()
    body = stamp + "\n" + text.rstrip() + "\n"
    destination = Path(out_dir).expanduser() if out_dir else source.parent
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / (source.stem + "_pylingual.py")
    target.write_text(body, encoding="utf-8")
    return str(target), "compile-only check passed; the sample and the output were not executed"


def from_provenance() -> str:
    """The same single stamp the recovery carries, marked as the other method."""
    from ...terminal.banner import stamp
    return stamp()


def compare(own_source: str, pylingual_path: str) -> dict:
    """Per-function and indicator differences between the two methods."""
    from ...triage.compare import compare_text
    other = Path(pylingual_path).read_text(encoding="utf-8", errors="replace")
    return compare_text(own_source, other, "pydecomp", Path(pylingual_path).name)


def available() -> str:
    """Whether a local PyLingual is on PATH — reported, never invoked."""
    hit = os.environ.get("PYDECOMP_PYLINGUAL")
    if hit:
        return f"configured: {hit}"
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(folder, "pylingual")
        if folder and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return f"on PATH: {candidate}"
    return "not found (optional; pydecomp works without it)"
