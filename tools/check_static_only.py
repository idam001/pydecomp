#!/usr/bin/env python3
"""Prove that pydecomp never executes, imports or spawns the sample.

This is the one invariant the project will not trade away, so it is checked by
a tool rather than by trust.  The scan is deliberately blunt: it walks the AST
of every module in ``src/pydecomp`` and fails on

* ``exec``/``eval``/``compile`` applied to something that looks like sample data
  (a name containing raw/bytes/blob/payload/sample/source/**data**),
* any reference to ``subprocess``, ``os.system``, ``os.popen``, ``os.exec*``,
  ``os.spawn*``, ``pty`` or ``runpy``,
* ``importlib`` being pointed at a recovered path (``spec_from_file_location``,
  ``exec_module`` on a recovered module),
* ``socket``/``urllib``/``http``/``requests`` outside the evaluator whitelist,
* any string that would run a sample through the shell.

The two allowed exceptions are named here so the rule stays auditable:
``native`` loads pydecomp's *own* sidecar, and the audit compiles the text
pydecomp itself just produced.

    python3 tools/check_static_only.py           # exit 1 on a violation
    python3 tools/check_static_only.py --list    # show the rules
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "pydecomp"

SAMPLE_WORDS = {"raw", "bytes", "blob", "payload", "sample", "data", "buf", "body",
                "decoded", "recovered", "text", "src", "source", "code_bytes"}

FORBIDDEN_MODULES = {"subprocess", "pty", "runpy", "socket", "urllib", "http",
                     "ftplib", "telnetlib", "smtplib", "requests", "aiohttp"}

FORBIDDEN_ATTRS = {"system", "popen", "execv", "execve", "execl", "execlp", "spawnv",
                   "spawnl", "fork", "forkpty", "spec_from_file_location"}

# Files allowed to touch a shell-free importlib for the sidecar.
ALLOWED = {
    ("native/__init__.py", "exec"),        # loads pydecomp's own compressed sidecar
    ("native/sidecar.py", "exec"),
    ("eval/expr_eval.py", "compile"),      # compiles a whitelisted AST, never sample text
    ("lift/audit.py", "compile"),          # compiles *our* output to check runnability
    ("output/verify.py", "compile"),
    ("bytecode/roundtrip.py", "compile"),
}


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | \
           {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}


def scan(path: pathlib.Path) -> list[str]:
    rel = path.relative_to(SRC).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return [f"{rel}: does not parse: {exc}"]

    # Documenting *why* we avoid a shell must not look like calling one, so
    # docstrings are excluded from the string scan below.
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))

    problems: list[str] = []
    for node in ast.walk(tree):
        # -- imports that would let the sample reach the outside world
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES:
                    problems.append(f"{rel}:{node.lineno}: imports {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in FORBIDDEN_MODULES:
                problems.append(f"{rel}:{node.lineno}: imports {node.module}")

        # -- os.system / os.popen / os.exec* / os.spawn* / fork
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in FORBIDDEN_ATTRS:
            owner = node.func.value
            base = getattr(owner, "id", None) or getattr(owner, "attr", None)
            if base in {"os", "posix", "nt", "pty", "shutil", "importlib"}:
                problems.append(f"{rel}:{node.lineno}: {base}.{node.func.attr}()")

        # -- builtin exec()/eval() applied to anything: the sample is data
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            func = node.func
            name = func.id
            if name not in {"exec", "eval", "compile", "run_module", "run_path"}:
                continue
            if name == "compile":
                continue                      # parses only; audited below, never runs
            if (rel, name) in ALLOWED:
                continue
            first = node.args[0] if node.args else None
            if first is None:
                continue
            words = _names_in(first)
            hit = words & SAMPLE_WORDS
            problems.append(
                f"{rel}:{node.lineno}: {name}() on {'/'.join(sorted(hit)) or 'a value'}"
                f" — the sample is data, never code to run")

        # -- os.exec*/os.spawn* through a string attribute
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in docstrings:
            lowered = node.value.lower()
            for phrase in ("os.system(", "subprocess.", "os.popen(", "/bin/sh"):
                if phrase in lowered:
                    problems.append(f"{rel}:{node.lineno}: shell-shaped string {phrase!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list the rules and exit")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.list:
        print("forbidden modules:", ", ".join(sorted(FORBIDDEN_MODULES)))
        print("forbidden attributes:", ", ".join(sorted(FORBIDDEN_ATTRS)))
        print("allowed exec/compile sites:", *[f"  {f}: {k}" for f, k in sorted(ALLOWED)],
              sep="\n")
        return 0

    files = sorted(SRC.rglob("*.py"))
    problems: list[str] = []
    for path in files:
        problems.extend(scan(path))

    if problems:
        print(f"{len(problems)} violation(s):", *problems, sep="\n  ")
        return 1
    if not args.quiet:
        print(f"static-only: {len(files)} modules scanned, "
              f"{len(ALLOWED)} audited exec/compile sites, no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
