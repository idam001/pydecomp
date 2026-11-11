"""pydecomp - verify."""
from __future__ import annotations

import ast
import builtins
import re


def _exec_dry_run(path: str, timeout: float = 8.0) -> tuple[bool, str]:
    """Item 28: a *static* runnability check - compile, resolve, report.

    The first version shelled out and imported the sample with the network
    stubbed.  That broke the tool's own promise (and gate v5): a deobfuscator
    must never execute the thing it is analysing.  So this does the work a
    dry run was there for, without running anything: it compiles the file,
    resolves every global it can, and names what it could not.
    """
    try:
        with open(path, "rb") as handle:
            source = handle.read()
    except OSError as exc:
        return False, f"cannot read: {exc}"
    try:
        compile(source, path, "exec")
    except SyntaxError as exc:
        return False, f"syntax error line {exc.lineno}: {exc.msg}"
    except (ValueError, MemoryError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return False, f"unparseable: {exc}"
    defined = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            defined.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, ast.alias):
            defined.add((node.asname or node.name).split(".")[0])
        elif isinstance(node, ast.Global):
            defined.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
    missing = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in defined:
                missing.add(node.id)
    if missing:
        sample = ", ".join(sorted(missing)[:6])
        return False, (f"compiles, but {len(missing)} name(s) never resolve: {sample}")
    hazards = []
    for label, pattern in (("shell", r"os\.(system|popen|execv|spawn\w*)"),
                           ("network", r"(socket\.|requests\.|urlopen|http\.client)"),
                           ("filesystem", r"(shutil\.rmtree|os\.remove|unlink)"),
                           ("persistence", r"(schtasks|crontab|Startup|reg add)")):
        if re.search(pattern, source.decode("utf-8", "replace")):
            hazards.append(label)
    if hazards:
        return True, "compiles, every name resolves · would touch " + ", ".join(hazards)
    return True, "compiles, every name resolves"
