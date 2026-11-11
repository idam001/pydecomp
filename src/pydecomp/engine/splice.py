"""Splicing a recovered payload back onto the code it was cut from.

Most exec chains in the wild carry a self-contained payload, but plenty of
samples build a table, a helper and a key at module level and then hand the
payload only *part* of the program:

    _T = ['...', '...']
    def mix(a, b): return (a ^ b) + 2 * (a & b)
    exec(decompress(decode('...')))          # <- payload uses _T and mix

Recovering just the payload leaves free names behind, so the "recovered"
program would not even import.  This module carries across the outer
definitions the payload actually reads (transitively), and nothing else: the
loader statements themselves are never copied, so no exec chain comes back.
"""
from __future__ import annotations

import ast

_LOADER_NAMES = {"exec", "eval", "compile", "__import__", "execfile", "marshal",
                 "loads", "decompress", "b64decode", "b85decode"}


def _mentions_loader(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in _LOADER_NAMES:
                return True
    return False


def _bound_names(tree) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def _free_names(tree, bound: set[str] | None = None) -> set[str]:
    bound = set(bound or ())
    bound |= _bound_names(tree)
    free = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) \
                and node.id not in bound:
            free.add(node.id)
    return free


def _top_level_defs(source: str) -> tuple[list, dict[str, object]]:
    """Top-level statements, and the index from name -> statement."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], {}
    order: list = []
    index: dict[str, object] = {}
    for stmt in tree.body:
        keep = None
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not _mentions_loader(stmt):
                keep = stmt
        elif isinstance(stmt, ast.Assign) and not _mentions_loader(stmt):
            if all(isinstance(target, ast.Name) for target in stmt.targets):
                keep = stmt
        elif isinstance(stmt, ast.Import):
            keep = stmt
        elif isinstance(stmt, ast.ImportFrom):
            keep = stmt
        if keep is None:
            continue
        order.append(keep)
        if isinstance(keep, (ast.Import, ast.ImportFrom)):
            for alias in keep.names:
                index[(alias.asname or alias.name).split(".")[0]] = keep
        elif isinstance(keep, ast.Assign):
            for target in keep.targets:
                index[target.id] = keep
        else:
            index[keep.name] = keep
    return order, index


def _split_imports(text: str) -> tuple[str, str]:
    """Leading contiguous import lines of a payload, and the rest."""
    lines = text.splitlines()
    index = 0
    block: list[str] = []
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith(("import ", "from ")) and "(" not in stripped:
            block.append(line)
            index += 1
            continue
        break
    if not block:
        return "", text
    return "\n".join(block), "\n".join(lines[index:])


def carry_over(outer: str, payload: str) -> str:
    """Return ``payload`` prefixed with the outer definitions it still needs."""
    if not outer.strip() or not payload.strip():
        return payload
    try:
        payload_tree = ast.parse(payload)
    except SyntaxError:
        return payload
    order, index = _top_level_defs(outer)
    if not index:
        return payload

    have = _bound_names(payload_tree)
    needed: set[str] = set()
    frontier = [name for name in _free_names(payload_tree) if name not in have]
    while frontier:
        name = frontier.pop()
        if name in needed or name in have:
            continue
        stmt = index.get(name)
        if stmt is None:
            continue
        needed.add(name)
        for extra in _free_names(ast.Module(body=[stmt], type_ignores=[])):
            if extra not in needed and extra not in have:
                frontier.append(extra)

    if not needed:
        return payload
    carried = [stmt for stmt in order
               if any(name in needed for name, binding in index.items() if binding is stmt)]
    # imports first, then definitions in the order the sample had them
    carried.sort(key=lambda stmt: 0 if isinstance(stmt, (ast.ImportFrom, ast.Import)) else 1)
    if not carried:
        return payload
    try:
        prefix = "\n\n".join(ast.unparse(stmt) for stmt in carried)
    except Exception:                                  # noqa: BLE001
        return payload
    # keep the module's imports at the top: the payload usually opens with them
    head, rest = _split_imports(payload)
    if head:
        merged = head + "\n\n" + prefix + "\n\n" + rest
    else:
        merged = prefix + "\n\n" + payload
    try:
        compile(merged, "<splice>", "exec", dont_inherit=True)
    except SyntaxError:
        return payload
    return merged
