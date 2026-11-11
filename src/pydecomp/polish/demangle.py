"""pydecomp - demangle."""
from __future__ import annotations

import ast


_ast = ast          # the polish passes read better with a short name

def _mangled_name(name: str) -> bool:
    """``lIIllIlI``, ``_0x1a2b``, ``O0O0O0`` - the usual decoder-ring names."""
    if len(name) < 4:
        return False
    stripped = name.lstrip("_")
    if not stripped:
        return False
    if name.startswith("_0x") and len(name) > 4:
        return True
    pairs = set(stripped)
    if pairs <= set("lI1O0oO"):
        return len(name) >= 5
    if pairs <= set("Il1"):
        return len(name) >= 5
    if pairs <= set("_-") and len(name) >= 6:
        return True
    if len(name) >= 6 and len(pairs) <= 3 and not name.isalpha():
        return True
    return False

def _demangle(tree, limit: int = 4000) -> dict:
    """Rename decoder-ring identifiers, keeping the original in a comment."""
    used = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Name):
            used.add(node.id)
        elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                               _ast.ClassDef)):
            used.add(node.name)
        elif isinstance(node, _ast.arg):
            used.add(node.arg)
    mapping = {}
    kind = {"func": 0, "class": 0, "name": 0}
    for name in sorted(used):
        if len(mapping) >= limit:
            break
        if not _mangled_name(name):
            continue
        if name.startswith(("__", "pydecomp")):
            continue
        kind["name"] += 1
        candidate = f"v{kind['name']}"
        while candidate in used:
            kind["name"] += 1
            candidate = f"v{kind['name']}"
        mapping[name] = candidate
        used.add(candidate)
    if not mapping:
        return {}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Name) and node.id in mapping:
            node.id = mapping[node.id]
        elif isinstance(node, _ast.arg) and node.arg in mapping:
            node.arg = mapping[node.arg]
        elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                               _ast.ClassDef)) and node.name in mapping:
            node.name = mapping[node.name]
        elif isinstance(node, _ast.Attribute) and node.attr in mapping:
            node.attr = mapping[node.attr]
        elif isinstance(node, _ast.keyword) and node.arg in mapping:
            node.arg = mapping[node.arg]
        elif isinstance(node, _ast.Global):
            node.names = [mapping.get(n, n) for n in node.names]
        elif isinstance(node, _ast.Nonlocal):
            node.names = [mapping.get(n, n) for n in node.names]
    return mapping
