"""Static comparison for two recovered Python source files."""
from __future__ import annotations

import ast
import difflib
import hashlib
from pathlib import Path

from .iocs import extract


def _functions(source: str) -> dict[str, str]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return {}
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            try:
                normalized = ast.dump(node, annotate_fields=True, include_attributes=False)
            except (TypeError, ValueError):
                continue
            result[node.name] = hashlib.sha256(normalized.encode()).hexdigest()
    return result


def compare_text(left: str, right: str, left_name: str = "left.py",
                 right_name: str = "right.py") -> dict:
    """Compare text, named AST units, and extracted indicators without execution."""
    left_units, right_units = _functions(left), _functions(right)
    left_iocs = extract(left).get("iocs", {})
    right_iocs = extract(right).get("iocs", {})
    all_ioc_types = sorted(set(left_iocs) | set(right_iocs))
    ioc_delta = {
        kind: {"added": sorted(set(right_iocs.get(kind, ())) - set(left_iocs.get(kind, ()))),
               "removed": sorted(set(left_iocs.get(kind, ())) - set(right_iocs.get(kind, ())))}
        for kind in all_ioc_types
        if set(left_iocs.get(kind, ())) != set(right_iocs.get(kind, ()))
    }
    diff = list(difflib.unified_diff(left.splitlines(), right.splitlines(),
                                    fromfile=left_name, tofile=right_name, lineterm=""))
    return {
        "left": left_name,
        "right": right_name,
        "same_text": left == right,
        "functions": {
            "added": sorted(right_units.keys() - left_units.keys()),
            "removed": sorted(left_units.keys() - right_units.keys()),
            "changed": sorted(name for name in left_units.keys() & right_units.keys()
                               if left_units[name] != right_units[name]),
        },
        "iocs": ioc_delta,
        "diff": diff[:20_000],
    }


def compare_files(left_path: str, right_path: str) -> dict:
    left, right = Path(left_path), Path(right_path)
    limit = 64 * 1024 * 1024
    if left.stat().st_size > limit or right.stat().st_size > limit:
        raise ValueError("comparison inputs are limited to 64 MiB each")
    return compare_text(left.read_text(encoding="utf-8", errors="replace"),
                        right.read_text(encoding="utf-8", errors="replace"),
                        left.name, right.name)


def render(result: dict) -> str:
    lines = [f"Static comparison: {result['left']} ↔ {result['right']}",
             f"identical text: {'yes' if result['same_text'] else 'no'}"]
    for key, label in (("added", "functions added"), ("removed", "functions removed"),
                       ("changed", "functions changed")):
        values = result["functions"][key]
        lines.append(f"{label}: {', '.join(values) if values else 'none'}")
    if result["iocs"]:
        lines.append("indicator changes:")
        for kind, delta in result["iocs"].items():
            lines.append(f"  {kind}: +{len(delta['added'])} -{len(delta['removed'])}")
    else:
        lines.append("indicator changes: none")
    if result["diff"]:
        lines += ["", *result["diff"]]
    return "\n".join(lines)
