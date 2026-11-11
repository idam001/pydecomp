"""Coverage: did the recovered program keep everything the original had?

Unpacking a sample answers "what is in here"; it does not answer "did I lose
anything on the way".  This module compares the program as it came out of the
container against the program after cleaning, function by function, and reports
what survived:

* every def/class that existed and whether it still exists;
* statement counts per function (a drop is expected - that is folding - but a
  function going to zero statements, or vanishing entirely, is not);
* module-level names, imports, class definitions;
* how many of the original's string literals and numeric constants still appear.

A file that scores "complete" had nothing dropped.  A file that does not is a
bug report you can act on, not a feeling.
"""
from __future__ import annotations

from ..polish.demangle import _ast

_KEPT, _MISSING, _EMPTY, _RENAMED = "kept", "missing", "emptied", "renamed"


def _count_statements(nodes) -> int:
    return sum(1 for node in nodes if isinstance(node, _ast.stmt))


def _body_statements(node) -> int:
    return sum(1 for sub in _ast.walk(node) if isinstance(sub, _ast.stmt))


def _definitions(tree) -> dict:
    """Top-level and nested defs/classes: name -> (kind, statement count)."""
    found: dict[str, tuple[str, int]] = {}
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            found.setdefault(node.name, ("def", _body_statements(node)))
        elif isinstance(node, _ast.ClassDef):
            found.setdefault(node.name, ("class", _body_statements(node)))
    return found


def _module_names(tree) -> set[str]:
    names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, _ast.Assign):
            names.update(target.id for target in stmt.targets
                         if isinstance(target, _ast.Name))
        elif isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            names.add(stmt.name)
    return names


def _imports(tree) -> set[str]:
    modules: set[str] = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, _ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def _literals(tree) -> tuple[set[str], set[int]]:
    strings: set[str] = set()
    numbers: set[int] = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Constant):
            if isinstance(node.value, str) and len(node.value) >= 3:
                strings.add(node.value)
            elif isinstance(node.value, int) and not isinstance(node.value, bool):
                numbers.add(node.value)
    return strings, numbers


def _parse(text: str):
    try:
        return _ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def compare(original: str, recovered: str) -> dict:
    """Compare the program that came out of the container with the cleaned one."""
    result = {
        "parsed": False, "definitions": {}, "kept": 0, "lost": 0, "emptied": 0,
        "statements_before": 0, "statements_after": 0, "names_lost": [], "renamed": 0,
        "imports_lost": [], "strings_before": 0, "strings_kept": 0,
        "verdict": "unparsed",
    }
    before, after = _parse(original), _parse(recovered)
    if before is None or after is None:
        # at least say whether the text itself survived
        result["verdict"] = ("compared as text only: "
                              + ("recovered source is larger" if len(recovered) >= len(original)
                                 else "recovered source is smaller"))
        return result
    result["parsed"] = True

    old_defs = _definitions(before)
    new_defs = _definitions(after)
    for name, (kind, statements) in sorted(old_defs.items()):
        if name not in new_defs:
            result["definitions"][name] = {"kind": kind, "status": _MISSING,
                                           "before": statements, "after": 0}
            result["lost"] += 1
            continue
        new_count = new_defs[name][1]
        status = _EMPTY if new_count == 0 else _KEPT
        if status == _EMPTY:
            result["emptied"] += 1
        else:
            result["kept"] += 1
        result["definitions"][name] = {"kind": kind, "status": status,
                                       "before": statements, "after": new_count}

    # a definition whose name changed is not a loss: de-mangling renames things.
    # Match each missing name to an unexplained new one of the same kind and a
    # similar body size, but only when the match is unambiguous.
    new_only = {name: info for name, info in new_defs.items() if name not in old_defs}
    for name, info in list(result["definitions"].items()):
        if info["status"] != _MISSING:
            continue
        tolerance = max(2, info["before"] // 4)
        candidates = [(candidate, shape) for candidate, shape in new_only.items()
                      if shape[0] == info["kind"]
                      and abs(shape[1] - info["before"]) <= tolerance]
        if len(candidates) == 1:
            candidate, shape = candidates[0]
            info["status"] = _RENAMED
            info["renamed_to"] = candidate
            info["after"] = shape[1]
            del new_only[candidate]
            result["lost"] -= 1
            result["renamed"] += 1
            result["kept"] += 0

    result["names_lost"] = sorted(_module_names(before) - _module_names(after))
    result["imports_lost"] = sorted(_imports(before) - _imports(after))
    result["statements_before"] = _count_statements(_ast.walk(before))
    result["statements_after"] = _count_statements(_ast.walk(after))

    old_strings, old_numbers = _literals(before)
    new_strings, new_numbers = _literals(after)
    result["strings_before"] = len(old_strings)
    result["strings_kept"] = len(old_strings & new_strings)
    result["strings_folded"] = result["strings_before"] - result["strings_kept"]
    result["numbers_before"] = len(old_numbers)
    result["numbers_kept"] = len(old_numbers & new_numbers)

    total_defs = max(len(old_defs), 1)
    lost_share = result["lost"] / total_defs
    string_share = (result["strings_kept"] / result["strings_before"]
                    if result["strings_before"] else 1.0)
    if result["lost"] == 0 and result["emptied"] == 0:
        result["verdict"] = "complete"
    elif lost_share <= 0.15 and string_share >= 0.5:
        result["verdict"] = "mostly complete"
    else:
        result["verdict"] = "incomplete"
    return result


def summary(result: dict) -> str:
    if not result["parsed"]:
        return result["verdict"]
    renamed = f", {result['renamed']} renamed" if result.get("renamed") else ""
    return (f"{result['verdict']}: {result['kept']} definition(s) kept, "
            f"{result['lost']} lost{renamed} · {result['strings_kept']}/"
            f"{result['strings_before']} literals · "
            f"{result['statements_before']}→{result['statements_after']} statements")


def render_markdown(name: str, result: dict) -> str:
    lines = [f"# Coverage — `{name}`", ""]
    lines.append(f"- **verdict**: {result['verdict']}")
    if not result["parsed"]:
        lines += ["", "The recovered file could not be compared structurally "
                      "(it is a string dump or pseudo-code).", ""]
        return "\n".join(lines)
    lines += [f"- **definitions kept**: {result['kept']} / "
              f"{result['kept'] + result['lost']}",
              f"- **string literals kept**: {result['strings_kept']} / "
              f"{result['strings_before']}"
              + (f" ({result['strings_folded']} folded into call sites)"
                 if result.get("strings_folded") else ""),
              f"- **statements**: {result['statements_before']} before → "
              f"{result['statements_after']} after (folding removes statements)",
              ""]
    if result["definitions"]:
        lines += ["| definition | kind | statements before | after | status |",
                  "| --- | --- | --- | --- | --- |"]
        for name_, info in result["definitions"].items():
            status = info["status"]
            if info.get("renamed_to"):
                status += f" → `{info['renamed_to']}`"
            lines.append(f"| `{name_}` | {info['kind']} | {info['before']} | "
                         f"{info['after']} | {status} |")
        lines.append("")
    if result["names_lost"]:
        lines += [f"- **module names lost**: {', '.join(result['names_lost'])}", ""]
    if result["imports_lost"]:
        lines += [f"- **imports lost**: {', '.join(result['imports_lost'])}", ""]
    if not result["names_lost"] and not result["imports_lost"]:
        lines += ["- no module name or import was lost", ""]
    return "\n".join(lines)
