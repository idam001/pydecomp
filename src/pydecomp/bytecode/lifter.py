"""pydecomp - lifter."""
from __future__ import annotations

import ast
import builtins
import re
import warnings

from ..bytecode.codeobj import CodeObj
from ..polish.demangle import _ast
from ..terminal.banner import header
from ..terminal.color import step

class _PydecompUnknown:
    """Stand-in for an operand the analysis could not resolve.

    It answers every protocol the recovered code might use — call, attribute,
    item, iteration — and renders as ``<unknown>``, so a reconstruction that is
    missing one operand still runs instead of dying on ``None(...)``.
    """

    __slots__ = ("why",)

    def __init__(self, why: str = "operand"):
        self.why = why

    def __getattr__(self, item):
        return _PydecompUnknown(f"{self.why}.{item}")

    def __call__(self, *args, **kwargs):
        return _PydecompUnknown(f"{self.why}()")

    def __getitem__(self, item):
        return _PydecompUnknown(f"{self.why}[...]")

    def __setitem__(self, item, value):
        return None

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def __bool__(self):
        return False

    def __str__(self):
        return "<unknown>"

    __repr__ = __str__

    def __eq__(self, other):
        return isinstance(other, _PydecompUnknown)

    def __hash__(self):
        return 0

def audit_source(text: str) -> dict:
    """Static runnability check for a reconstruction.

    Parsing proves the file can be imported at all; the unbound-globals scan
    lists the names that would raise ``NameError`` the moment their branch
    runs.  Nothing is executed — the file is only parsed and walked.
    """
    import ast as _ast
    report = {"compiles": False, "error": "", "missing": [], "statements": 0}
    try:
        tree = _ast.parse(text)
    except SyntaxError as exc:
        report["error"] = f"{exc.msg} (line {exc.lineno})"
        return report
    report["compiles"] = True
    report["statements"] = sum(1 for node in _ast.walk(tree)
                               if isinstance(node, _ast.stmt))
    defined = set(dir(builtins))
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Store):
            defined.add(node.id)
        elif isinstance(node, _ast.arg):
            defined.add(node.arg)
        elif isinstance(node, (_ast.Import, _ast.ImportFrom)):
            for alias in node.names:
                defined.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, _ast.ExceptHandler) and node.name:
            defined.add(node.name)
        elif isinstance(node, (_ast.Global, _ast.Nonlocal)):
            defined.update(node.names)
        elif isinstance(node, _ast.comprehension):
            for target_node in _ast.walk(node.target):
                if isinstance(target_node, _ast.Name):
                    defined.add(target_node.id)
    missing = sorted({node.id for node in _ast.walk(tree)
                      if isinstance(node, _ast.Name) and isinstance(node.ctx, _ast.Load)
                      and node.id not in defined})
    report["missing"] = missing
    return report

def audit_line(report: dict) -> str:
    """One-line summary of :func:`audit_source` for panels and reports."""
    if not report.get("compiles"):
        return f"syntax error — {report.get('error', 'unknown')}"
    count = report.get("statements", 0)
    statements = f"{count:,} statement{'' if count == 1 else 's'}"
    missing = report.get("missing") or []
    if not missing:
        return f"syntax ok · {statements} · no unbound names"
    preview = ", ".join(missing[:4]) + ("…" if len(missing) > 4 else "")
    return (f"syntax ok · {statements} · "
            f"{len(missing)} unbound name{'' if len(missing) == 1 else 's'} ({preview})")

class Tok:
    __slots__ = ("kind", "val")

    def __init__(self, kind, val):
        self.kind = kind
        self.val = val

def _flit(text: str) -> str:
    return (text.replace("{", "{{").replace("}", "}}").replace("\\", "\\\\")
            .replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
            .replace("\r", "\\r"))

def _fmt(tok, conv="", spec=""):
    inner = "{" + render(tok) + (("!" + conv) if conv else "") + ((":" + spec) if spec else "")
    return inner + "}"

def render(tok) -> str:
    if isinstance(tok, (bytes, bytearray)):
        return repr(bytes(tok))
    if not isinstance(tok, Tok):
        return str(tok)
    k, v = tok.kind, tok.val
    if k in ("expr",):
        if isinstance(v, (bytes, bytearray)):
            return repr(bytes(v))
        return v if isinstance(v, str) else repr(v)
    if k == "str":
        return repr(v)
    if k == "null":
        return ""
    if k == "dict":
        return "{" + ", ".join(f"{render(a)}: {render(b)}" for a, b in v) + "}"
    if k == "list":
        return "[" + ", ".join(render(x) for x in v) + "]"
    if k == "set":
        return "{" + ", ".join(render(x) for x in v) + "}"
    if k == "tup":
        return "(" + ", ".join(render(x) for x in v) + ")"
    if k == "fstr":
        return 'f"' + "".join(v) + '"'
    if k == "mod":
        return v
    if k == "fromattr":
        return v[1]
    if k == "code":
        return f"<code {v}>"
    if k == "func":
        return "None" if v is None else f"type({(v.qualname or v.name)!r}, (), {{}})"
    return str(v)

def _not_callable(tok) -> bool:
    """True when the whole token is a literal, so it cannot be the callable."""
    if not isinstance(tok, Tok) or tok.kind != "expr":
        return False
    text = tok.val.strip()
    if not text or text == "None":
        return True
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError):
        return False                                  # an expression, fine
    return isinstance(value, (int, float, complex, str, bytes, bool, tuple, list,
                              dict, set, frozenset, type(None)))

VALUE_LOADERS = frozenset({"LOAD_CONST", "LOAD_SMALL_INT", "LOAD_FAST", "LOAD_FAST_BORROW",
                           "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF", "LOAD_FAST_CHECK",
                           "LOAD_CONST"})

def _skip_padding(instrs, idx):
    """Step over NOT_TAKEN / NOP / CACHE style filler instructions."""
    while idx < len(instrs) and instrs[idx][1] in ("NOT_TAKEN", "NOP", "CACHE",
                                                   "EXTENDED_ARG", "RESUME"):
        idx += 1
    return idx

def _resolve_target(instrs, where, idx, off, name, arg):
    """Where does this jump really land?

    3.13/3.14 wordcode carries inline cache words and a NOT_TAKEN hint after
    conditional jumps, so the textbook ``off + 2 + arg*2`` is frequently two
    bytes short.  Try the plausible offsets and take the first one that lands
    on a real instruction.
    """
    backward = "BACKWARD" in name
    base = (off + 2 - arg * 2) if backward else (off + 2 + arg * 2)
    step = -2 if backward else 2
    candidates = [base]
    if name in ("FOR_ITER", "SEND"):
        candidates = [base + step, base, base + 2 * step]
    elif name.startswith("POP_JUMP"):
        nxt = instrs[idx + 1] if idx + 1 < len(instrs) else None
        if nxt is not None and nxt[1] == "NOT_TAKEN":
            candidates = [base + step, base]        # the hint slot is part of the jump
        else:
            candidates = [base, base + step]
    for candidate in candidates:
        if candidate in where:
            return candidate
    return base

def _fold_ternary(instrs, where, idx, off, arg):
    """``A if cond else B`` compiles to: jump, A, jump forward, B.

    Returns ``(text_a, text_b, resume_index)`` when the pattern is exactly one
    value-producing instruction per branch, otherwise ``None``.
    """
    a_idx = _skip_padding(instrs, idx + 1)
    if a_idx + 1 >= len(instrs):
        return None
    load_a = instrs[a_idx]
    jump = instrs[_skip_padding(instrs, a_idx + 1)]
    if load_a[1] not in VALUE_LOADERS or not jump[1].startswith("JUMP"):
        return None
    else_offset = _resolve_target(instrs, where, idx, off, "POP_JUMP_IF_FALSE", arg)
    j_idx = where.get(jump[0])
    if j_idx is None:
        return None
    resume_offset = _resolve_target(instrs, where, j_idx, jump[0], jump[1], jump[2])
    if else_offset not in where or resume_offset not in where:
        return None
    load_b = instrs[where[else_offset]]
    if load_b[1] not in VALUE_LOADERS:
        return None
    if else_offset + 2 != resume_offset:                 # else branch must be one op
        return None
    return load_a[3], load_b[3], where[resume_offset]

def _argnames(code: CodeObj) -> list:
    return [code.varnames[i] for i in range(min(code.argcount, len(code.varnames)))]

def sanitize(lines: list) -> list:
    """Clamp indentation and fill empty blocks so the result always parses."""
    fixed = []
    prev_indent = 0
    prev_opens = False
    for raw in lines:
        if raw.strip() == "":
            fixed.append("")
            continue
        body = raw.lstrip(" ")
        indent = (len(raw) - len(body)) // 4
        if body.startswith("#"):
            fixed.append("    " * min(indent, prev_indent + (1 if prev_opens else 0)) + body)
            continue
        if body.startswith(("elif ", "else:", "except", "finally:")):
            indent = max(indent, 0)
        elif indent == 0 and body.startswith("return"):
            fixed.append("# " + body)
            continue
        elif prev_opens:
            indent = prev_indent + 1
        else:
            indent = min(indent, prev_indent)
        if prev_opens and indent != prev_indent + 1:
            fixed.append("    " * (prev_indent + 1) + "pass")
        fixed.append("    " * indent + body)
        prev_indent = indent
        prev_opens = body.split("#")[0].rstrip().endswith(":")
    if prev_opens:
        fixed.append("    " * (prev_indent + 1) + "pass")
    return fixed

def compile_problem(text: str):
    """(lineno, message) for the first thing that stops this text compiling.

    ``ast.parse`` is not enough on its own: it accepts ``return`` outside a
    function, which blows up only when the file is actually compiled.  A
    SyntaxWarning (calling an int, say) is treated as a problem too, because a
    clean file should import without noise.
    """
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            compile(text, "<pydecomp output>", "exec")
        except SyntaxError as exc:
            return exc.lineno or 1, exc.msg
        except ValueError as exc:
            return 1, str(exc)
    for warning in caught:
        if issubclass(warning.category, SyntaxWarning):
            return getattr(warning, "lineno", 0) or 1, str(warning.message)
    return None

def clamp_indent(lines: list, limit: int = 72) -> list:
    """Keep CPython's 100-column indentation ceiling out of reach.

    Hostile code nests functions dozens deep; Python refuses to *tokenise* past
    100 columns, so deep levels are folded onto one shared level and
    ``ensure_parseable`` repairs the block structure afterwards.
    """
    if not any(len(line) - len(line.lstrip(" ")) > limit for line in lines):
        return lines
    out = []
    for line in lines:
        body = line.lstrip(" ")
        indent = len(line) - len(body)
        if not body:
            out.append(line)
        elif indent > limit:
            # deeper than Python can tokenise: keep the text, drop the nesting
            out.append(" " * limit + "# " + body)
        else:
            out.append(line)
    return out

def fix_empty_blocks(lines: list) -> list:
    """Give every header a body; deep folding can leave one bare."""
    out = []
    for index, line in enumerate(lines):
        out.append(line)
        body = line.strip()
        if not body or body.startswith("#") or not body.endswith(":"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        nxt = None
        for following in lines[index + 1:]:
            stripped = following.strip()
            if stripped and not stripped.startswith("#"):
                nxt = following
                break
        nxt_indent = len(nxt) - len(nxt.lstrip(" ")) if nxt is not None else -1
        if nxt is None or nxt_indent <= indent:
            out.append(" " * (indent + 4) + "pass")
    return out

LEFTOVER_MARK = re.compile(
    r"^\s*(\d+\s*\?|\?|\.|,|\)|\]|\}|unresolved|stack underflow"
    r"|(import|from)\s*$|(import|from)\s+(import|from)\b)")

def _bound_and_loaded(text: str):
    """Every name the lifted text binds, and every name it reads."""
    bound, loaded = set(), set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return bound, loaded
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            (bound if isinstance(node.ctx, (ast.Store, ast.Del)) else loaded).add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.alias):
            bound.add((node.asname or node.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            pass
        elif isinstance(node, ast.Global) or isinstance(node, ast.Nonlocal):
            bound.update(node.names)
    return bound, loaded

def name_audit(text: str, importable: set | None = None):
    """Names the lifted code reads but never binds (outside real builtins).

    The lifter invents two helpers of its own (``__exception__`` and the class
    dict bookkeeping), and a hand-lifted script can legitimately reference
    something the bytecode only knew at runtime.  Rather than let any of those
    become a NameError on the first line, they get a guarded placeholder.
    """
    import builtins
    builtin_names = set(dir(builtins))
    bound, loaded = _bound_and_loaded(text)
    unknown = sorted(n for n in loaded - bound - builtin_names
                     if not n.startswith("__annotations__"))
    if not unknown:
        return []
    importable = importable or set()
    lines = ["# ---------------------------------------------------------------",
             "# Names the lifted code reads but never defines.  Each one gets an",
             "# inert stand-in, so importing this file cannot raise NameError,",
             "# AttributeError or 'NoneType is not callable'.",
             "# ---------------------------------------------------------------",
             "class _Missing:",
             '    """Placeholder for a name the bytecode only knew at runtime."""',
             "",
             "    def __init__(self, name='?'):",
             "        self._name = name",
             "",
             "    def __getattr__(self, item):",
             "        return _Missing(f'{self._name}.{item}')",
             "",
             "    def __call__(self, *a, **k):",
             "        return _Missing(f'{self._name}()')",
             "",
             "    def __getitem__(self, item):",
             "        return _Missing(f'{self._name}[{item}]')",
             "",
             "    def __iter__(self):",
             "        return iter(())",
             "",
             "    def __bool__(self):",
             "        return False",
             "",
             "    def __str__(self):",
             "        return f'<missing {self._name}>'",
             "",
             "    __repr__ = __str__",
             ""]
    for name in unknown[:60]:
        if name == "__exception__":
            lines.append("__exception__ = Exception  # no live exception at module level")
        elif name in importable:
            lines.append(f"try:  # {name} was imported by the original payload")
            lines.append(f"    import {name}")
            lines.append("except Exception:")
            lines.append(f"    {name} = _Missing({name!r})")
        else:
            lines.append(f"{name} = _Missing({name!r})  # not defined in the recovered code")
    lines.append("")
    return lines

def _is_class_body(code: "CodeObj") -> bool:
    """CPython class bodies always write __module__ and __qualname__."""
    names = set(code.names)
    return "__qualname__" in names and "__module__" in names and "__firstlineno__" in names

CLASS_BOOKKEEPING = ("__module__", "__qualname__", "__firstlineno__", "__classdict__",
                     "__classdictcell__", "__static_attributes__", "__doc__")

def clean_class_body(lines: list) -> list:
    """Drop the compiler's class bookkeeping so a class body reads like source."""
    out = []
    for line in lines:
        stripped = line.strip()
        head = stripped.split("=")[0].strip() if "=" in stripped else ""
        if head in CLASS_BOOKKEEPING:
            out.append(line[:len(line) - len(line.lstrip())] + "# " + stripped)
        else:
            out.append(line)
    return out

def d6_const(value):
    return ast.Constant(value=value)

def _d6_fix_breaks(stmts):
    """Turn a ``while True`` fall-through exit at module level into ``break``."""
    out = []
    for i, stmt in enumerate(stmts):
        if isinstance(stmt, ast.If) and not stmt.orelse and i == len(stmts) - 1:
            tail = stmt.body[-1] if stmt.body else None
            if isinstance(tail, ast.Expr) and isinstance(tail.value, ast.Constant) \
                    and tail.value.value is None:
                stmt = ast.If(test=stmt.test, body=[ast.Break()], orelse=[])
            elif isinstance(tail, ast.Return) and (tail.value is None or (
                    isinstance(tail.value, ast.Constant) and tail.value.value is None)):
                stmt = ast.If(test=stmt.test, body=[ast.Break()], orelse=[])
        out.append(stmt)
    return out

def d6_until_backward_or(value, offset):
    return value if value is not None else offset

def d6_is_back_edge(target, header) -> bool:
    """Does ``target`` close a loop that starts at ``header``?

    Since 3.12 the compiler jumps back to the instruction that *prepares* the
    header (``GET_ITER`` / a ``RESUME``) rather than to the ``FOR_ITER`` itself,
    so an exact comparison misses the back edge and the loop body swallows the
    rest of the function.
    """
    if target is None or header is None:
        return False
    return header - 24 <= target <= header + 2
