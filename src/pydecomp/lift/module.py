"""pydecomp - module."""
from __future__ import annotations

import ast
import sys

from ..bytecode.codeobj import CodeObj, _last_module_code
from ..bytecode.decompiler6 import (
    Decompiler6, _classdef, _last_engine, content_coverage, d6_trim, fix_stray_returns,
    roundtrip_score, sanitize_tree,
)
from ..bytecode.disassembler import disassemble
from ..bytecode.folding import d6_expr_fixups, fold_tree
from ..bytecode.lifter import (
    CLASS_BOOKKEEPING, Tok, _argnames, _flit, _fmt, _fold_ternary,
    _is_class_body, _not_callable, _resolve_target, clamp_indent, clean_class_body, compile_problem,
    name_audit, render, sanitize,
)
from ..bytecode.magic import host_version
from ..bytecode.marshal_reader import iter_code
from ..bytecode.opcodes.tables import BINARY_SYMS, OPNAMES
from ..engine.artifact import _score
from ..lift.classes import promote_class_bodies
from ..lift.quality import ensure_parseable
from ..limits import __version__
from ..terminal.banner import header

def lift(code: CodeObj, version: tuple, label: str = "<module>", depth: int = 0,
         header: bool = True, emitted: set | None = None) -> list:
    """Turn one code object into readable, *syntactically valid* Python-ish lines."""
    out = []
    args = _argnames(code)
    emitted = emitted if emitted is not None else set()
    is_module = depth == 0 and label == "<module>"
    if is_module:
        level = 0
        if header:
            out.append(f"# ===== module ===== ({len(code.code)} bytes of bytecode)")
    else:
        level = depth + 1
        if header:
            extra = ", *args, **kwargs" if code.flags & 0x04 else ""
            out.append(f"def {label}({', '.join(args)}{extra}):")
    body = []
    stack = []
    closes = []                                          # (offset, level)
    notes = {"text": "", "loop": None, "bad": 0, "exc": False}

    def emit(line):
        if "<?>" in line:
            line = line.replace("<?>", "_PydecompUnknown()") + "  # ambiguous operand"
        elif notes["text"]:
            line = line + "  # " + notes["text"]
        notes["text"] = ""
        body.append("    " * level + line)

    def mark(reason: str) -> None:
        notes["text"] = (notes["text"] + ", " + reason) if notes["text"] else reason

    def pop(n=1):
        vals = []
        for _ in range(n):
            vals.append(stack.pop() if stack else Tok("expr", "<?>"))
        return vals[::-1]

    def open_kind(kind):
        for i in range(len(stack) - 1, -1, -1):
            if isinstance(stack[i], Tok) and stack[i].kind == kind:
                return i
        return None

    def literal_items(tok):
        """Elements of a literal sequence on the stack, if it is one.

        ``[*('A', 'B')]`` compiles to ``BUILD_LIST 0`` + ``LOAD_CONST`` +
        ``LIST_EXTEND 1``.  The tuple never becomes a token of its own, so the
        elements have to be read back out of the constant — otherwise the list
        silently renders as ``[]`` and the recovered script dies on an empty
        sequence at run time.
        """
        if isinstance(tok, Tok) and tok.kind in ("list", "set", "tup"):
            return list(tok.val)
        if not isinstance(tok, Tok) or tok.kind != "expr":
            return None
        try:
            value = ast.literal_eval(render(tok))
        except (ValueError, SyntaxError, TypeError, MemoryError):
            return None
        if isinstance(value, (tuple, list, set, frozenset)) and len(value) <= 5000:
            return [Tok("expr", repr(item)) for item in value]
        return None

    instrs = list(disassemble(code, version))
    where = {ins[0]: idx for idx, ins in enumerate(instrs)}
    index = 0
    while index < len(instrs):
        off, opname, arg, text = instrs[index]
        index += 1
        while closes and off >= closes[-1][0]:
            level = closes.pop()[1]
        if opname in ("RESUME", "NOP", "CACHE", "EXTENDED_ARG", "MAKE_CELL",
                      "COPY_FREE_VARS", "RETURN_GENERATOR", "NOT_TAKEN", "PRECALL",
                      "SETUP_ANNOTATIONS", "TO_BOOL", "END_FOR", "POP_ITER",
                      "END_SEND", "INTERPRETER_EXIT", "RESERVED"):
            continue
        if opname == "PUSH_NULL":
            stack.append(Tok("null", None))
        elif opname == "LOAD_CONST":
            const = code.consts[arg] if arg < len(code.consts) else None
            if isinstance(const, CodeObj):
                stack.append(Tok("code", const.qualname or const.name))
            elif isinstance(const, str):
                stack.append(Tok("str", const))
            else:
                stack.append(Tok("expr", text))
        elif opname == "RETURN_CONST":
            if is_module:
                emit(f"# module ends ({text})")
            else:
                emit("return" if text == "None" else f"return {text}")
        elif opname == "LOAD_SMALL_INT":
            stack.append(Tok("expr", text))
        elif opname in ("LOAD_NAME", "LOAD_GLOBAL"):
            if opname == "LOAD_GLOBAL" and arg & 1:
                stack.append(Tok("null", None))
            stack.append(Tok("expr", text))
        elif opname in ("LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_DEREF",
                        "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR"):
            stack.append(Tok("expr", text))
        elif opname in ("LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"):
            first, _, second = text.partition(",")
            stack.append(Tok("expr", first.strip()))
            stack.append(Tok("expr", second.strip()))
        elif opname == "LOAD_ATTR":
            owner = pop(1)[0]
            if arg & 1:                                   # method load: two slots
                stack.append(Tok("null", None))
            stack.append(Tok("expr", f"{render(owner)}.{text}"))
        elif opname in ("STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"):
            if not stack and notes["exc"]:
                stack.append(Tok("expr", "__exception__"))
            if notes["loop"] is not None:
                # this store is the loop variable binding itself
                body[notes["loop"]] = body[notes["loop"]].replace("__item__", text, 1)
                notes["loop"] = None
                pop(1)
                continue
            tok = pop(1)[0]
            if isinstance(tok, Tok) and tok.kind == "fromattr":
                module, attr = tok.val
                alias = f" as {text}" if text != attr else ""
                emit(f"from {module} import {attr}{alias}")
            elif isinstance(tok, Tok) and tok.kind == "func":
                emit(f"def {text}({', '.join(_argnames(tok.val))}):")
                emitted.add(id(tok.val))
                body.extend(lift(tok.val, version, text, depth=level, header=False,
                                 emitted=emitted))
            elif isinstance(tok, Tok) and tok.kind == "mod":
                emit(f"import {tok.val}")
            else:
                emit(f"{text} = {render(tok)}")
        elif opname in ("STORE_FAST_STORE_FAST", "STORE_FAST_LOAD_FAST"):
            first, _, second = text.partition(",")
            emit(f"{first.strip()}, {second.strip()} = {render(pop(1)[0])}")
        elif opname == "STORE_ATTR":
            obj, val = pop(2)
            emit(f"{render(obj)}.{text} = {render(val)}")
        elif opname == "STORE_SUBSCR":
            key, obj, val = pop(3)
            emit(f"{render(obj)}[{render(key)}] = {render(val)}")
        elif opname == "DELETE_SUBSCR":
            key, obj = pop(2)
            emit(f"del {render(obj)}[{render(key)}]")
        elif opname == "BINARY_OP":
            b, a = pop(2)
            sym = BINARY_SYMS.get(arg, "?")
            if arg >= 13:
                emit(f"{render(a)} {sym} {render(b)}")
            else:
                stack.append(Tok("expr", f"{render(a)} {sym} {render(b)}"))
        elif opname in ("BINARY_SUBSCR", "BINARY_SLICE"):
            key, obj = pop(2)
            stack.append(Tok("expr", f"{render(obj)}[{render(key)}]"))
        elif opname == "COMPARE_OP":
            b, a = pop(2)
            stack.append(Tok("expr", f"{render(a)} {text} {render(b)}"))
        elif opname in ("IS_OP", "CONTAINS_OP"):
            b, a = pop(2)
            sym = ("is not" if arg else "is") if opname == "IS_OP" else ("not in" if arg else "in")
            if opname == "CONTAINS_OP":
                expr = f"{render(b)} {sym} {render(a)}"
            else:
                # ``() is None`` is a constant: identity against a literal that
                # the compiler would only warn about, so say what it means
                left_literal = isinstance(a, Tok) and a.kind in ("tup", "list", "dict",
                                                                "str", "null")
                right_literal = isinstance(b, Tok) and b.kind in ("tup", "list", "dict",
                                                                 "null")
                if left_literal and right_literal:
                    expr = repr(a.kind == b.kind and a.kind == "null"
                                and a.val == b.val)
                    if arg:
                        expr = repr(not ast.literal_eval(expr))
                else:
                    expr = f"{render(a)} {sym} {render(b)}"
            stack.append(Tok("expr", expr))
        elif opname.startswith("UNARY_"):
            sym = {"UNARY_NEGATIVE": "-", "UNARY_NOT": "not ", "UNARY_INVERT": "~"}.get(opname, "")
            stack.append(Tok("expr", sym + render(pop(1)[0])))
        elif opname == "BUILD_TUPLE":
            stack.append(Tok("tup", list(pop(arg))))
        elif opname == "BUILD_LIST":
            stack.append(Tok("list", list(pop(arg))))
        elif opname == "BUILD_SET":
            stack.append(Tok("set", list(pop(arg))))
        elif opname == "BUILD_MAP":
            if arg == 0:
                stack.append(Tok("dict", []))
            else:
                items = pop(arg * 2)
                stack.append(Tok("dict", [(items[i], items[i + 1])
                                          for i in range(0, len(items), 2)]))
        elif opname == "BUILD_CONST_KEY_MAP":
            keys = pop(1)[0]
            vals = pop(arg)
            if isinstance(keys, Tok) and keys.kind == "tup":
                stack.append(Tok("dict", list(zip(keys.val, vals))))
            else:
                stack.append(Tok("expr", f"dict(zip({render(keys)}, [...]))"))
        elif opname == "BUILD_SLICE":
            stack.append(Tok("expr", ":".join(render(i) for i in pop(arg))))
        elif opname in ("LIST_APPEND", "SET_ADD"):
            val = pop(1)[0]
            idx = len(stack) - arg
            if 0 <= idx < len(stack) and isinstance(stack[idx], Tok):
                held = stack[idx]
                if isinstance(held.val, list) and held.kind in ("list", "set", "tup"):
                    held.val.append(val)
                else:
                    stack[idx] = Tok("list", [Tok("expr", render(held)), val])
        elif opname in ("LIST_EXTEND", "SET_UPDATE", "DICT_UPDATE", "DICT_MERGE"):
            extra = pop(1)[0]
            idx = len(stack) - arg
            if 0 <= idx < len(stack) and isinstance(stack[idx], Tok):
                if not isinstance(stack[idx].val, list):
                    items = literal_items(extra) or [Tok("expr", render(extra))]
                    stack[idx] = Tok("list", [Tok("expr", render(stack[idx]))] + items)
                    continue
                if extra.kind in ("list", "set", "tup"):
                    stack[idx].val.extend(extra.val)
                elif extra.kind == "dict" and stack[idx].kind == "dict":
                    stack[idx].val.extend(extra.val)
                else:
                    items = literal_items(extra)
                    if items:
                        stack[idx].val.extend(items)
        elif opname == "MAP_ADD":
            key, val = pop(2)
            idx = open_kind("dict")
            if idx is not None:
                stack[idx].val.append((key, val))
            else:
                emit(f"# {render(key)}: {render(val)}")
        elif opname == "BUILD_STRING":
            chunks = []
            for part in pop(arg):
                if part.kind == "fstr":
                    chunks.extend(part.val)
                elif part.kind == "str":
                    chunks.append(_flit(part.val))
                else:
                    chunks.append("{" + render(part) + "}")
            stack.append(Tok("fstr", chunks))
        elif opname == "FORMAT_SIMPLE":
            stack.append(Tok("fstr", [_fmt(pop(1)[0])]))
        elif opname == "FORMAT_WITH_SPEC":
            spec = pop(1)[0]
            stack.append(Tok("fstr", [_fmt(pop(1)[0], spec=render(spec))]))
        elif opname == "CONVERT_VALUE":
            conv = {1: "s", 2: "r", 3: "a"}.get(arg, "")
            stack.append(Tok("fstr", [_fmt(pop(1)[0], conv=conv)]))
        elif opname == "FORMAT_VALUE":
            flags = arg & 0x03
            spec = pop(1)[0] if arg & 0x04 else None
            val = pop(1)[0]
            conv = {1: "s", 2: "r", 3: "a"}.get(flags, "")
            stack.append(Tok("fstr", [_fmt(val, conv=conv,
                                           spec=render(spec) if spec else "")]))
        elif opname == "CALL":
            call_args = pop(arg)
            fn = pop(1)[0]
            if isinstance(fn, Tok) and fn.kind == "null" and stack:
                fn = pop(1)[0]
            if stack and isinstance(stack[-1], Tok) and stack[-1].kind == "null":
                stack.pop()                           # the callable's self slot
            if _not_callable(fn):
                mark("call operands did not line up")
                stack.append(Tok("expr", "None"))
            else:
                stack.append(Tok("expr",
                                 f"{render(fn)}({', '.join(render(a) for a in call_args)})"))
        elif opname == "CALL_KW":
            kwnames = pop(1)[0]
            vals = pop(arg)
            fn = pop(1)[0]
            if isinstance(fn, Tok) and fn.kind == "null" and stack:
                fn = pop(1)[0]
            while stack and isinstance(stack[-1], Tok) and stack[-1].kind == "null":
                stack.pop()
            names = []
            if _not_callable(fn):
                mark("call operands did not line up")
                stack.append(Tok("expr", "None"))
                continue
            if isinstance(kwnames, Tok) and kwnames.kind == "tup":
                names = [str(render(k)).strip("'\"") for k in kwnames.val]
            elif isinstance(kwnames, Tok) and kwnames.kind == "str":
                try:
                    literal = ast.literal_eval(kwnames.val)
                except (ValueError, SyntaxError):
                    literal = ()
                if isinstance(literal, tuple):
                    names = [str(x) for x in literal]
            elif isinstance(kwnames, Tok) and kwnames.kind == "expr":
                try:
                    literal = ast.literal_eval(kwnames.val)
                except (ValueError, SyntaxError):
                    literal = ()
                if isinstance(literal, tuple):
                    names = [str(x) for x in literal]
            nkw = len(names)
            positional = [render(v) for v in vals[:len(vals) - nkw]]
            keywords = [f"{n}={render(v)}" for n, v in zip(names, vals[len(vals) - nkw:])]
            stack.append(Tok("expr", f"{render(fn)}({', '.join(positional + keywords)})"))
        elif opname == "CALL_FUNCTION_EX":
            kwargs = pop(1)[0] if arg & 1 else None
            call_args = pop(1)[0]
            fn = pop(1)[0]
            extra = f", **{render(kwargs)}" if kwargs else ""
            stack.append(Tok("expr", f"{render(fn)}(*{render(call_args)}{extra})"))
        elif opname in ("CALL_INTRINSIC_1", "CALL_INTRINSIC_2"):
            n = 1 if opname.endswith("1") else 2
            call_args = pop(n)
            stack.append(Tok("expr", f"<intrinsic {arg}>({', '.join(render(a) for a in call_args)})"))
        elif opname == "POP_TOP":
            val = pop(1)[0]
            text_val = render(val).strip()
            if isinstance(val, Tok) and val.kind in ("mod", "mod_used"):
                if val.kind == "mod":
                    emit(f"import {val.val}")
            elif text_val in ("", "None", "<?>"):
                emit("# value discarded here" if text_val != "<?>" else "# operand unavailable")
            elif text_val:
                emit(text_val)
        elif opname == "RETURN_VALUE":
            val = render(pop(1)[0])
            if is_module:
                emit(f"# module ends ({val})")
            else:
                emit("return" if val == "None" else f"return {val}")
        elif opname == "IMPORT_NAME":
            pop(2)
            stack.append(Tok("mod", text))
        elif opname == "IMPORT_FROM":
            mod = stack[-1] if stack else Tok("mod", "?")
            if isinstance(mod, Tok) and mod.kind == "mod":
                mod.kind = "mod_used"
            stack.append(Tok("fromattr", (render(mod), text)))
        elif opname in ("UNPACK_SEQUENCE", "UNPACK_EX"):
            emit(f"# unpack {render(pop(1)[0])} into {arg} values")
        elif opname.startswith("JUMP"):
            target = _resolve_target(instrs, where, index - 1, off, opname, arg)
            if "BACKWARD" in opname:
                level = max(level - 1, depth + (1 if depth else 0))
                emit(f"# loop back to {target}")
            else:
                emit(f"# jump to {target}")
        elif opname.startswith("POP_JUMP_IF"):
            folded = _fold_ternary(instrs, where, index - 1, off, arg)
            if folded is not None:
                then_text, else_text, resume_at = folded
                cond = render(pop(1)[0])
                stack.append(Tok("expr", f"({then_text} if {cond} else {else_text})"))
                index = resume_at
                continue
            cond = render(pop(1)[0])
            neg = "not " if opname == "POP_JUMP_IF_FALSE" else ""
            if "NONE" in opname:
                cond += " is None" if "NOT" not in opname else " is not None"
                neg = ""
            target = _resolve_target(instrs, where, index - 1, off, opname, arg)
            emit(f"if {neg}{cond}:")
            closes.append((target, level))
            level += 1
        elif opname == "FOR_ITER":
            target = _resolve_target(instrs, where, index - 1, off, opname, arg)
            emit(f"for __item__ in {render(pop(1)[0])}:")
            notes["loop"] = len(body) - 1
            closes.append((target, level))
            level += 1
        elif opname == "GET_ITER":
            pass
        elif opname == "MAKE_FUNCTION":
            qual = pop(1)[0]
            wanted = qual.val if isinstance(qual, Tok) else str(qual)
            found = None
            for const in code.consts:
                if isinstance(const, CodeObj) and (const.qualname or const.name) == wanted:
                    found = const
                    break
            stack.append(Tok("func", found) if found is not None else qual)
        elif opname == "SET_FUNCTION_ATTRIBUTE":
            pass
        elif opname == "SWAP":
            if len(stack) >= arg:
                stack[-1], stack[-arg] = stack[-arg], stack[-1]
        elif opname == "COPY":
            stack.append(stack[-arg] if len(stack) >= arg else Tok("expr", "<?>"))
        elif opname == "RAISE_VARARGS":
            targets = ", ".join(render(x) for x in pop(arg or 1))
            emit(f"# raise {targets}".rstrip())
        # ---- exception frames: keep the shadow stack honest instead of dropping it
        elif opname == "PUSH_EXC_INFO":
            notes["exc"] = True
            stack.append(Tok("expr", "__exception__"))
        elif opname == "CHECK_EXC_MATCH":
            exc, exc_type = pop(2)
            stack.append(Tok("expr",
                             f"isinstance({render(exc)}, {render(exc_type)})"))
        elif opname == "POP_EXCEPT":
            notes["exc"] = False
            if stack:
                pop(1)
        elif opname == "RERAISE":
            emit("# re-raise (exception path)")
        elif opname == "WITH_EXCEPT_START":
            emit("# with-block __exit__")
        elif opname:
            emit(f"# {opname} {text}".rstrip())

    if not body:
        body.append("    " * (depth + 1) + "pass")
    out.extend(body)
    out.append("")
    return out

def decompile_code6(code, version, resolve_target, opnames):
    """Return (ast.Module, warnings) or raise D6Unsupported."""
    dec = Decompiler6(code, version, resolve_target, opnames)
    body = dec.run()
    return ast.Module(body=body, type_ignores=[]), []

def decompile_object(code: CodeObj, version: tuple, name: str | None = None,
                     kind: str = "function", tolerant: bool = False):
    """Rebuild one code object as real source.  Returns ``(text, score)``."""
    global _last_engine, _last_module_code
    if name is None:
        _last_module_code = code
    _last_engine = None
    if version < (3, 11):
        return None, 0.0                             # block-stack era: use the lifter
    try:
        engine = Decompiler6(code, version, None, OPNAMES.get(version) or {},
                             tolerant=tolerant)
        _last_engine = engine
        body = engine.run()
    except Exception:                                # noqa: BLE001 - any opcode surprise
        return None, 0.0
    if name is None:
        body = [stmt for stmt in body
                if not (isinstance(stmt, ast.Return) and stmt.value is None)]
        module = ast.Module(body=body or [ast.Pass()], type_ignores=[])
    elif kind == "class":
        if not name.isidentifier():
            return None, 0.0
        kept = []
        for stmt in body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name) \
                    and stmt.targets[0].id in CLASS_BOOKKEEPING:
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue
            if isinstance(stmt, ast.Return) and stmt.value is None:
                continue
            kept.append(stmt)
        node = _classdef(name, d6_trim(kept) if kept else [ast.Pass()])
        module = ast.Module(body=[node], type_ignores=[])
    else:
        if not name.isidentifier():
            return None, 0.0
        node = ast.FunctionDef(name=name, args=engine._arguments(code),
                               body=d6_trim(body), decorator_list=[],
                               returns=None)
        module = ast.Module(body=[node], type_ignores=[])
    try:
        if sys.getrecursionlimit() < 20000:
            sys.setrecursionlimit(20000)
        sanitize_tree(module)
        fix_stray_returns(module)
        d6_expr_fixups(module)
        ast.fix_missing_locations(module)
        text = ast.unparse(module)
    except Exception:                                # noqa: BLE001 - malformed node
        return None, 0.0
    if compile_problem(text) is not None:
        return None, 0.0
    score = roundtrip_score(code, text, version)
    if True:
        try:                                         # run the decryptors, statically
            folded = ast.unparse(fold_tree(ast.parse(text)))
            if compile_problem(folded) is None and len(folded) <= len(text) * 4:
                text = folded
        except Exception:                            # noqa: BLE001 - keep raw rebuild
            pass
    return text, score

def decompile_accepted(score: float, version: tuple) -> bool:
    """Only take rebuilt source when it can be trusted.

    Same interpreter: the rebuilt text has to reproduce the original opcode
    stream almost exactly.  Other versions cannot be recompiled here, so the
    bar is name coverage, and the lifter stays the fallback.
    """
    if version == host_version():
        return score >= 0.85
    return score >= 0.55

def _lift_module5(code: CodeObj, version: tuple) -> str:
    """Whole-module reconstruction: module statements + every function."""
    lines = ["# Reconstructed from bytecode.  Every string, constant and URL is the",
             "# real one; control-flow frames are approximated by the lifter, and any",
             "# statement the lifter could not line up is kept as a comment.",
             ""]
    emitted: set = set()
    importable = {text for _off, opname, _arg, text in disassemble(code, version)
                  if opname == "IMPORT_NAME"}
    lines.extend(lift(code, version, "<module>", depth=0, emitted=emitted))
    for nested in code.consts:
        if not isinstance(nested, CodeObj) or id(nested) in emitted:
            continue                                    # already lifted inline
        name = nested.qualname or nested.name
        if _is_class_body(nested):
            emitted.add(id(nested))
            class_text, class_score = decompile_object(nested, version, name)
            if class_text is not None and decompile_accepted(class_score, version):
                lines.extend(class_text.rstrip().split("\n"))
                continue
            lines.append(f"class {name}:")
            class_lines = lift(nested, version, name, depth=0, header=False,
                               emitted=emitted)
            lines.extend(clean_class_body(class_lines))
            for sub in nested.consts:
                if isinstance(sub, CodeObj) and id(sub) not in emitted:
                    lines.extend(lift(sub, version, sub.qualname or sub.name, depth=1,
                                      emitted=emitted))
            continue
        lines.extend(lift(nested, version, name, depth=0, emitted=emitted))
        for sub in nested.consts:
            if isinstance(sub, CodeObj) and id(sub) not in emitted:
                lines.extend(lift(sub, version, sub.qualname or sub.name, depth=1,
                                  emitted=emitted))
    text = "\n".join(ensure_parseable(clamp_indent(sanitize(lines)))) + "\n"
    head = name_audit(text, importable)
    # provenance first, then any stand-ins, then the reconstruction
    return "\n".join(list(head) + [text]) + "\n"

SIZE_BUDGET = 2_000_000

def lift_module(code: CodeObj, version: tuple) -> str:
    """Whole-module reconstruction: rebuilt source where proven, lifter elsewhere."""
    try:
        text = _lift_module6(code, version)
    except Exception:                                # noqa: BLE001 - never fail the run
        text = None
    if text is None or compile_problem(text) is not None:
        fallback = _lift_module5(code, version)
        promoted = promote_class_bodies(fallback)
        if compile_problem(promoted) is None:
            return promoted
        return fallback
    text = promote_class_bodies(text)
    if len(text) > SIZE_BUDGET:
        # a rebuild that explodes into million-character lines tells the reader
        # less than the statement lifter, which stays close to the bytecode
        alt = _lift_module5(code, version)
        if compile_problem(alt) is None and len(alt) * 2 < len(text):
            return alt
    return text

_last_module_version = None

LIFT_QUALITY = {"proven": False}

def _append_missing_units(code: CodeObj, version: tuple, text: str | None,
                          limit: int = 600) -> str | None:
    """Rebuild nested code objects the module statement flow never reached."""
    if text is None:
        return text
    engine = _last_engine
    used = engine.consumed_ids() if engine is not None else set()
    missing = []
    for unit in iter_code(code):
        if id(unit) in used or len(unit.code) < 4:
            continue
        name = getattr(unit, "name", "") or ""
        if not name.isidentifier() or name in ("<lambda>", "<listcomp>", "<genexpr>",
                                               "<dictcomp>", "<setcomp>"):
            continue
        if f"def {name}(" in text or f"class {name}:" in text:
            continue
        missing.append(unit)
    recovered = []
    for unit in missing[:limit]:
        name = unit.name
        names = set(unit.names)
        kind = "class" if {"__module__", "__qualname__"} <= names else "function"
        try:
            piece, _score = decompile_object(unit, version, name, kind=kind)
        except Exception:                            # noqa: BLE001 - keep going
            piece = None
        if piece and f"def {name}(" not in text and f"class {name}:" not in text:
            recovered.append(piece.rstrip())
            text = text + "\n" + piece
    if not recovered:
        return text
    return text

def _lift_module6(code: CodeObj, version: tuple) -> str | None:
    """Rebuild the whole module as source when the round trip proves it."""
    global _last_module_code, _last_module_version
    _last_module_code = code
    _last_module_version = version
    LIFT_QUALITY["proven"] = False
    body_text, score = decompile_object(code, version, None)
    proven = body_text is not None and decompile_accepted(score, version)
    LIFT_QUALITY["proven"] = proven
    content_first = False
    if not proven:
        # second attempt for hostile modules: degrade instead of giving up, but
        # only accept it when the result really is valid Python
        body_text, score = decompile_object(code, version, None, tolerant=True)
        if body_text is None or compile_problem(body_text) is not None:
            return None
        # the structural pass loses code when a handler swallows a region; the
        # statement lifter never structures try/with, so it keeps more.  Take
        # whichever recovers more of the payload.
        try:
            lifted = _lift_module5(code, version)
        except Exception:                            # noqa: BLE001 - optional path
            lifted = None
        # A desynchronised statement can swallow the MAKE_FUNCTION/STORE pairs
        # that follow it, which silently drops whole functions.  Each code
        # object that never made it into the rebuild is rebuilt on its own and
        # appended, so no payload code is left behind.
        body_text = _append_missing_units(code, version, body_text)
        if lifted and compile_problem(lifted) is None:
            # Which candidate *keeps more of the payload*?  Length alone is a
            # poor proxy (a rebuild can be long and still drop constants), so
            # both are measured against the original's constants and names.
            mine = content_coverage(code, body_text)
            theirs = content_coverage(code, lifted)
            if theirs > mine or (len(lifted) > len(body_text) * 1.5 and theirs >= mine - 0.05):
                body_text = lifted
                content_first = True
    importable = {text for _off, opname, _arg, text in disassemble(code, version)
                  if opname == "IMPORT_NAME"}
    # One line, always the same: the recovered file says who produced it and
    # nothing else.  The round-trip score and the degraded-mode note are still
    # reported — the console panel and the `--reports` files carry them.
    from ..terminal.banner import stamp
    lines = [stamp(), ""]
    header = lines[0]
    lines = lines[1:]
    lines.extend(body_text.rstrip().split("\n"))
    text = "\n".join(ensure_parseable(clamp_indent(sanitize(lines)))) + "\n"
    head = name_audit(text, importable)
    # provenance first, then any stand-ins, then the reconstruction
    return "\n".join([header] + list(head) + [text]) + "\n"
