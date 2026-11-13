"""The SSA engine: what it guarantees, and what it refuses.

Two kinds of test live here.  The first kind checks the IR's own invariants -
every value defined once, phi inputs that name real values, a back edge exactly
where a loop is.  The second kind checks the rule that makes a second engine
safe: the emitter's output is accepted only when it recompiles to the same
instruction stream, and a shape the emitter does not model is refused rather
than guessed.
"""
from __future__ import annotations

import ast
import dis
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pytest                                              # noqa: E402

from pydecomp.bytecode import ir_pipeline                   # noqa: E402
from pydecomp.bytecode.codeobj import codeobj_from_host     # noqa: E402
from pydecomp.bytecode.disassembler import disassemble       # noqa: E402
from pydecomp.bytecode.ir_build import build_ir, Unsupported  # noqa: E402
from pydecomp.bytecode.ir_emit import emit_module            # noqa: E402
from pydecomp.proof import tiers                             # noqa: E402

SOURCES = {
    "assign": "x = 1\nname = 'pydecomp'\nprint(name, x)\n",
    "arithmetic": "def f(a, b):\n    c = a + b * 2\n    return c\n",
    "if_return": "def g(x):\n    if x > 3:\n        return 1\n    return 0\n",
    "if_else_names": "def h(x):\n    y = 1\n    if x:\n        y = 2\n    return y\n",
    "while": "n = 0\nwhile n < 3:\n    n += 1\n",
    "for": "out = []\nfor i in range(4):\n    out.append(i * 2)\n",
    "import": "import zlib\nfrom json import dumps\n",
    "fstring": "def s(n):\n    return f'{n!r:>4}'\n",
    "nested_def": "def outer(a):\n    def inner(b):\n        return b + 1\n    return inner(a)\n",
}


def code_for(source: str):
    return codeobj_from_host(compile(source, "<ir-test>", "exec"))


@pytest.mark.parametrize("label", sorted(SOURCES))
def test_construct_is_instruction_identical(label):
    """Every construct the emitter claims to model recompiles identically."""
    text, report = ir_pipeline.lift_module_ir(code_for(SOURCES[label]),
                                              tiers.host_version())
    assert text is not None, report["detail"]
    assert tiers.grade(text, code_for(SOURCES[label]), tiers.host_version()) == "semantic"
    assert report["tier"] == "semantic"


def test_emitted_text_compiles_and_has_no_stray_return():
    text, _report = ir_pipeline.lift_module_ir(code_for(SOURCES["assign"]),
                                               tiers.host_version())
    compile(text, "<emitted>", "exec")
    tree = ast.parse(text)
    assert not any(isinstance(node, ast.Return) for node in tree.body)


@pytest.mark.parametrize("label", sorted(SOURCES))
def test_values_are_defined_once(label):
    fir = build_ir(code_for(SOURCES[label]), tiers.host_version())
    assert len(set(fir.values)) == len(fir.values)
    for value in fir.values.values():
        for ident in value.phi_inputs:
            assert ident in fir.values, "a phi names a value that does not exist"


def test_a_loop_produces_a_back_edge():
    fir = build_ir(code_for(SOURCES["while"]), tiers.host_version())
    edges = fir.back_edges()
    assert edges, "a while loop must leave a back edge"
    reach = fir.reachable()
    dom = fir.dominators()
    assert dom[fir.entry] == {fir.entry}
    for bid in reach:
        assert fir.entry in dom[bid], "the entry dominates everything it reaches"
    assert fir.stats()["loops"] >= 1


def test_for_loop_iterates_the_object_not_iter_of_it():
    text, _report = ir_pipeline.lift_module_ir(code_for(SOURCES["for"]),
                                               tiers.host_version())
    assert "for i in range(4):" in text
    assert "iter(" not in text


def test_loop_body_is_not_repeated():
    text, _report = ir_pipeline.lift_module_ir(code_for(SOURCES["for"]),
                                               tiers.host_version())
    assert text.count("for i in range(4):") == 1
    assert text.count("out.append(i * 2)") == 1


def test_unmodelled_shape_is_refused_not_guessed():
    """`try` needs exception-table structure the emitter does not model yet."""
    source = ("def t(x):\n"
              "    try:\n"
              "        return int(x)\n"
              "    except ValueError:\n"
              "        return 0\n")
    text, report = ir_pipeline.lift_module_ir(code_for(source), tiers.host_version())
    assert text is None
    assert report["detail"], "a refusal has to say what it refused"


def test_emitter_output_that_differs_is_thrown_away(monkeypatch):
    """The acceptance rule: identical instructions, or the stack engine keeps it."""
    monkeypatch.setattr(ir_pipeline, "emit_module", lambda fir, version: "x = 99\n")
    text, report = ir_pipeline.lift_module_ir(code_for(SOURCES["assign"]),
                                               tiers.host_version())
    assert text is None
    assert "instruction-identical" in report["detail"]


def test_size_limit_hands_large_code_to_the_stack_engine(monkeypatch):
    monkeypatch.setattr(ir_pipeline, "IR_SIZE_LIMIT", 1)
    text, report = ir_pipeline.lift_module_ir(code_for(SOURCES["assign"]),
                                               tiers.host_version())
    assert text is None
    assert "stack engine" in report["detail"]


def test_jump_targets_match_the_interpreter():
    """The 3.13 displacement rule, checked against `dis` rather than assumed."""
    source = ("def f(a, b):\n"
              "    t = 0\n"
              "    for i in range(a):\n"
              "        if i % 2:\n"
              "            t += i\n"
              "        else:\n"
              "            t -= b\n"
              "    return t\n")
    host = tiers.host_version()
    original = compile(source, "<jumps>", "exec").co_consts[0]
    real = {instr.offset: instr.argval for instr in dis.get_instructions(original)}
    seen = 0
    for offset, opname, _arg, text in disassemble(codeobj_from_host(original), host):
        if text.startswith("to "):
            target = int(text.split("to ", 1)[1])
            assert target == real[offset], (offset, opname, target, real[offset])
            seen += 1
    assert seen >= 4


def test_pipeline_reports_which_engine_ran():
    from pydecomp.lift.module import LIFT_QUALITY, lift_module

    text = lift_module(code_for(SOURCES["while"]), tiers.host_version())
    assert text.splitlines()[0].startswith("#[ Deobfuscated by idam Emmanuel ]")
    assert LIFT_QUALITY["engine"] in ("ssa-ir", "stack")
    assert LIFT_QUALITY["proven"] is (LIFT_QUALITY["engine"] == "ssa-ir")
    assert LIFT_QUALITY["ir"]["engine"] == "ssa-ir"


def test_unmodelled_opcode_raises_unsupported():
    """An opcode outside the IR is named, and the exception type is the contract."""
    source = "def t(x):\n    try:\n        return 1\n    except:\n        return 0\n"
    with pytest.raises(Unsupported):
        emit_module(build_ir(code_for(source), tiers.host_version()),
                    tiers.host_version())


def test_the_ir_never_executes_the_sample():
    """Static means static: no exec, no eval, no subprocess in the new engine."""
    banned = {"exec", "eval", "subprocess", "os.system", "popen"}
    for name in ("ir.py", "ir_build.py", "ir_emit.py", "ir_pipeline.py"):
        path = os.path.join(ROOT, "src", "pydecomp", "bytecode", name)
        tree = ast.parse(open(path).read())
        called = {node.func.id for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        assert not (called & banned), (name, called & banned)
        assert not any(item.split(".")[0] in banned for item in imported), name
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in banned:
                raise AssertionError(f"{name} reaches {node.attr}")


def test_emit_module_is_deterministic():
    code = code_for(SOURCES["if_else_names"])
    first, _a = ir_pipeline.lift_module_ir(code, tiers.host_version())
    second, _b = ir_pipeline.lift_module_ir(code, tiers.host_version())
    assert first == second


def test_describe_advertises_the_builder_and_emitter():
    info = ir_pipeline.describe()
    assert info["engine"] == "ssa-ir"
    assert info["builder"] and info["emitter"]
    assert ir_pipeline.available() == "in-house"


def test_ir_and_stack_engines_agree_on_names():
    """Whatever the engine, the recovered names come from the code object."""
    text, _report = ir_pipeline.lift_module_ir(code_for(SOURCES["for"]),
                                               tiers.host_version())
    for name in ("out", "i", "range", "append"):
        assert name in text
