"""Bytecode round trips: compile, marshal, lift, compare.

These are the tests that keep the lifter honest.  Each shape is compiled by the
*running* interpreter, marshalled, then lifted back to source; the recovered
source must contain the same behaviour-bearing constructs.  Nothing is executed:
``compile()`` and ``marshal.dumps()`` only produce bytes.
"""
from __future__ import annotations

import ast
import pathlib
import py_compile
import sys
import tempfile

import pydecomp
import pytest

SHAPES = {
    "assignment": "value = 1 + 2\n",
    "augmented": "total = 0\ntotal += 3\n",
    "loop": "total = 0\nfor item in [1, 2, 3]:\n    total += item\n",
    "while": "count = 0\nwhile count < 3:\n    count += 1\n",
    "compare": "if 2 < 3 and not 4 == 5:\n    flag = True\n",
    "string": "text = 'a' + 'b' * 2\n",
    "format": "name = 'x'\nline = f'hello {name}'\n",
    "function": "def add(a, b):\n    return a + b\n",
    "defaults": "def greet(name, greeting='hi'):\n    return greeting + ' ' + name\n",
    "closure": "scale = 2\ndef apply(value):\n    return value * scale\n",
    "class": (
        "class Point:\n"
        "    def __init__(self, x):\n"
        "        self.x = x\n"
        "\n"
        "    def double(self):\n"
        "        return self.x * 2\n"
    ),
    "inheritance": "class Base:\n    pass\n\nclass Child(Base):\n    pass\n",
    # recovered as a real `try` inside a function; at module scope the lifter
    # keeps the statements but comments the frames out (see the last test)
    "try_except": (
        "def parse(blob):\n"
        "    try:\n"
        "        return int(blob)\n"
        "    except ValueError:\n"
        "        return 0\n"
    ),
    "comprehension": "squares = [item * item for item in range(4)]\n",
    "dict_literal": "table = {'a': 1, 'b': 2}\n",
    "lambda": "double = lambda value: value * 2\n",
    "unpack": "first, second = 1, 2\n",
    "starred": "def take(*args, **kwargs):\n    return args, kwargs\n",
    "sort_key": "values = [3, 1, 2]\nvalues.sort(reverse=True)\n",
    "assert": "state = True\nassert state, 'must hold'\n",
    "slice": "items = [1, 2, 3]\nhead = items[:2]\n",
    "exception_raise": "def boom():\n    raise ValueError('no')\n",
}


def lift(source: str) -> str:
    """Compile to a .pyc, then lift it back the way the CLI does."""
    folder = pathlib.Path(tempfile.mkdtemp())
    path = folder / "shape.py"
    path.write_text(source, encoding="utf-8")
    pyc = py_compile.compile(str(path), cfile=str(path) + "c", doraise=True,
                             invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    version, module = pydecomp.parse_pyc(pathlib.Path(pyc).read_bytes())
    return pydecomp.lift_module(module, version)


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_shape_lifts_to_valid_python(name):
    text = lift(SHAPES[name])
    assert text.strip(), "nothing recovered"
    ast.parse(text)                      # must be valid Python


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_shape_keeps_its_identifiers(name):
    source = SHAPES[name]
    text = lift(source)
    tree = ast.parse(source)
    wanted = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    wanted |= {node.name for node in ast.walk(tree)
               if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    wanted -= {"Base", "self"}           # may be folded or implied
    missing = sorted(name for name in wanted if name not in text)
    assert missing == [], f"{name}: lost {missing}\n{text}"


@pytest.mark.parametrize("name", ["class", "inheritance", "try_except"])
def test_structure_survives(name):
    text = lift(SHAPES[name])
    tree = ast.parse(text)
    kinds = {type(node).__name__ for node in ast.walk(tree)}
    expected = {
        "class": {"ClassDef", "FunctionDef"},
        "inheritance": {"ClassDef"},
        "try_except": {"Try"},
    }[name]
    assert expected <= kinds, f"{name}: missing {expected - kinds}\n{text}"


def test_module_level_try_keeps_its_statements():
    """Known limit: statements survive, the `try` frame becomes a comment."""
    source = "try:\n    value = int('1')\nexcept ValueError:\n    value = 0\n"
    text = lift(source)
    assert "int('1')" in text
    assert "value = 0" in text
    ast.parse(text)


def test_preamble_is_the_first_line():
    text = lift(SHAPES["assignment"])
    assert text.splitlines()[0] == (
        "#[ Deobfuscated by idam Emmanuel ] only through pydecomp")
    assert text.count("Deobfuscated by") == 1, "the stamp appears once"


def test_lift_is_deterministic():
    source = SHAPES["class"]
    assert lift(source) == lift(source)
