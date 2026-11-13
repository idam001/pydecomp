"""Hostile input: the readers fail politely.

Fuzzing (``tools/fuzz_parsers.py``) found two ways for a partly-decoded stream to
come out as a crash instead of a refusal:

* a marshal stream nesting a thousand containers deep became a ``RecursionError`` -
  the reader is recursive, and nothing bounded the depth;
* a code object whose ``names``/``varnames``/``consts`` held a scalar rather than a
  table made the disassembler and the version scorer raise ``TypeError`` while
  scoring a candidate decode.

Both are pinned here, because the fuzz gate proves them on random bytes and these
prove them on the exact shapes.
"""
from __future__ import annotations

import marshal

import pytest

from pydecomp.bytecode.codeobj import CodeObj
from pydecomp.bytecode.disassembler import disassemble
from pydecomp.bytecode.marshal_reader import MAX_DEPTH, MarshalReader, parse_marshal_blob
from pydecomp.bytecode.version_score import _version_score


def nested(depth: int) -> bytes:
    """A marshal stream of *depth* nested one-element tuples."""
    return (b"".join(b"(" + (1).to_bytes(4, "little") for _ in range(depth))
            + b"N" + b"t" * depth)


# --------------------------------------------------------------------------
# the depth guard
# --------------------------------------------------------------------------

def test_a_shallow_nest_still_reads():
    value = MarshalReader(nested(10), (3, 13)).object()
    depth = 0
    while isinstance(value, tuple) and len(value) == 1:
        value = value[0]
        depth += 1
    assert depth == 10


def test_depth_is_refused_at_the_limit_with_a_declared_error():
    with pytest.raises(ValueError, match="nests deeper"):
        MarshalReader(nested(MAX_DEPTH + 5), (3, 13)).object()


def test_a_stream_thousands_deep_is_a_refusal_not_a_stack_overflow():
    # this used to raise RecursionError, which is not something the pipeline
    # handles, and on a smaller stack would kill the process
    try:
        MarshalReader(nested(20000), (3, 13)).object()
    except ValueError as exc:
        assert "nests deeper" in str(exc)
    except RecursionError:                                # pragma: no cover
        pytest.fail("a deep stream raised RecursionError instead of a refusal")


def test_the_depth_counter_returns_to_zero_after_a_refusal():
    reader = MarshalReader(nested(MAX_DEPTH + 5), (3, 13))
    with pytest.raises(ValueError):
        reader.object()
    assert reader.depth == 0


# --------------------------------------------------------------------------
# tables that are not tables
# --------------------------------------------------------------------------

def scalar_tables() -> CodeObj:
    code = CodeObj()
    code.code = bytes([100, 1, 83, 0])          # LOAD_NAME 1; RETURN_VALUE
    code.consts = 7                              # a scalar where a table belongs
    code.names = None
    code.varnames = 3
    return code


def test_the_disassembler_renders_a_malformed_code_object():
    instructions = list(disassemble(scalar_tables(), (3, 13)))
    assert instructions, "a malformed code object still disassembles"
    assert all(isinstance(text, str) for _off, _name, _arg, text in instructions)


def test_the_version_scorer_does_not_raise_on_it():
    assert isinstance(_version_score(scalar_tables(), (3, 13)), float)


def test_parse_marshal_blob_refuses_garbage_without_raising():
    for blob in (b"", b"\x00", b"c" + b"\xff" * 40, nested(400)):
        version, obj, layout = parse_marshal_blob(blob)
        assert version is None and obj is None and layout == 0.0


def test_parse_marshal_blob_still_reads_a_real_stream():
    blob = marshal.dumps(compile("x = 1\n", "s.py", "exec"))
    version, obj, layout = parse_marshal_blob(blob)
    assert obj is not None, "a real marshal stream still decodes"
    assert layout > 0.99
