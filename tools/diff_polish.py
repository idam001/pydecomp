#!/usr/bin/env python3
"""Prove the polish passes change how code reads without changing what it does.

Every pass in ``polish/`` rewrites structure that carries meaning: a loop, a
branch, an inlined call, a propagated constant, a re-associated arithmetic
expression.  Each one is covered by a *structural* test - "does the output
contain ``for _item in items``" - and structure is not behaviour.  The
mutable-literal propagation bug recorded in ``docs/UPGRADES.md`` passed every
gate this project had, because the rewritten code parsed, compiled and looked
right; it just returned ``[]``.

So this harness compares *results*.  It generates small programs (never a
sample: the fixtures below are written here, in this file), runs one polish pass
over each, then executes the original and the rewritten program in separate
interpreter processes over a table of inputs and compares what they return.  Any
divergence fails the gate, and the failure names the fixture and the pass.

    python3 tools/diff_polish.py              # every fixture, every pass
    python3 tools/diff_polish.py --list       # fixture and pass names
    python3 tools/diff_polish.py mba opaque   # a subset of passes
    python3 tools/diff_polish.py -v           # show each variant's source

What is executed is the *fixture* - code this tool wrote - in a separate process,
with ``-I`` so the environment stays out of the comparison.  The sample is
never involved.

Two things keep the gate from going quiet.  Before comparing anything, the harness
plants a wrong rewrite (``a + b`` becomes ``a - b``) and refuses to continue if it
does not catch it - a green run has to mean the comparison works.  And every pass
is required to have changed at least one fixture: a pass that rewrote nothing was
not tested, and the gate says so rather than counting it as clean.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import subprocess
import sys
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

TIMEOUT = 60

# --------------------------------------------------------------------------
# the passes under test: name -> callable(tree) -> anything
# --------------------------------------------------------------------------

def passes():
    from pydecomp.polish.aliases import normalize_aliases
    from pydecomp.polish.dead import _strip_dead
    from pydecomp.polish.evaluate import fold_expressions
    from pydecomp.polish.fold import _fold_constants
    from pydecomp.polish.inline import inline_pure_functions, propagate_constants
    from pydecomp.polish.loops import recover_loops
    from pydecomp.polish.mba import simplify_mba
    from pydecomp.polish.opaque import strip_opaque
    from pydecomp.polish.strarrays import resolve_string_arrays
    from pydecomp.polish.unflatten import _unflatten

    return {
        "mba": simplify_mba,
        "opaque": strip_opaque,
        "dead": _strip_dead,
        "eval": fold_expressions,
        "fold": _fold_constants,
        "inline": inline_pure_functions,
        "propagate": propagate_constants,
        "aliases": normalize_aliases,
        "loops": recover_loops,
        "unflatten": _unflatten,
        "strarrays": resolve_string_arrays,
    }


# --------------------------------------------------------------------------
# fixtures: each defines run(<arg>) and is exercised over the inputs beside it
# --------------------------------------------------------------------------

FIXTURES: list[tuple[str, str, list[str]]] = [
    ("append_loop", """
        def run(n):
            out = []
            for i in range(n):
                out.append(i * 2)
            return out
    """, ["0", "1", "4"]),

    ("mutable_default_table", """
        def run(n):
            table = {}
            for i in range(n):
                table[i] = i * i
            return sorted(table.items())
    """, ["0", "3"]),

    ("while_counter", """
        def run(n):
            total = 0
            i = 0
            while i < n:
                total += i
                i += 1
            return total
    """, ["0", "1", "5"]),

    ("string_builder", """
        def run(n):
            out = ''
            for i in range(n):
                out += 'ab'
            return out
    """, ["0", "2", "3"]),

    ("mba_sum_diff", """
        def run(pair):
            a, b = pair
            hidden = (a ^ b) + 2 * (a & b)
            masked = (a | b) - (a & b)
            return [hidden, masked, hidden - masked]
    """, ["[3, 5]", "[0, 0]", "[7, 7]", "[10, 3]"]),

    ("opaque_guard", """
        def run(x):
            if x * x >= 0:
                return 'real'
            return 'junk'
    """, ["0", "3", "-4"]),

    ("polynomial_guard", """
        def run(x):
            if (x * x + x) % 2 == 0:
                return x + 1
            return -1
    """, ["0", "1", "6", "-3"]),

    ("dead_and_unused", """
        def run(n):
            unused = n * 3
            if False:
                return 'never'
            return n + 1
    """, ["0", "2"]),

    ("inlined_decoder", """
        def _d(s):
            return s[::-1]

        _payload = _d('cba')

        def run(n):
            return _payload * n
    """, ["0", "1", "2"]),

    ("alias_chain", """
        _a = _b = 'inner'

        def run(n):
            return _a * n + _b
    """, ["0", "2"]),

    ("constant_propagation", """
        _scale = 3
        _offset = 2.5

        def run(n):
            return n * _scale + _offset
    """, ["0", "2", "-1"]),

    ("nested_loops", """
        def run(n):
            total = 0
            for i in range(n):
                for j in range(i):
                    total += i * j
            return total
    """, ["0", "1", "4"]),

    ("try_loop", """
        def run(pair):
            a, b = pair
            out = []
            for value in (a, b, 0):
                try:
                    out.append(10 // value)
                except ZeroDivisionError:
                    out.append('div0')
            return out
    """, ["[2, 5]", "[1, 1]"]),

    ("flattened_states", """
        def run(n):
            state = 0
            total = 0
            while True:
                if state == 0:
                    if n <= 0:
                        state = 2
                    else:
                        state = 1
                elif state == 1:
                    total += n
                    n -= 1
                    state = 0
                elif state == 2:
                    return total
    """, ["0", "1", "3"]),

    ("string_table", """
        _S = ['apple', 'banana', 'cherry']
        _off = 1

        def run(n):
            return _S[(n + _off) % 3]
    """, ["0", "1", "2"]),

    ("recursion_untouched", """
        def run(n):
            if n <= 1:
                return 1
            return n * run(n - 1)
    """, ["0", "1", "5"]),

    ("loop_index_recovery", """
        def run(items):
            total = 0
            i = 0
            while i < len(items):
                total += items[i] * 2
                i += 1
            return total
    """, ["[]", "[1]", "[1, 2, 3]"]),

    ("unicode_alias", """
        ᐁ = 3

        def run(n):
            return ᐁ * n
    """, ["0", "2"]),

    ("dynamic_builtin_lookup", """
        import base64
        _d = __import__('base64').b64decode

        def run(n):
            return len(_d('aGk=')) * n
    """, ["0", "2"]),

    ("decoder_constant_fold", """
        import base64
        _p = base64.b64decode('aGk=')

        def run(n):
            return len(_p) * n
    """, ["0", "2"]),

    ("constant_expression_fold", """
        _a = 'a' + 'b' * 3

        def run(n):
            return len(_a) * n
    """, ["0", "2"]),

    ("dead_after_return", """
        def run(n):
            return n + 1
            n = 99
    """, ["0", "2"]),

    ("strarray_accessor", """
        _t = ['apple', 'banana', 'cherry']

        def _s(i):
            return _t[i]

        _first = _s(0)

        def run(n):
            return len(_first) * n
    """, ["0", "2"]),

    ("module_name_bound_late", """
        def run(n):
            return len(_name) * n

        _name = 'abc'
    """, ["0", "2"]),

    ("rebound_in_loop", """
        def run(n):
            k = 1
            for i in range(n):
                k = k + i
            return k
    """, ["0", "1", "4"]),

    ("bit_math_loop", """
        def run(n):
            total = 0
            for i in range(n):
                total ^= (i & 3) | (i << 1)
            return total
    """, ["0", "1", "6"]),
]


# --------------------------------------------------------------------------
# execution: the fixture, and only the fixture, in a separate process
# --------------------------------------------------------------------------

def driver(source: str, inputs: list[str]) -> str:
    """The fixture plus a tail that prints one repr per input."""
    lines = [source, "", "import json as _j", "_out = []"]
    for literal in inputs:
        lines.append(f"_out.append(repr(run({literal})))")
    lines.append("print(_j.dumps(_out))")
    return "\n".join(lines)


def execute(source: str, inputs: list[str]) -> tuple[str, str]:
    """Return ('ok', json) or ('crash', message).  Never raises."""
    try:
        done = subprocess.run([sys.executable, "-I", "-c", driver(source, inputs)],
                              capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return "crash", f"timed out after {TIMEOUT}s"
    if done.returncode != 0:
        tail = (done.stderr.strip().splitlines() or ["no output"])[-1]
        return "crash", tail
    return "ok", done.stdout.strip()


def unparse(tree) -> str:
    return ast.unparse(ast.fix_missing_locations(tree))


def render(tree) -> str:
    return unparse(tree) if not isinstance(tree, str) else tree


# --------------------------------------------------------------------------
# the comparison
# --------------------------------------------------------------------------

def variants(source: str, chosen: dict) -> list[tuple[str, str]]:
    """Every pass's output for *source*, plus the whole fixed-point driver."""
    out: list[tuple[str, str]] = []
    for name, apply in chosen.items():
        try:
            tree = ast.parse(source)
            apply(tree)
            out.append((name, unparse(tree)))
        except Exception as exc:                             # noqa: BLE001
            out.append((name, f"__pass_error__: {type(exc).__name__}: {exc}"))
    try:
        from pydecomp.polish.apply import polish_source
        text, _notes = polish_source(source)
        out.append(("polish_source", text))
    except Exception as exc:                                 # noqa: BLE001
        out.append(("polish_source", f"__pass_error__: {type(exc).__name__}: {exc}"))
    return out


def check_fixture(name: str, source: str, inputs: list[str], chosen: dict,
                  verbose: bool) -> tuple[list[dict], list[str]]:
    source = textwrap.dedent(source).strip() + "\n"
    expected = execute(source, inputs)
    failures: list[dict] = []
    fired: list[str] = []
    # two passes often reachthe same text (a fold and an evaluate agree); the
    # comparison is cached by text, but both passes still count as exercised
    cache: dict[str, tuple] = {}
    for pass_name, text in variants(source, chosen):
        if text.startswith("__pass_error__"):
            failures.append({"fixture": name, "pass": pass_name,
                             "kind": "pass raised", "detail": text[16:]})
            continue
        if text.strip() == source.strip():
            continue                       # a pass that changed nothing says nothing
        fired.append(pass_name)
        if text in cache:
            got = cache[text]
        else:
            got = execute(text, inputs)
            cache[text] = got
        if verbose:
            print(f"    {pass_name}: {text.splitlines()[0][:70]}")
        if got != expected:
            failures.append({"fixture": name, "pass": pass_name,
                             "kind": "behaviour differs",
                             "expected": expected, "got": got,
                             "source": text})
    return failures, fired


def planted_pass(tree):
    """A rewriter that is wrong on purpose: `a + b` becomes `a - b`.

    The harness has to catch this, or a green run means nothing.  It is the same
    class of bug as the mutable-literal propagation recorded in docs/UPGRADES.md -
    the output still parses, still compiles, and returns the wrong number.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.BinOp) \
                and isinstance(node.value.op, ast.Add):
            node.value.op = ast.Sub()
    return tree


def self_test() -> bool:
    """Prove the comparison catches a divergence before trusting a clean run."""
    source, inputs = None, []
    for name, text, given in FIXTURES:
        body = textwrap.dedent(text).strip() + "\n"
        adds = [node for node in ast.walk(ast.parse(body))
                if isinstance(node, ast.Return) and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.Add)]
        if adds:                    # a fixture whose result is a sum, so `-` shows
            source, inputs = body, given
            break
    if source is None:
        return False
    found, _fired = check_fixture("while_counter", source, inputs,
                                  {"planted": planted_pass}, False)
    return any(item["kind"] == "behaviour differs" for item in found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="pass names to test (default: all)")
    parser.add_argument("--list", action="store_true", help="print fixtures and passes")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", help="write the failures here")
    args = parser.parse_args()

    chosen = passes()
    if args.list:
        print("fixtures:", ", ".join(name for name, _s, _i in FIXTURES))
        print("passes:  ", ", ".join(chosen), "polish_source")
        return 0
    if args.names:
        unknown = [name for name in args.names if name not in chosen]
        if unknown:
            print(f"unknown pass(es): {', '.join(unknown)}")
            return 2
        chosen = {name: chosen[name] for name in args.names}

    if not self_test():
        print("FAIL self-test: a planted `a + b -> a - b` went unnoticed, so a green "
              "run here would mean nothing")
        return 1
    print("  ok   self-test             a planted divergence is caught")

    failures: list[dict] = []
    compared = 0
    fired: dict[str, int] = {name: 0 for name in chosen}
    fired["polish_source"] = 0
    print()
    for name, source, inputs in FIXTURES:
        expected = execute(textwrap.dedent(source).strip() + "\n", inputs)
        if expected[0] != "ok":
            failures.append({"fixture": name, "pass": "-", "kind": "fixture does not run",
                             "detail": expected[1]})
            print(f"  FAIL {name:<22} fixture does not run: {expected[1]}")
            continue
        found, changed = check_fixture(name, source, inputs, chosen, args.verbose)
        for pass_name in changed:
            fired[pass_name] = fired.get(pass_name, 0) + 1
        compared += 1
        if found:
            failures.extend(found)
            print(f"  FAIL {name:<22} {len(found)} divergence(s)")
            for item in found:
                print(f"        {item['pass']}: {item['kind']}")
                if item["kind"] == "behaviour differs":
                    print(f"          original : {item['expected']}")
                    print(f"          rewritten: {item['got']}")
                    print(textwrap.indent(item["source"].strip(), "          | "))
                else:
                    print(f"          {item.get('detail')}")
        elif args.verbose:
            print(f"  ok   {name:<22} identical")

    total_variants = len(FIXTURES) * (len(chosen) + 1)
    print()
    # A gate that can go quiet is not a gate: every pass has to have changed at
    # least one fixture, or this run proved nothing about it.
    quiet = [name for name, count in fired.items() if not count]
    print("  " + "  ".join(f"{name}:{count}" for name, count in fired.items()))
    if quiet:
        failures.append({"fixture": "-", "pass": ", ".join(quiet),
                         "kind": "never fired",
                         "detail": "no fixture makes this pass rewrite anything, so "
                                   "this run proved nothing about it"})
    if failures:
        print(f"{len(failures)} divergence(s) over {compared} fixtures "
              f"({total_variants} executions)")
        print(textwrap.indent(json.dumps(failures, indent=1)[:3000], "  "))
        if args.json:
            pathlib.Path(args.json).write_text(json.dumps(failures, indent=1), encoding="utf-8")
        return 1

    print(f"ok differential: {compared} fixtures x {len(chosen)} passes, "
          f"every rewrite returns what the original returns — all good")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
