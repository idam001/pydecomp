#!/usr/bin/env python3
"""How much of the identity corpus the SSA engine reconstructs on its own.

Every case in ``tests/integration/test_identity.py`` is compiled, the module code
object goes through ``ir_build`` → ``ir_emit``, and the result is accepted only
when it recompiles to the same instruction stream.  The rest of the corpus is
carried by the stack engine, whose output the identity gate already proves.

    python3 tools/ir_coverage.py            # table + totals
    python3 tools/ir_coverage.py --quiet    # totals only
    python3 tools/ir_coverage.py --check    # fail if coverage drops below FLOOR
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "integration"))

import pydecomp as P                                        # noqa: E402
from pydecomp.bytecode.ir_pipeline import lift_module_ir     # noqa: E402
from pydecomp.bytecode.codeobj import codeobj_from_host      # noqa: E402


#: the number of cases the SSA engine reconstructs identically today.  The gate
#: fails if a change makes this worse; raising it is the work of each release.
FLOOR = 16


def corpus() -> dict:
    from test_identity import CASES
    return dict(CASES)


def main() -> int:
    quiet = "--quiet" in sys.argv
    rows = []
    for label, source in corpus().items():
        try:
            code = codeobj_from_host(compile(source, f"<{label}>", "exec"))
        except SyntaxError:
            rows.append((label, "n/a", "does not compile on this interpreter"))
            continue
        text, report = lift_module_ir(code, P.host_version())
        if text is None:
            rows.append((label, "stack", report.get("detail", "")))
        else:
            rows.append((label, "ssa-ir", report.get("detail", "")))
    ir = sum(1 for row in rows if row[1] == "ssa-ir")
    total = len(rows)
    if not quiet:
        width = max(len(row[0]) for row in rows)
        for label, engine, detail in rows:
            print(f"{label:<{width}}  {engine:<7}  {detail}")
        print()
    summary = (f"SSA engine: {ir}/{total} cases instruction-identical "
               f"({100.0 * ir / total:.1f}%)")
    check = "--check" in sys.argv
    if not check:
        print(summary)
        print(f"stack engine carries the other {total - ir}")
    if check and ir < FLOOR:
        print(f"REGRESSION: the SSA engine covered {FLOOR} cases before, {ir} now")
        return 1
    if check:
        # the gate reads the last line, so the verdict is the last line
        print(f"ok {summary}, floor {FLOOR}, "
              f"stack engine carries the other {total - ir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
