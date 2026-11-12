"""Probe: control-flow flattening (Jawbreaker style) and inline-__import__ shapes."""
import base64
import os
import pathlib
import subprocess
import sys
import tempfile
import zlib

TOOL = str(pathlib.Path(__file__).resolve().parents[2] / "dist" / "pydecomp.py")
PROGRAM = (
    'import os\n'
    'LIMIT = 3\n'
    'def total(values):\n'
    '    acc = 0\n'
    '    for value in values:\n'
    '        acc += value * 2\n'
    '    return acc\n'
    'if __name__ == "__main__":\n'
    '    print(total([1, 2, 3]))\n'
)

FLATTENED = '''import os
LIMIT = 3

def total(items):
    _state = 4
    _acc = 0
    _index = 0
    while True:
        if _state == 0:            # entry
            _acc = 0
            _index = 0
            _state = 1
        elif _state == 1:          # loop guard
            if _index < len(items):
                _state = 2
            else:
                _state = 3
        elif _state == 2:          # body
            _acc += items[_index] * 2
            _index += 1
            _state = 1
        elif _state == 3:          # exit
            return _acc
        elif _state == 4:
            if 7 * 7 == 49:
                _state = 0
            else:
                _state = 9
        else:
            _state = 3

if __name__ == "__main__":
    print(total([1, 2, 3]))
'''


def pyminifier() -> str:
    blob = base64.b64encode(zlib.compress(PROGRAM.encode(), 9)).decode()
    return (
        "__import__('builtins').exec(__import__('zlib').decompress("
        f"__import__('base64').b64decode('{blob}')))\n"
    )


def inline_builtins() -> str:
    blob = base64.b64encode(zlib.compress(PROGRAM.encode()[::-1], 9)).decode()
    return (
        "_bi = __import__('builtins')\n"
        "_co = __import__('codecs')\n"
        f"_bi.exec(_co.decode(__import__('zlib').decompress("
        f"__import__('base64').b64decode('{blob}')), 'utf-8')[::-1])\n"
    )


CASES = {
    "jawbreaker_flattened": lambda: FLATTENED,
    "pyminifier_inline": pyminifier,
    "inline_builtins": inline_builtins,
}


def main() -> int:
    work = tempfile.mkdtemp()
    failures = 0
    for name, builder in CASES.items():
        sample = os.path.join(work, name + ".py")
        with open(sample, "w") as handle:
            handle.write(builder())
        out = os.path.join(work, name)
        proc = subprocess.run([sys.executable, TOOL, sample, "-o", out,
                               "--no-color", "--no-anim"],
                              capture_output=True, text=True, timeout=300)
        written = [f for f in os.listdir(out) if f.endswith(".py")] if os.path.isdir(out) else []
        if proc.returncode != 0 or not written:
            print(f"FAIL {name:22} exit={proc.returncode} {proc.stderr.strip()[:200]}")
            failures += 1
            continue
        text = open(os.path.join(out, written[0]), encoding="utf-8",
                    errors="surrogateescape").read()
        body = text.split("\n", 1)[1]
        try:
            compile(body, "<r>", "exec", dont_inherit=True)
            parses = "ok"
        except SyntaxError as exc:
            parses = f"SYNTAX {exc.msg}"
        checks = {
            "function": "def total" in body,
            "no dispatcher": "_state" not in body and "while True" not in body,
            "loop": "for " in body or "while " in body,
            "print": "print(" in body,
        }
        verdict = "ok" if parses == "ok" and all(checks.values()) else "FAIL"
        if verdict == "FAIL":
            failures += 1
        print(f"{verdict:4} {name:22} {len(text):>6,} B  parse={parses:8} "
              + " ".join(f"{k}={'y' if v else 'n'}" for k, v in checks.items()))
        print("     " + "\n     ".join(body.strip().splitlines()[:14]))
        print()
    passing = len(CASES) - failures
    tail = "all good" if not failures else f"{failures} failed"
    print(f"{passing}/{len(CASES)} shapes reconstructed — {tail}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
