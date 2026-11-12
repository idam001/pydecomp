"""Named-family stress: BlankOBF, pyobfuscate.dev, Jawbreaker, Wodx, PlusOBF.

Each fixture is built with the real recipe those families use, then run through
dist/pydecomp.py.  The check is the same one a user would make: does the
recovered file import cleanly and still contain the original program's logic?
"""
import base64
import lzma
import marshal
import os
import pathlib
import subprocess
import sys
import sysconfig
import tempfile
import zlib

TOOL = str(pathlib.Path(__file__).resolve().parents[2] / "dist" / "pydecomp.py")
PROGRAM = (
    'import os\n'
    'API = "https://collector.invalid/v2/report"\n'
    'def collect(payload):\n'
    '    print("upload", len(payload))\n'
    '    return os.getcwd()\n'
    'if __name__ == "__main__":\n'
    '    collect(API)\n'
)


def compile_code(source: str):
    return compile(source, "<sample>", "exec")


def blankobf() -> str:
    """BlankOBF: base64(lzma(marshal(code))) inside a bare exec."""
    blob = base64.b64encode(lzma.compress(marshal.dumps(compile_code(PROGRAM)))).decode()
    return ("import base64, lzma, marshal\n"
            f"exec(marshal.loads(lzma.decompress(base64.b64decode('{blob}'))))\n")


def pyobfuscate_dev() -> str:
    """pyobfuscate.dev: reversed base64 + zlib through a one-liner lambda."""
    body = base64.b64encode(zlib.compress(PROGRAM.encode(), 9))[::-1].decode()
    return ("import base64, zlib\n"
            "_ = lambda __: zlib.decompress(base64.b64decode(__[::-1]))\n"
            f"exec(_('{body}'))\n")


def jawbreaker() -> str:
    """Jawbreaker: string pairs joined at runtime, then exec'd."""
    halves = [PROGRAM[i:i + 7] for i in range(0, len(PROGRAM), 7)]
    table = ",\n".join('    %r' % base64.b64encode(part.encode()).decode()
                       for part in halves)
    return ("import base64\n"
            "_0x = [\n%s\n]\n"
            "exec(''.join(base64.b64decode(_p).decode() for _p in _0x))\n" % table)


def wodx() -> str:
    """Wodx: one giant chr()-of-ordinals payload, marshalled, exec'd."""
    numbers = ",".join(str(ord(ch)) for ch in marshal.dumps(compile_code(PROGRAM)).hex())
    return ("exec(marshal.loads(bytes.fromhex(''.join(chr(_n) for _n in [%s]))))\n"
            % numbers)


def plusobf() -> str:
    """PlusOBF: bz2 + base64 with the builtin names split apart."""
    blob = base64.b64encode(zlib.compress(PROGRAM.encode()[::-1], 9)).decode()
    return ("_i = __import__\n"
            "_b = _i('base64')\n"
            "_z = _i('zlib')\n"
            f"exec(_z.decompress(_b.b64decode('{blob}'))[::-1].decode())\n")


FAMILIES = {
    "blankobf": blankobf,
    "pyobfuscate_dev": pyobfuscate_dev,
    "jawbreaker": jawbreaker,
    "wodx": wodx,
    "plusobf": plusobf,
}


def main() -> int:
    work = tempfile.mkdtemp()
    failures = 0
    for name, builder in FAMILIES.items():
        sample = os.path.join(work, f"{name}.py")
        with open(sample, "w") as handle:
            handle.write(builder())
        out = os.path.join(work, name)
        proc = subprocess.run([sys.executable, TOOL, sample, "-o", out,
                               "--no-color", "--no-anim"],
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(f"FAIL {name:16} tool exit {proc.returncode}")
            failures += 1
            continue
        written = [f for f in os.listdir(out) if f.endswith(".py")]
        text = open(os.path.join(out, written[0]), encoding="utf-8",
                    errors="surrogateescape").read()
        body = text.split("\n", 1)[1]
        try:
            compile(body, "<recovered>", "exec", dont_inherit=True)
            parses = "ok"
        except SyntaxError as exc:
            parses = f"SYNTAX {exc.msg}"
        has_api = "collector.invalid" in body
        has_fn = "def collect" in body
        verdict = "ok" if (parses == "ok" and has_api and has_fn) else "FAIL"
        if verdict == "FAIL":
            failures += 1
        print(f"{verdict:4} {name:16} {len(text):>7,} B  parse={parses:10} "
              f"url={'y' if has_api else 'n'} function={'y' if has_fn else 'n'}")
        if verdict == "FAIL":
            print("     " + " | ".join(body.strip().splitlines()[:4]))
    passing = len(FAMILIES) - failures
    tail = "all good" if not failures else f"{failures} failed"
    print(f"\n{passing}/{len(FAMILIES)} named families reconstructed — {tail}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
