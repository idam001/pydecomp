"""Run pydecomp against the hardest-obfuscation benchmark and score the result."""
# --- test harness paths (src/ layout) ---
import os as _os
import pathlib as _pathlib
import sys as _sys
ROOT = _pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
ENV = {**_os.environ, "PYTHONPATH": str(SRC)}
if str(SRC) not in _sys.path:
    _sys.path.insert(0, str(SRC))
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))            # repo root
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, FIXTURES)
import pydecomp as P                                              # noqa: E402
import obf_cases                                                # noqa: E402

CASES = os.path.join(FIXTURES, "obf_cases")


def run_case(folder: str) -> dict:
    truth = json.load(open(os.path.join(folder, "truth.json")))
    target = [name for name in os.listdir(folder) if name != "truth.json"][0]
    out_dir = tempfile.mkdtemp()
    env = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")}
    proc = subprocess.run([sys.executable, "-m", "pydecomp",
                           os.path.join(folder, target), "-o", out_dir,
                           "--no-color", "--no-anim"],
                          capture_output=True, text=True, timeout=600, env=env)
    files = [name for name in os.listdir(out_dir) if name.endswith(".py")]
    text = open(os.path.join(out_dir, files[0])).read() if files else ""
    rebuilt = any("Deobfuscated by" in line for line in text.split("\n")[:3])
    result = {
        "case": os.path.basename(folder),
        "rc": proc.returncode,
        "bytes": len(text),
        "rebuilt_source": rebuilt,
        "compiles": P.compile_problem(text) is None if text else False,
        "secret": truth["secret"] in text,
        "endpoint": truth["endpoint"] in text,
        "marker": truth["marker"] in text,
        "decoder_calls": len(re.findall(r"_d\(|_q\(|_s0\(|_junk\(|_mba\(", text)),
    }
    flat = sum(1 for _ in re.finditer(r"state\s*==", text))
    result["flat_leftover"] = flat
    contains = truth.get("contains") or {key: True for key in ("secret", "endpoint", "marker")}
    scored = [key for key in ("secret", "endpoint", "marker") if contains.get(key)]
    result["reachable"] = 1 + len(scored)
    result["score"] = int(result["compiles"]) + sum(result[key] for key in scored)
    return result


def main() -> int:
    obf_cases.build()
    rows = []
    for name in sorted(os.listdir(CASES)):
        folder = os.path.join(CASES, name)
        if os.path.isdir(folder):
            rows.append(run_case(folder))
    head = f"{'case':22s} {'rc':>3s} {'bytes':>7s} {'src':>4s} {'ok':>3s} " \
           f"{'secret':>7s} {'endp':>5s} {'mark':>5s} {'score':>5s}"
    print(head)
    print("-" * len(head))
    for row in rows:
        print(f"{row['case']:22s} {row['rc']:3d} {row['bytes']:7d} "
              f"{'yes' if row['rebuilt_source'] else ' - ':>4s} "
              f"{'y' if row['compiles'] else 'n':>3s} "
              f"{'yes' if row['secret'] else ' - ':>7s} "
              f"{'yes' if row['endpoint'] else ' - ':>5s} "
              f"{'yes' if row['marker'] else ' - ':>5s} "
              f"{row['score']:d}/{row['reachable']}")
    total = sum(row["score"] for row in rows)
    reachable = sum(row["reachable"] for row in rows)
    print(f"\nsemantic score: {total}/{reachable} reachable "
          f"({4 * len(rows)} checks, {4 * len(rows) - reachable} of them on values "
          f"the case never contains)  "
          f"| rebuilt as source: {sum(1 for r in rows if r['rebuilt_source'])}/{len(rows)}")
    json.dump(rows, open(os.path.join(HERE, "obf_report.json"), "w"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
