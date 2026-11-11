# Install

pydecomp has **no runtime dependencies** — only CPython 3.9 or newer. Pick the
delivery that matches where you are.

## pip / pipx (from the repository)

> **The PyPI name `pydecomp` belongs to an unrelated project** (a geometry
> package). `pip install pydecomp` installs that one, not this tool. Install
> from Git until a release is published under a name this project owns.

```bash
pip install "git+https://github.com/idam001/pydecomp.git"
pipx install "git+https://github.com/idam001/pydecomp.git"   # isolated CLI
```

This gives you the `pydecomp` command:

```bash
pydecomp --version
pydecomp --selftest
```

## From a checkout

```bash
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
pip install -e ".[dev]"
python3 tools/run_gates.py     # nine gates, ~10 seconds
```

Without installing anything, the package runs straight from `src/`:

```bash
PYTHONPATH=src python3 -m pydecomp sample.py
```

## Single file (no pip, phone, jump host)

The whole package — engine, decoders, opcode tables and the native sidecar —
builds into one runnable file:

```bash
python3 tools/build_single.py        # -> dist/pydecomp.py, ~273 KB
```

Copy it anywhere Python exists:

```bash
scp dist/pydecomp.py phone:/sdcard/
# Termux:
python3 pydecomp.py suspicious.py
```

On a phone or a jump host, see [Termux](termux.md) for the exact steps.

The bundle is self-sufficient: it carries its own module table, so there is no
`pydecomp/` directory to keep beside it. `python3 tools/build_single.py --check`
verifies a download matches a checkout.

## Docker

```bash
docker build -t pydecomp .
docker run --rm -v "$PWD:/w" -w /w --network=none pydecomp sample.py
```

No image is published yet, so build it locally with the command above. Once an
image is pushed it will live at `ghcr.io/idam001/pydecomp`.

The image is `python:3.13-slim` plus the package. It runs as a non-root user,
with no network at runtime.

## Termux

Short version — full walkthrough on the [Termux page](termux.md):

```bash
pkg install python
curl -L -O https://raw.githubusercontent.com/idam001/pydecomp/main/dist/pydecomp.py
python pydecomp.py sample.py -o out --no-anim --reports --yara --diff
```

`--no-anim` skips the staged spinner (the animation wants a real tty, and it is
wasted work on a phone).

## Verifying your install

```bash
python pydecomp.py --selftest     # or just: pydecomp --selftest
```

It checks the interpreter, imports the native sidecar, runs a synthetic
recovery end to end and prints the version of each component. Exit code is 0
when every part is ready.

## Uninstall

Nothing is written outside the package and the output folder; there is no cache
directory and no config file.

```bash
pip uninstall pydecomp
```
