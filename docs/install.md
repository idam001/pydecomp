# Install

pydecomp has **no runtime dependencies** — only CPython 3.9 or newer. Pick the
delivery that matches where you are.

## pip / pipx

```bash
pip install pydecomp
pipx install pydecomp            # isolated, recommended for a CLI
```

This gives you the `pydecomp` command:

```bash
pydecomp --version
pydecomp --selftest
```

## From a checkout

```bash
git clone https://github.com/pydecomp/pydecomp.git
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
python3 tools/build_single.py        # -> dist/pydecomp.py, ~199 KB
```

Copy it anywhere Python exists:

```bash
scp dist/pydecomp.py phone:/sdcard/
# Termux:
python3 pydecomp.py suspicious.py
```

The bundle is self-sufficient: it carries its own module table, so there is no
`pydecomp/` directory to keep beside it. `python3 tools/build_single.py --check`
verifies a download matches a checkout.

## Docker

```bash
docker build -t pydecomp .
docker run --rm -v "$PWD:/w" -w /w --network=none pydecomp sample.py
```

Or from GHCR:

```bash
docker run --rm -v "$PWD:/w" -w /w --network=none ghcr.io/pydecomp/pydecomp sample.py
```

The image is `python:3.13-slim` plus the package. It runs as a non-root user,
with no network at runtime.

## Termux notes

Everything is pure standard library, so the F-Droid or Play-Store Termux build
works as-is:

```bash
pkg install python
python3 pydecomp.py sample.py --no-anim        # animation needs a real tty
```

`--no-anim` also helps on slow links: it skips the staged spinner.

## Verifying your install

```bash
pydecomp --selftest
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
