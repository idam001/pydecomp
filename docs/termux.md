# Termux (Android)

pydecomp is pure standard library, so it runs on a phone with nothing but
Python.  There is no pip dependency to break, no compiled extension, and no
build step you have to perform on the device: the single-file bundle is the
whole tool.

Everything below was run on Termux itself; the command names are what Termux
ships, not a desktop translation.

## 1. Install Python

```bash
pkg update
pkg install python curl
python --version          # 3.12 or newer is plenty
```

Termux provides both `python` and `python3`; this page uses `python`.

## 2. Get the tool

**Download the single file** (smallest, easiest to move around):

```bash
mkdir -p ~/tools && cd ~/tools
curl -L -O https://raw.githubusercontent.com/idam001/pydecomp/main/dist/pydecomp.py
python pydecomp.py --version
```

GitHub serves raw files through a short CDN cache (minutes), so if you download
seconds after a release you may briefly get the previous file. Pinning a commit
always works: `https://raw.githubusercontent.com/idam001/pydecomp/<sha>/dist/pydecomp.py`.

That is the entire installation — one 273 KB file, no package directory beside
it.  If you would rather keep a checkout with the tests and docs:

```bash
pkg install git
git clone https://github.com/idam001/pydecomp.git
cd pydecomp
python -m pip install ".[dev]"
```

## 3. Check the install

```bash
python ~/tools/pydecomp.py --selftest
```

```
   ╭─ SELFTEST ──────────────────────────────────────────────────────────────╮
   │ pydecomp  1.0.0                                                         │
   │ python    3.12.7                                                        │
   │ platform  Linux aarch64                                                 │
   │ native    8.1.0 (embedded)                                              │
   ╰─────────────────────────────────────────────────────────────────────────╯
   ✔ ELF parser: ET_DYN
   ✔ native layer is ready — options 2 and 3 will work
```

Exit code is 0 when every part is ready.  `(embedded)` is correct here: in the
single file the native sidecar lives inside the bundle, so it has no path of its
own.

## 4. Let Termux see your files

Android keeps app storage separate.  To reach a file you downloaded with a
browser or received over chat:

```bash
termux-setup-storage        # tap Allow
ls ~/storage/downloads      # /sdcard/Download
```

Anything under `~/storage/` is just a symlink — you can read it in place, but
writing output there is slower than writing to Termux's own storage, so send
results to `~` and copy them out at the end.

## 5. Deobfuscate something

```bash
cd ~/storage/downloads
python ~/tools/pydecomp.py suspicious.py -o ~/out --no-anim
```

Then, with the evidence you would want in a report:

```bash
python ~/tools/pydecomp.py suspicious.py -o ~/out \
    --no-anim --reports --yara --diff
cp ~/out/* ~/storage/shared/pydecomp-results/    # out to Android storage
```

What you get in `~/out`:

| file | what it is |
|---|---|
| `suspicious_deob.py` | the recovered program, stamp header and nothing else added |
| `suspicious_deob.report.md` | human-readable findings |
| `suspicious_deob.report.json` | same findings, machine-readable |
| `suspicious_deob.yar` | YARA rule built from the recovered indicators |
| `suspicious_deob.coverage.md` | what was kept versus the unpacked original |

## Flags that matter on a phone

| flag | why |
|---|---|
| `--no-anim` | the spinner wants a real tty; on a phone it is only wasted work |
| `--no-color` | for piping results into a chat, a note app, or `less -R` |
| `--fast` | skips the expensive opaque-predicate search; identical output for clean files |
| `--deep` | the opposite — more decoder chains, more XOR keys. Slower, more battery |
| `--dry-run` | checks the recovered program compiles and every name resolves, without running it |
| `--artifacts` | keeps the untouched input bytes next to the output, for chain of custody |
| `-o ~/out` | write to Termux storage; `~/storage/…` is slower |

Nothing here ever executes the sample.  That matters more on a phone than
anywhere else: the file you are looking at cannot touch your contacts, your
SMS, or your accounts, because no interpreter ever loads it.

## Big samples, small RAM

A 1.5 MB six-layer packer unpacks to ~1.6 MB of source in a few seconds and a
few tens of MB of RAM.  On a low-memory device:

- prefer `--fast` for exploratory passes and re-run with `--deep` only on
  samples that look interesting;
- run one sample at a time — the tool works on one input per invocation;
- keep output on `~`, not on `/sdcard`.

If Android kills the process, it is the OS reclaiming memory, not a crash:
`dmesg | tail` will show the low-memory kill.  Close other apps and retry with
`--fast`.

## Working inside Termux day to day

```bash
alias pydecomp='python ~/tools/pydecomp.py'      # add to ~/.bashrc
pydecomp suspicious.py -o ~/out --no-anim
```

Copying a result into a note or a chat is easiest with `--no-color` and one
sample at a time:

```bash
pydecomp suspicious.py -o ~/out --no-anim --no-color | tail -12
```

## What not to expect

- **No GUI.** It is a terminal tool; the ASCII panel is the interface.
- **No native disassembly of your own apps** — the native options work on ELF
  payloads you feed it, not on installed Android apps (which are APK/AAB, and
  reading them is outside what this tool does).
- **No PyPI install under the name `pydecomp`** — that name on PyPI is an
  unrelated geometry package. Use the single file or the Git URL.
