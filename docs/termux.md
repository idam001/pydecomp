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

## The main menu

With **no file argument** the tool opens its menu instead of taking a path:

```bash
python ~/tools/pydecomp.py
```

```
   ╭─ MAIN MENU ─────────────────────────────────────────────────────────────╮
   │ [1]  Deobfuscate a script     peel every layer  ·  save one file        │
   │ [2]  Cython module (.so)      rebuild the source from a compiled module │
   │ [3]  ELF binary               find python payloads inside a binary      │
   │ [0]  Exit                                                               │
   ╰─────────────────────────────────────────────────────────────────────────╯
   ❯ option
```

Type `1`, Enter, then paste the path of the sample and press Enter again.  The
menu loops until you choose `0`.

Two things worth knowing about menu mode:

- **Results land next to the sample** unless you pass `-o`.  Pass it on the
  command line — the menu keeps it for the whole session:

  ```bash
  python ~/tools/pydecomp.py -o ~/out      # then pick 1 and paste a path
  ```

- Menu mode asks for the sample path; the one-shot form takes it as an argument
  and never prompts, which is what you want for scripting:

  ```bash
  python ~/tools/pydecomp.py sample.py -o ~/out --no-anim
  ```

## Making `pydecomp` a real command

An `alias` only exists in the shell that defined it, and only after you load it.
After adding `alias pydecomp='python ~/tools/pydecomp.py'` to `~/.bashrc` you
must either open a new Termux session or run:

```bash
source ~/.bashrc
pydecomp                 # now this is the menu
```

Rather than rely on an alias, install it properly — pip writes a launcher with
the correct Termux interpreter path, so the plain command works forever:

```bash
pkg install git
python -m pip install "git+https://github.com/idam001/pydecomp.git"
pydecomp --selftest      # a real command, from any folder
```

Or write your own launcher (correct for Termux, where there is no `/usr/bin`):

```bash
mkdir -p $PREFIX/bin
cat > $PREFIX/bin/pydecomp <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
exec python "$HOME/tools/pydecomp.py" "$@"
EOF
chmod +x $PREFIX/bin/pydecomp
pydecomp --selftest
```

Note the shebang: the single file starts with `#!/usr/bin/env python3`, which is
right on Linux and macOS but wrong on Android, where `/usr/bin` does not exist.
So on Termux always start it as `python pydecomp.py …` (or use the launcher
above) — do not `./pydecomp.py`. If you want the download itself to be
executable, Termux ships a fixer: `termux-fix-shebang ~/tools/pydecomp.py`.

## Why the layout looks different from the desktop screenshots

Past versions sized every panel for a **minimum of 52 columns**.  A phone
terminal is usually 40–50, so each box was drawn wider than the screen, wrapped,
and the borders looked broken — that is the ragged frame you saw.

The interface now measures the terminal it is actually in:

| terminal width | what you get |
|---|---|
| 96+ columns | the full board: block-letter logo, ornament rules, one-line menu |
| 60–95 | same board, logo replaced by a wordmark when the letters no longer fit |
| 34–59 | compact board, menu descriptions on their own line instead of chopped |
| under 34 | the layout still fits; nothing wraps, ever |

Long progress lines and paths are trimmed from the middle, keeping what
identifies them — `saved to  …/out/KAMRUL~4_deob.py` rather than a cut-off
directory name.  Everything fits inside the width; nothing is ever drawn wider
than the window.

## "file not found" now tells you where to look

If the name you paste is not where the shell is standing, you no longer just get
a red line.  The tool searches the places a phone actually keeps downloads
(`~/storage/downloads`, `~/storage/shared`, `~/Download`, `/sdcard/Download`,
the current folder, your home) and answers with something you can paste:

```
   ✘ file not found: KAMRUL~4.py
     looked in: /data/data/com.termux/files/home/tools
     did you mean: /data/data/com.termux/files/home/storage/downloads/KAMRUL~4.py
     paste: python pydecomp.py '~/storage/downloads/KAMRUL~4.py' -o ~/out
```

- If exactly one file has that name, it is used and announced:
  `i using /…/storage/downloads/KAMRUL~4.py`.
- If **two** files share the name it refuses to guess and lists them.
- If you pointed at a folder, it says so and shows what is inside.

So `KAMRUL~4.py` works from any folder once it is in a scans/listings location.

## If a command "does not exist"

| what you typed | what happened | what to type |
|---|---|---|
| `python pydecomp` | Python was told to open a file called `pydecomp`, which is not there (the name ends in `.py`) | `python pydecomp.py` |
| `pydecomp` → *command not found* | the alias was written to `~/.bashrc` in a shell that had already started | `source ~/.bashrc`, or open a new session |
| `./pydecomp.py` → *bad interpreter* | Android has no `/usr/bin/env` | `python pydecomp.py` |
| `python pydecomp.py` shows the **menu** instead of a result | no path was given, which is how you ask for the menu | `python pydecomp.py sample.py -o ~/out` |
| `✘ file not found: KAMRUL~4.py` | the shell was in `~/tools`, the file is in the downloads folder | `python pydecomp.py '~/storage/downloads/KAMRUL~4.py' -o ~/out` — or just re-run: the tool now offers the match |

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
