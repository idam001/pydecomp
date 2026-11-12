# Freezers

A freezer wraps a Python program in something that is not Python. Each reader
claims the bytes by signature, returns the members worth digging into, and the
engine recurses into them with the same `dig()` a plain file goes through — so a
freezer inside a freezer still resolves.

```console
$ pydecomp app.bin
   ▸ stage 1   pyinstaller container: 3 python member(s) inside
   ▸ stage 2   deepest member: pkg.mod.pyc
   ▸ stage 3   pyc header · CPython 3.13 · 8,418 B
```

| freezer | signature | what comes out |
|---|---|---|
| **PyInstaller** | `MEI\014\013\012\013\016` cookie | CArchive TOC → `PYZ` → per-module `.pyc` with the stripped 16-byte header rebuilt from the cookie's interpreter version |
| **cx_Freeze** | `library.zip` of `.pyc`, or an all-`.pyc` zip | the modules |
| **py2exe** | PE image with an appended zip | the embedded `library.zip` |
| **PEX** | `PEX-INFO` | the app's own sources (bootstrap skipped) |
| **shiv** | `_bootstrap/` + `site-packages/` | the packaged sources |
| **briefcase** | `*.dist-info` + `app_packages/` | the app tree |

PyInstaller notes, since they are the ones that bite:

* the cookie is found by searching for the magic, not by assuming it is at the
  end — a self-extractor may have data after it;
* `package_len`, `toc_offset` and `toc_len` are used to derive the archive start,
  so the reader works on one-file and one-dir layouts;
* a compressed member occupies `compressed` bytes and an uncompressed one
  `uncompressed`; reading the wrong field slices a `PYZ` into the next member —
  fixed, and pinned by `test_pyinstaller_recovers_pyz_modules`;
* `PYZ` member offsets are relative to the **decompressed** stream, not to the
  marshalled table.

PyOxidizer stays detect-only until a reader lands; nothing pretends otherwise.
