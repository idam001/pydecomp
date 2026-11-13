"""A member inside an archive: zip and tar, read in memory, nothing extracted.

A packer that ships a zip is shipping one file, and reading that file is the
whole job.  Both openers return a member only when the archive holds exactly
one plausible one - picking "the interesting member" out of a dozen is a guess,
and guesses do not become payloads here.
"""

from __future__ import annotations

import io
import tarfile
import zipfile

from ..spec import Backend

SKIP = (b"__MACOSX", b".DS_Store")


def _only(candidates: list[bytes]) -> bytes | None:
    usable = [item for item in candidates if item]
    return usable[0] if len(usable) == 1 else None


def _open_zip(blob: bytes) -> bytes | None:
    if not blob.startswith(b"PK\x03\x04") and b"PK\x03\x04" not in blob[:4096]:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(bytes(blob))) as archive:
            members = [name for name in archive.namelist()
                       if not any(marker.decode() in name for marker in SKIP)
                       and not name.endswith("/")]
            if len(members) != 1:
                return None
            return _only([archive.read(members[0])])
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError):
        return None


def _open_tar(blob: bytes) -> bytes | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(bytes(blob)), mode="r:*") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            if len(members) != 1:
                return None
            handle = archive.extractfile(members[0])
            return _only([handle.read()]) if handle is not None else None
    except (tarfile.TarError, OSError, EOFError):
        return None


BACKENDS = [
    Backend("zipmember", "compress", 2, _open_zip, None,
            "the single file inside a zip"),
    Backend("tarmember", "compress", 2, _open_tar, None,
            "the single file inside a tar"),
]
