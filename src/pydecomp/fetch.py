"""pydecomp - fetch.

Some loaders do not carry their payload: they download it and run it.  A
zero-execution tool cannot follow them *by itself* - but fetching a URL is not
executing code, so with the operator's explicit say-so (``--fetch-iocs``) this
module retrieves each indicator and hands the bytes back to the engine, which
unpacks them statically exactly like anything else.

Off by default, bounded by a timeout, a size cap and a host count, and every
fetch is recorded so the proof can say where the bytes came from.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

REQUEST_TIMEOUT = 10.0
MAX_BYTES = 32 * 1024 * 1024
MAX_URLS = 8
USER_AGENT = "pydecomp/1.0 (static analysis; explicit --fetch-iocs)"


def urls(text: str) -> list[str]:
    """Plain http(s) URLs in *text*, de-duplicated and in order."""
    from .triage.iocs import extract
    found = extract(text or "") if text else {}
    out = []
    for url in (found.get("iocs") or {}).get("url", []) or []:
        if url.startswith(("http://", "https://")) and url not in out:
            out.append(url)
    return out[:MAX_URLS]


class Fetched:
    """One retrieval, and whether it was allowed to happen."""

    __slots__ = ("url", "ok", "status", "body", "note")

    def __init__(self, url: str):
        self.url = url
        self.ok = False
        self.status = 0
        self.body = b""
        self.note = ""

    def line(self) -> str:
        if not self.ok:
            return f"{self.url} - {self.note or 'not fetched'}"
        return f"{self.url} ({self.status}, {len(self.body):,} B)"


def fetch(url: str, timeout: float = REQUEST_TIMEOUT) -> Fetched:
    """Retrieve one URL.  No redirect into another scheme, no unbounded body."""
    result = Fetched(url)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        result.note = f"refused scheme {parsed.scheme!r}"
        return result
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(MAX_BYTES + 1)
            result.status = getattr(response, "status", 200) or 200
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result.note = f"{type(exc).__name__}: {exc}"
        return result
    if len(body) > MAX_BYTES:
        result.note = f"larger than the {MAX_BYTES:,} B cap - refused"
        return result
    result.body = body
    result.ok = bool(body)
    result.note = "" if body else "empty response"
    return result


def run(text: str, timeout: float = REQUEST_TIMEOUT) -> list[Fetched]:
    """Fetch every URL in *text* (bounded).  Callers must opt in first."""
    return [fetch(url, timeout) for url in urls(text)]


def summary(results: list[Fetched]) -> str:
    if not results:
        return "no indicators to fetch"
    ok = [item for item in results if item.ok]
    total = sum(len(item.body) for item in ok)
    return (f"{len(ok)}/{len(results)} indicator(s) fetched, {total:,} B "
            "handed back to the engine")
