"""Opt-in, bounded URL retrieval for static payload analysis.

Fetched bytes are handed to the static decoder pipeline and are never executed.
The fetcher deliberately avoids proxy configuration and redirects, resolves a
public destination once, pins the connection to that address, and enforces a
response-size cap.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
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
            status = f"HTTP {self.status}: " if self.status else ""
            return f"{self.url} - {status}{self.note or 'not fetched'}"
        return f"{self.url} ({self.status}, {len(self.body):,} B)"


def _public_address(host: str, port: int) -> str:
    """Resolve once and return a public address suitable for a pinned socket."""
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not records:
        raise OSError("host did not resolve")
    addresses = []
    for family, _socktype, _proto, _canonname, sockaddr in records:
        address = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise OSError("DNS returned an invalid address") from exc
        if not parsed.is_global:
            raise PermissionError(f"refused non-public address {parsed}")
        if family in (socket.AF_INET, socket.AF_INET6) and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError("host has no usable public address")
    return addresses[0]


def _pinned_connection(address: str, secure: bool):
    """Build a one-request connection class that never resolves the host again."""
    if secure:
        class PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self):
                sock = socket.create_connection(
                    (address, self.port), self.timeout, self.source_address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        return PinnedHTTPSConnection

    class PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.create_connection(
                (address, self.port), self.timeout, self.source_address)
    return PinnedHTTPConnection


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connection_class):
        super().__init__()
        self.connection_class = connection_class

    def http_open(self, req):
        return self.do_open(self.connection_class, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connection_class):
        super().__init__(context=ssl.create_default_context())
        self.connection_class = connection_class

    def https_open(self, req):
        return self.do_open(self.connection_class, req)


def _opener(url: str):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"refused scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid URL port")
    address = _public_address(parsed.hostname, port)
    connection = _pinned_connection(address, parsed.scheme == "https")
    handler = (_PinnedHTTPSHandler(connection) if parsed.scheme == "https"
               else _PinnedHTTPHandler(connection))
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), handler)


def fetch(url: str, timeout: float = REQUEST_TIMEOUT) -> Fetched:
    """Retrieve one public URL without following redirects or executing bytes."""
    result = Fetched(url)
    try:
        opener = _opener(url)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
            result.status = getattr(response, "status", 200) or 200
    except urllib.error.HTTPError as exc:
        result.status = exc.code
        result.note = f"{exc.reason} (redirects and non-success responses are not followed)"
        exc.close()
        return result
    except (urllib.error.URLError, OSError, ValueError, PermissionError) as exc:
        result.note = f"{type(exc).__name__}: {exc}"
        return result
    if len(body) > MAX_BYTES:
        result.note = f"larger than the {MAX_BYTES:,} B cap - refused"
        return result
    result.body = body
    result.ok = 200 <= result.status < 300 and bool(body)
    result.note = "" if result.ok else "empty or unsuccessful response"
    return result


def run(text: str, timeout: float = REQUEST_TIMEOUT) -> list[Fetched]:
    """Fetch indicator URLs (bounded). Callers must opt in first."""
    return [fetch(url, timeout) for url in urls(text)]


def summary(results: list[Fetched]) -> str:
    if not results:
        return "no indicators to fetch"
    ok = [item for item in results if item.ok]
    total = sum(len(item.body) for item in ok)
    return (f"{len(ok)}/{len(results)} indicator(s) fetched, {total:,} B "
            "handed back to the engine")
