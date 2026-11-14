from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pydecomp import fetch as fetch_mod


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/private")
            self.end_headers()
            return
        body = b"static payload bytes"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_fetch_pins_connection_and_returns_bytes(monkeypatch, local_server):
    monkeypatch.setattr(fetch_mod, "_public_address", lambda _host, _port: "127.0.0.1")
    result = fetch_mod.fetch(f"http://example.invalid:{local_server}/payload")
    assert result.ok
    assert result.status == 200
    assert result.body == b"static payload bytes"


def test_fetch_does_not_follow_redirects(monkeypatch, local_server):
    monkeypatch.setattr(fetch_mod, "_public_address", lambda _host, _port: "127.0.0.1")
    result = fetch_mod.fetch(f"http://example.invalid:{local_server}/redirect")
    assert not result.ok
    assert result.status == 302
    assert "not followed" in result.note


def test_fetch_refuses_private_dns_results(monkeypatch):
    monkeypatch.setattr(fetch_mod.socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ])
    monkeypatch.setattr(fetch_mod.socket, "create_connection",
                        lambda *_args, **_kwargs: pytest.fail("must refuse before connect"))
    result = fetch_mod.fetch("http://example.invalid/payload")
    assert not result.ok
    assert "non-public address" in result.note


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://user:password@example.com/",
    "http://example.com:99999/",
])
def test_fetch_refuses_unsafe_url_forms(url):
    result = fetch_mod.fetch(url)
    assert not result.ok
    assert result.note


def test_fetch_refuses_oversized_response(monkeypatch, local_server):
    monkeypatch.setattr(fetch_mod, "_public_address", lambda _host, _port: "127.0.0.1")
    monkeypatch.setattr(fetch_mod, "MAX_BYTES", 4)
    result = fetch_mod.fetch(f"http://example.invalid:{local_server}/payload")
    assert not result.ok
    assert result.body == b""
    assert "cap" in result.note
