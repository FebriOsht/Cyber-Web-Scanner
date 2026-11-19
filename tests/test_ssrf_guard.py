import http.server
import threading

import pytest

import ssrf_guard as g
from scanner import _new_session, run_full_scan


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1",
])
def test_internal_ips_are_not_public(ip):
    assert not g.is_public_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_are_public(ip):
    assert g.is_public_ip(ip)


@pytest.mark.parametrize("url", [
    "ftp://example.com/", "file:///etc/passwd", "http://localhost/", "http://127.0.0.1/",
    "http://[::1]/", "http://metadata.internal/", "http://example.com:22/", "http://user:pw@example.com/",
])
def test_check_url_blocks_dangerous_urls(url):
    with pytest.raises(g.BlockedTarget):
        g.check_url(url)


def test_domain_resolving_to_private_ip_is_blocked(monkeypatch):
    monkeypatch.setattr(g.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with pytest.raises(g.BlockedTarget):
        g.resolve_public("evil.example")


def test_mixed_public_and_private_answers_are_blocked(monkeypatch):
    answers = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(g.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(g.BlockedTarget):
        g.resolve_public("rebind.example")


def test_scan_refuses_internal_target():
    r = run_full_scan("http://127.0.0.1/")
    assert r["valid"] is False
    assert "ditolak" in r["invalid_reason"]
    assert r["score_info"]["grade"] == "N/A"


def test_session_blocks_metadata_endpoint():
    with pytest.raises(g.BlockedTarget):
        _new_session().get("http://169.254.169.254/latest/meta-data/", timeout=2)


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


def _allow_local_test_server(monkeypatch, port):
    real = g.is_public_ip
    monkeypatch.setattr(g, "is_public_ip", lambda ip: ip == "127.0.0.1" or real(ip))
    monkeypatch.setattr(g, "ALLOWED_PORTS", (None, 80, 443, port))


def test_redirect_to_internal_address_is_blocked(monkeypatch):
    class Redirect(_Quiet):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

    srv, port = _serve(Redirect)
    try:
        _allow_local_test_server(monkeypatch, port)
        with pytest.raises(g.BlockedTarget):
            _new_session().get(f"http://127.0.0.1:{port}/", timeout=5)
    finally:
        srv.shutdown()


def test_response_size_limit(monkeypatch):
    class Big(_Quiet):
        def do_GET(self):
            body = b"x" * 5000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, port = _serve(Big)
    try:
        _allow_local_test_server(monkeypatch, port)
        monkeypatch.setattr(g, "MAX_BYTES", 1000)
        with pytest.raises(g.ResponseTooLarge):
            _new_session().get(f"http://127.0.0.1:{port}/", timeout=5)
    finally:
        srv.shutdown()
