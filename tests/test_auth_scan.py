import base64
import http.server
import json
import threading

import pytest

import auth_scan as a
import ssrf_guard as g


class App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/.well-known/cws-verify-"):
            token = self.path.rsplit("cws-verify-", 1)[-1].replace(".txt", "")
            return self._send(200, token, "text/plain")
        if self.path.startswith("/api/orders/"):
            return self._send(200, json.dumps({"id": self.path.rsplit("/", 1)[-1], "total": 999, "secret": "x" * 300}))
        self._send(404, "{}")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send(401, json.dumps({"error": "invalid"}))


@pytest.fixture
def server(monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    real = g.is_public_ip
    monkeypatch.setattr(g, "is_public_ip", lambda ip: ip == "127.0.0.1" or real(ip))
    monkeypatch.setattr(g, "ALLOWED_PORTS", (None, 80, 443, port))
    yield f"http://127.0.0.1:{port}", port
    srv.shutdown()


def test_ownership_file_can_be_read(server):
    base, port = server
    token, _how = a.verify_ownership(f"127.0.0.1:{port}")
    r = a._session(False).get(f"{base}/.well-known/cws-verify-{token}.txt", timeout=5)
    assert token in r.text


def test_idor_and_rate_limit_detected(server):
    base, _ = server
    cfg = a.AuthConfig({
        "accounts": [{"name": "A", "cookies": {"session": "a"}}, {"name": "B", "cookies": {"session": "b"}}],
        "object_urls": [{"as": "A", "url": f"{base}/api/orders/1", "owned_by_other": f"{base}/api/orders/2"}],
        "login": {"url": f"{base}/api/login", "json": {"email": "x", "password": "y"}},
    })
    out = a.run(cfg, verify=False)
    assert out["idor"] and out["idor"][0]["as"] == "A"
    assert out["rate_limit"]["attempts"] == 8 and not out["rate_limit"]["limited"]
    assert {"AUTH-IDOR", "AUTH-NO-RATE-LIMIT"} <= {f[0] for f in a.findings(out)}


def test_weak_jwt_alg_none_is_flagged():
    head = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    cfg = a.AuthConfig({"accounts": [{"name": "A", "cookies": {"session": head + ".e30.x"}}]})
    assert a.check_session_tokens(cfg, False)[0]["account"] == "A"


def test_no_requests_without_object_urls(server):
    cfg = a.AuthConfig({"accounts": [{"name": "A", "cookies": {"session": "a"}}]})
    out = a.run(cfg, verify=False)
    assert out["idor"] == [] and out["rate_limit"] is None