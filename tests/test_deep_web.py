import base64
import http.server
import json
import threading

import pytest
from bs4 import BeautifulSoup

import deep_web as dw
import ssrf_guard as g
from scanner import _new_session


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


# Kunci palsu dirakit saat pengujian berjalan agar tidak tertulis utuh di repositori.
STRIPE = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
HEADER = _b64({"alg": "HS256", "typ": "JWT"})
SERVICE_JWT = HEADER + "." + _b64({"role": "service_role", "iss": "supabase"}) + "." + "s" * 24
ANON_JWT = HEADER + "." + _b64({"role": "anon", "iss": "supabase"}) + "." + "a" * 24

INDEX = ('<html><head><script src="/app.js"></script>'
         '<script src="https://cdn.example.org/lib.js"></script><script>var a = 1;</script></head><body>ok</body></html>')
FILES = {
    "/app.js": ("application/javascript",
                f'/*! jQuery v3.4.1 | (c) OpenJS */ var k="{STRIPE}"; var s="{SERVICE_JWT}"; var a="{ANON_JWT}";\n'
                "//# sourceMappingURL=app.js.map"),
    "/app.js.map": ("application/json", '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'),
    "/backup.zip": ("application/zip", b"PK\x03\x04" + b"\x00" * 64),
    "/phpinfo.php": ("text/html", "<html><title>PHP 8.1 - phpinfo()</title></html>"),
    "/openapi.json": ("application/json", '{"openapi": "3.0.0", "paths": {}}'),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, ctype, body, status=200):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Soft-404: semua jalur lain membalas beranda dengan status 200.
        self._send(*FILES.get(self.path.split("?")[0], ("text/html", INDEX)))

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/graphql":
            self._send("application/json", json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}))
        else:
            self._send("text/html", INDEX)


@pytest.fixture(scope="module")
def result():
    mp = pytest.MonkeyPatch()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    real = g.is_public_ip
    mp.setattr(g, "is_public_ip", lambda ip: ip == "127.0.0.1" or real(ip))
    mp.setattr(g, "ALLOWED_PORTS", (None, 80, 443, port))
    base = f"http://127.0.0.1:{port}"
    session = _new_session()
    resp = session.get(base + "/", timeout=5)
    out = dw.run(session, base, resp, BeautifulSoup(resp.text, "html.parser"), verify=False, budget=30)
    yield out
    srv.shutdown()
    mp.undo()


def test_secrets_found_and_masked(result):
    types = {x["type"] for x in result["secrets"]}
    assert "Stripe secret key" in types
    assert "Supabase service_role key" in types
    assert all(STRIPE not in x["masked"] and SERVICE_JWT not in x["masked"] for x in result["secrets"])
    assert len([x for x in result["secrets"] if x["type"] == "Supabase service_role key"]) == 1  # anon tidak dilaporkan


def test_sourcemap_and_library(result):
    assert result["sourcemaps"] == ["/app.js.map"]
    assert [(x["name"], x["version"]) for x in result["libraries"]] == [("jQuery", "3.4.1")]
    assert result["js_checked"] == 1 and result["js_total"] == 1


def test_files_are_validated_by_content_not_status(result):
    assert [x["path"] for x in result["backups"]] == ["/backup.zip"]
    assert result["config_files"] == []
    assert [x["path"] for x in result["ops"]] == ["/phpinfo.php"]
    assert [x["path"] for x in result["api_docs"]] == ["/openapi.json"]
    assert result["debug"] == []


def test_graphql_and_sri(result):
    assert [x["path"] for x in result["graphql"]] == ["/graphql"]
    assert result["sri_missing"] == ["cdn.example.org"]


def test_debug_marker_detection():
    assert dw._debug_kind(b"<pre>Traceback (most recent call last):\n  File ...", "text/html")
    assert dw._debug_kind(b"<h1>Not found</h1>", "text/html") is None


def test_safe_library_versions_are_not_flagged():
    assert dw.find_libraries("/*! jQuery v3.7.1 | (c) OpenJS */") == []
    assert dw.find_libraries("Bootstrap v5.3.3 (https://getbootstrap.com/)") == []


def test_google_key_is_low_severity():
    found = dw.find_secrets('var k="AIza' + "B" * 35 + '";', "x.js")
    assert found and found[0]["severity"] == "low"
