import subprocess
import sys
from pathlib import Path

from app import app
from flask import render_template
from scanner import analyze_csp, calculate_security_score

ROOT = Path(__file__).resolve().parents[1]


def sample_results():
    r = {
        "target": "https://example.com", "valid": True, "scanned_at": "2026-11-19 10:00:00 UTC",
        "evidence": {"final_url": "https://example.com/", "status_code": 200, "headers": {"server": "x"}},
        "security_headers": {"tidak_ditemukan": {"Referrer-Policy": "x"}, "ditemukan": {}, "hsts_max_age": 31536000},
        "ssl_info": {"valid": True, "sisa_hari": 90, "issuer": "X", "tls_version": "TLSv1.3", "berlaku_sampai": "2027-01-01"},
        "csp_quality": analyze_csp("frame-ancestors 'none'"), "coverage_modes": ["surface", "deep_web"],
        "deep_web": {"js_checked": 1, "js_total": 1, "secrets": [], "backups": [], "config_files": [], "ops": [], "debug": [],
                     "sourcemaps": [], "libraries": [], "api_docs": [], "graphql": [], "sri_missing": []},
    }
    r["score_info"] = calculate_security_score(r)
    return r


def test_result_page_has_v2_reporting_sections():
    with app.test_request_context():
        html = render_template("scan_result.html", results=sample_results())
    for needle in ("Skor per Kategori", "Lembar Telaah Manual", 'data-view="senior"', "col-senior", "copy-btn",
                   "Cakupan", "Web Mendalam", "Kode dan dependensi"):
        assert needle in html, needle


def test_cli_checklist_prints_markdown():
    out = subprocess.run([sys.executable, "cli.py", "--checklist"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert out.returncode == 0
    assert "# Lembar telaah manual" in out.stdout and "- [ ]" in out.stdout


def test_invalid_result_page_renders():
    """Hasil N/A (mis. target ditolak SSRF) harus tetap bisa dirender, termasuk meta|tojson."""
    from scanner import calculate_security_score
    r = {"target": "http://localtest.me", "valid": False,
         "invalid_reason": "Alamat localtest.me mengarah ke jaringan privat atau internal (127.0.0.1); pemindaian ditolak."}
    r["score_info"] = calculate_security_score(r)
    with app.test_request_context():
        html = render_template("scan_result.html", results=r)
    assert "N/A" in html and "ditolak" in html
