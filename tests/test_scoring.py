from scanner import analyze_csp, calculate_security_score, grade_from

GOOD_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
REQUIRED = {"id", "finding", "recommendation", "level", "severity", "points", "category", "track", "confidence"}


def clean_site(**over):
    r = {
        "valid": True,
        "evidence": {"final_url": "https://example.com/"},
        "security_headers": {"tidak_ditemukan": {}, "hsts_max_age": 31536000},
        "ssl_info": {"valid": True, "sisa_hari": 90},
        "tls_old_info": {"tls_lama_diterima": False},
        "caa_info": {"ada": True},
        "https_redirect_info": {"http_ke_https": True},
        "csp_quality": analyze_csp(GOOD_CSP),
        "email_security": {"domain": "example.com", "spf": True, "dmarc": True, "dmarc_policy": "reject"},
    }
    r.update(over)
    return r


def test_clean_site_scores_100_with_coverage():
    s = calculate_security_score(clean_site())
    assert s["score"] == 100 and s["grade"] == "A" and not s["grade_capped"]
    assert s["coverage"]["percent"] == 40 and "Permukaan" in s["coverage"]["label"]
    assert s["subscores"]["code"] is None


def test_one_critical_caps_grade_at_d():
    s = calculate_security_score(clean_site(sensitive_files={"terekspos": [{"path": "/.env"}]}))
    assert s["grade"] == "D"


def test_two_criticals_give_f():
    assert grade_from(95, 2) == "F"
    s = calculate_security_score(clean_site(
        sensitive_files={"terekspos": [{"path": "/.env"}]},
        exposed_git_info={"ditemukan": True},
    ))
    assert s["grade"] == "F"


def test_one_critical_caps_even_a_high_score():
    assert grade_from(95, 1) == "D" and grade_from(95, 0) == "A"


def test_csp_without_script_restriction_is_flagged():
    csp = analyze_csp("frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
    assert csp["tanpa_pembatas_skrip"]
    s = calculate_security_score(clean_site(csp_quality=csp))
    ids = [f["id"] for f in s["findings"]]
    assert "CSP-NO-SCRIPT-RESTRICTION" in ids and s["score"] == 90


def test_findings_have_all_structured_fields():
    s = calculate_security_score(clean_site(
        security_headers={"tidak_ditemukan": {"X-Content-Type-Options": "x"}, "hsts_max_age": 31536000},
        cookie_info={"bermasalah": [{"cookie": "sid", "tidak_ada": ["Secure"]}]},
    ))
    for f in s["findings"]:
        assert REQUIRED <= f.keys()
        assert f["finding"].startswith("Risiko ")  # format lama tetap dipakai tampilan web


def test_invalid_scan_is_not_graded():
    s = calculate_security_score({"valid": False, "invalid_reason": "x"})
    assert s["grade"] == "N/A" and s["coverage"]["percent"] == 40


def test_deep_web_findings_raise_coverage_and_cap_grade():
    s = calculate_security_score(clean_site(
        coverage_modes=["surface", "deep_web"],
        deep_web={"secrets": [{"type": "Stripe secret key", "masked": "sk_liv…K1l2", "file": "/app.js", "severity": "critical"}],
                  "backups": [{"path": "/backup.zip", "kind": "Arsip ZIP"}], "sourcemaps": ["/app.js.map"]},
    ))
    ids = {f["id"] for f in s["findings"]}
    assert {"JS-SECRET", "BACKUP-EXPOSED", "SOURCEMAP-EXPOSED"} <= ids
    assert s["grade"] == "F" and s["coverage"]["percent"] == 65
    assert s["subscores"]["code"] is not None


def test_dns_email_findings():
    s = calculate_security_score(clean_site(dns_email={
        "takeover": [{"subdomain": "old.example.com", "cname": "x.azurewebsites.net", "layanan": "azurewebsites.net",
                      "bukti": "NXDOMAIN", "confidence": "medium"}],
        "email": {"domain": "example.com", "has_mx": True, "spf_records": 1, "spf": "v=spf1 ~all", "spf_all": "~",
                  "spf_lookups": 12, "dmarc": True, "dmarc_rua": False, "dkim_checked": True, "dkim_selectors": [], "mta_sts": False},
    }))
    ids = {f["id"] for f in s["findings"]}
    assert {"SUBDOMAIN-TAKEOVER-CT", "SPF-TOO-MANY-LOOKUPS", "DMARC-NO-RUA", "DKIM-NOT-FOUND", "MTA-STS-MISSING"} <= ids
    assert s["score"] == 48 and s["grade"] == "F"  # 100 - 40 - 5 - 2 - 2 - 3
