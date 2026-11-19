import json
import subprocess

import pytest

import repo_scan as rs
from scanner import analyze_csp, calculate_security_score, coverage_info

# Kunci palsu dirakit saat pengujian berjalan agar tidak tertulis utuh di repositori.
STRIPE = "sk_" + "live_" + "Z9y8X7w6V5u4T3s2R1q0P9o8"


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
                   cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    d = tmp_path_factory.mktemp("proj")
    (d / "package.json").write_text(json.dumps({"dependencies": {
        "left-pad": "^1.3.0", "totally-made-up-pkg-xyz": "1.0.0", "@acme/internal": "1.0.0"}}))
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/jest": {"version": "29.0.0", "dev": True}}}))
    wf = d / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: someone/thing@v1\n      - run: echo \"${{ github.event.pull_request.title }}\"\n")
    (d / "Dockerfile").write_text("FROM node:20\nENV API_SECRET=abc123\nCOPY . .\nCMD [\"node\", \"index.js\"]\n")
    (d / ".env").write_text("SUPABASE_URL=x\n")
    (d / ".env.example").write_text("SUPABASE_URL=\n")
    (d / "app.ts").write_text("const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n")
    (d / "config.js").write_text(f'const stripe = "{STRIPE}";\n')
    git(d, "init", "-q")
    git(d, "add", "-A")
    git(d, "commit", "-q", "-m", "init")
    (d / "config.js").write_text("const stripe = process.env.STRIPE_KEY;\n")
    git(d, "rm", "-q", "--cached", ".env")
    (d / ".env").unlink()
    git(d, "add", "-A")
    git(d, "commit", "-q", "-m", "remove secret")
    return d


@pytest.fixture(scope="module")
def result(repo):
    mp = pytest.MonkeyPatch()
    mp.setattr(rs, "_osv_query", lambda pkgs: {("lodash", "4.17.15", "npm"): {
        "ids": ["GHSA-test-0001"], "severity": "HIGH", "summary": "Prototype pollution"}})
    mp.setattr(rs, "_registry_exists", lambda name, eco: name not in ("totally-made-up-pkg-xyz", "@acme/internal"))
    out = rs.run(str(repo), online=True)
    yield out
    mp.undo()


def test_secret_removed_from_code_is_still_found_in_history(result):
    assert not any(x["type"] == "Stripe secret key" for x in result["secrets"])
    hist = [x for x in result["history_secrets"] if x["type"] == "Stripe secret key"]
    assert hist and hist[0]["file"] == "config.js" and len(hist[0]["commit"]) == 8
    assert STRIPE not in hist[0]["masked"]


def test_env_file_in_history_but_example_ignored(result):
    assert result["env_files"] == []
    assert result["env_files_history"] == [".env"]


def test_dependencies_and_registry(result):
    assert result["deps"]["checked"] == 2  # jest (dev) tidak dihitung
    assert [x["name"] for x in result["deps"]["vulnerable"]] == ["lodash"]
    assert [x["name"] for x in result["missing_packages"]] == ["totally-made-up-pkg-xyz"]
    assert [x["name"] for x in result["scoped_missing"]] == ["@acme/internal"]


def test_workflow_docker_and_code_issues(result):
    ids = {x["id"] for x in result["workflows"]}
    assert {"CI-PRT-CHECKOUT", "CI-SCRIPT-INJECTION", "CI-UNPINNED-ACTION", "CI-BROAD-PERMISSIONS"} <= ids
    assert {x["id"] for x in result["docker"]} == {"DOCKER-ROOT", "DOCKER-SECRET-ENV"}
    assert [x["detail"] for x in result["code"] if x["id"] == "PUBLIC-ENV-SECRET"] == ["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"]


def test_repo_only_score(result):
    s = rs.score(result)
    ids = {f["id"] for f in s["findings"]}
    assert {"REPO-SECRET-HISTORY", "REPO-ENV-HISTORY", "DEP-VULN", "PKG-NOT-FOUND", "PUBLIC-ENV-SECRET", "CI-PRT-CHECKOUT"} <= ids
    assert s["grade"] == "F" and s["coverage"]["percent"] == 20
    assert all(f["finding"].startswith("Risiko ") for f in s["findings"])


def test_combined_report_includes_repo_findings(result):
    site = {
        "valid": True, "evidence": {"final_url": "https://example.com/"},
        "security_headers": {"tidak_ditemukan": {}, "hsts_max_age": 31536000},
        "ssl_info": {"valid": True, "sisa_hari": 90}, "caa_info": {"ada": True},
        "https_redirect_info": {"http_ke_https": True},
        "csp_quality": analyze_csp("default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"),
        "email_security": {"domain": "example.com", "spf": True, "dmarc": True, "dmarc_policy": "reject"},
        "coverage_modes": ["surface", "deep_web", "repo"], "repo": result,
    }
    s = calculate_security_score(site)
    assert "REPO-SECRET-HISTORY" in {f["id"] for f in s["findings"]}
    assert s["coverage"]["percent"] == 85 == coverage_info(("surface", "deep_web", "repo"))["percent"]


def test_offline_mode_skips_network(repo, monkeypatch):
    monkeypatch.setattr(rs, "_osv_query", lambda pkgs: pytest.fail("OSV must not be called offline"))
    monkeypatch.setattr(rs, "_registry_exists", lambda *a: pytest.fail("registry must not be called offline"))
    out = rs.run(str(repo), online=False)
    assert out["deps"]["vulnerable"] == [] and out["missing_packages"] == []
