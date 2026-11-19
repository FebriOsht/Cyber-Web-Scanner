import pytest

import dns_email as de

FINGERPRINTS = (("github.io", "there isn't a github pages site here"),)


@pytest.fixture
def fake_dns(monkeypatch):
    table = {}

    def doh(name, rtype, timeout=5):
        return table.get((name.lower(), rtype), (0, []))

    monkeypatch.setattr(de, "doh", doh)
    return table


def test_spf_lookup_count_is_recursive(fake_dns):
    fake_dns[("example.com", "TXT")] = (0, ["v=spf1 include:a.example include:b.example -all"])
    fake_dns[("a.example", "TXT")] = (0, ["v=spf1 " + " ".join(f"include:a{i}.example" for i in range(6)) + " ~all"])
    fake_dns[("b.example", "TXT")] = (0, ["v=spf1 a mx include:c.example ~all"])
    fake_dns[("example.com", "MX")] = (0, ["10 mx.example.com."])
    m = de.analyze_email("example.com")
    assert m["spf_lookups"] > 10
    assert m["spf_all"] == "-"


def test_plus_all_dmarc_and_mta_sts(fake_dns):
    fake_dns[("example.com", "TXT")] = (0, ["v=spf1 include:_spf.google.com +all"])
    fake_dns[("example.com", "MX")] = (0, ["1 aspmx.l.google.com."])
    fake_dns[("_dmarc.example.com", "TXT")] = (0, ["v=DMARC1; p=quarantine"])
    fake_dns[("google._domainkey.example.com", "TXT")] = (0, ["v=DKIM1; k=rsa; p=MIIBIjAN"])
    m = de.analyze_email("example.com")
    assert m["spf_all"] == "+"
    assert m["dmarc"] and not m["dmarc_rua"]
    assert m["dkim_selectors"] == ["google"]
    assert m["has_mx"] and not m["mta_sts"]


def test_non_sending_domain_skips_dkim(fake_dns):
    fake_dns[("oshtore.example", "TXT")] = (0, ["v=spf1 -all"])
    m = de.analyze_email("oshtore.example")
    assert not m["has_mx"] and not m["dkim_checked"] and m["spf_all"] == "-"


def test_azure_cname_to_nxdomain_is_takeover(fake_dns):
    fake_dns[("old.example.com", "CNAME")] = (0, ["old-app.azurewebsites.net."])
    fake_dns[("old-app.azurewebsites.net", "A")] = (3, [])
    e = de.check_subdomain("old.example.com", None, FINGERPRINTS)
    assert e["status"] == "rentan" and e["layanan"] == "azurewebsites.net"


def test_unknown_cname_to_nxdomain_is_only_flagged_for_review(fake_dns):
    fake_dns[("legacy.example.com", "CNAME")] = (0, ["gone.another-company.net."])
    fake_dns[("gone.another-company.net", "A")] = (3, [])
    e = de.check_subdomain("legacy.example.com", None, FINGERPRINTS)
    assert e["status"] == "dangling"


def test_normal_subdomains_are_ignored(fake_dns):
    fake_dns[("www.example.com", "CNAME")] = (0, ["cname.vercel-dns.com."])
    fake_dns[("cname.vercel-dns.com", "A")] = (0, ["76.76.21.21"])
    assert de.check_subdomain("www.example.com", None, FINGERPRINTS) is None
    assert de.check_subdomain("api.example.com", None, FINGERPRINTS) is None


def test_run_combines_ct_subdomains_and_email(fake_dns, monkeypatch):
    monkeypatch.setattr(de, "ct_subdomains", lambda root, timeout=10: (["old.example.com", "www.example.com"], "test"))
    fake_dns[("old.example.com", "CNAME")] = (0, ["old-app.azurewebsites.net."])
    fake_dns[("old-app.azurewebsites.net", "A")] = (3, [])
    out = de.run(None, "example.com", FINGERPRINTS, budget=10)
    assert out["ct_source"] == "test" and out["checked"] == 2
    assert [x["subdomain"] for x in out["takeover"]] == ["old.example.com"]
    assert out["email"]["domain"] == "example.com"
