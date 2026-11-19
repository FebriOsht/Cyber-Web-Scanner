"""Pemeriksaan DNS dan email lanjutan (bagian dari Mode Web mendalam).

Hanya membaca DNS publik (DNS-over-HTTPS) dan log Certificate Transparency. Tidak mengirim email,
tidak mendaftarkan atau mengklaim apa pun.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor

import requests

DOH = 'https://cloudflare-dns.com/dns-query'
TYPE_NUM = {'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28}
MAX_SUBDOMAINS = 40
BUDGET_SECONDS = 22
CT_TIMEOUT = 10
DKIM_SELECTORS = ('google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'default', 'mail', 'dkim', 'resend',
                  'zmail', 'smtp', 'mandrill', 'cf2024-1', 'hostingermail-a', 'protonmail', 'fm1')
# Layanan yang rawan diambil alih bila CNAME-nya menunjuk ke nama yang sudah tidak ada (NXDOMAIN).
DANGLING_NX = ('azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net',
               'azureedge.net', 'azure-api.net', 'azurestaticapps.net', 'elasticbeanstalk.com', 'herokudns.com',
               'herokuapp.com', 'github.io', 'netlify.app', 'surge.sh', 'bitbucket.io', 'ghost.io', 'myshopify.com',
               'pantheonsite.io', 'readthedocs.io', 'wpengine.com', 'fly.dev', 'onrender.com')
HOST_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')
UA = 'Mozilla/5.0 CyberWebScanner/2.0'


def doh(name, rtype, timeout=5):
    """Kembalikan (status DNS, daftar data). Status 3 berarti NXDOMAIN; 2 berarti gagal."""
    try:
        r = requests.get(DOH, params={'name': name, 'type': rtype}, headers={'accept': 'application/dns-json'}, timeout=timeout)
        data = r.json()
    except (requests.RequestException, ValueError):
        return 2, []
    want = TYPE_NUM.get(rtype)
    out = []
    for a in data.get('Answer', []) or []:
        if want and a.get('type') != want:
            continue
        val = re.sub(r'"\s+"', '', str(a.get('data', ''))).strip().strip('"')
        out.append(val)
    return data.get('Status', 2), out


def ct_subdomains(root, timeout=CT_TIMEOUT):
    """Subdomain dari log Certificate Transparency (crt.sh, cadangan Cert Spotter)."""
    names, source = set(), None
    try:
        r = requests.get('https://crt.sh/', params={'q': f'%.{root}', 'output': 'json'}, timeout=timeout, headers={'User-Agent': UA})
        if r.status_code == 200:
            for row in r.json()[:5000]:
                names.update(str(row.get('name_value', '')).split('\n'))
            source = 'crt.sh'
    except (requests.RequestException, ValueError):
        pass
    if not names:
        try:
            r = requests.get('https://api.certspotter.com/v1/issuances',
                             params={'domain': root, 'include_subdomains': 'true', 'expand': 'dns_names'}, timeout=timeout)
            if r.status_code == 200:
                for row in r.json():
                    names.update(row.get('dns_names', []))
                source = 'Cert Spotter'
        except (requests.RequestException, ValueError):
            pass
    clean = set()
    for n in names:
        n = n.strip().lower().rstrip('.')
        while n.startswith('*.'):
            n = n[2:]
        if n != root and n.endswith('.' + root) and HOST_RE.match(n):
            clean.add(n)
    return sorted(clean), source


def check_subdomain(fqdn, session, fingerprints):
    _, cnames = doh(fqdn, 'CNAME')
    if not cnames:
        return None
    target = cnames[0].rstrip('.').lower()
    entry = {'subdomain': fqdn, 'cname': target}
    status, _ = doh(target, 'A')
    if status == 3:
        svc = next((d for d in DANGLING_NX if target == d or target.endswith('.' + d)), None)
        entry.update(status='rentan' if svc else 'dangling', layanan=svc or target, confidence='medium',
                     bukti='CNAME menunjuk ke nama yang tidak ada (NXDOMAIN)')
        return entry
    host = next((h for h, _ in fingerprints if target.endswith(h)), None)
    if host and session is not None:
        try:
            r = session.get(f'https://{fqdn}', timeout=6, verify=False)
            body = (r.text or '')[:8000].lower()
            fp = next((p for h, p in fingerprints if h == host and p in body), None)
            if fp:
                entry.update(status='rentan', layanan=host, confidence='high', bukti=fp)
                return entry
        except requests.exceptions.RequestException:
            pass
    return None


LOOKUP_TERM = re.compile(r'^[+\-~?]?(?:include:|a$|a:|a/|mx$|mx:|mx/|ptr$|ptr:|exists:|redirect=)', re.I)
INCLUDE_TERM = re.compile(r'^[+\-~?]?(?:include:|redirect=)(\S+)', re.I)


def spf_lookups(record, depth=0, seen=None, limit=11):
    """Jumlah DNS lookup SPF secara rekursif (berhenti setelah melewati batas agar hemat)."""
    seen = set() if seen is None else seen
    count = 0
    for term in record.split()[1:]:
        if not LOOKUP_TERM.match(term):
            continue
        count += 1
        if count >= limit:
            return count
        m = INCLUDE_TERM.match(term)
        if m and depth < 10:
            dom = m.group(1).lower()
            if dom in seen:
                continue
            seen.add(dom)
            _, txt = doh(dom, 'TXT')
            sub = next((t for t in txt if t.lower().startswith('v=spf1')), None)
            if sub:
                count += spf_lookups(sub, depth + 1, seen, limit - count)
                if count >= limit:
                    return count
    return count


def _dmarc_tags(rec):
    tags = {}
    for part in rec.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_email(root):
    _, mx = doh(root, 'MX')
    has_mx = any(m.split()[-1].rstrip('.') not in ('', '.') for m in mx if m.split())
    _, txt = doh(root, 'TXT')
    spf = [t for t in txt if t.lower().startswith('v=spf1')]
    out = {'domain': root, 'has_mx': has_mx, 'spf_records': len(spf), 'spf': None, 'spf_all': None, 'spf_lookups': 0,
           'dmarc': False, 'dmarc_rua': False, 'dkim_checked': False, 'dkim_selectors': [], 'mta_sts': False, 'tls_rpt': False}
    if spf:
        rec = spf[0]
        out['spf'] = rec[:300]
        m = re.search(r'(?:^|\s)([+\-~?]?)all(?:\s|$)', rec, re.I)
        out['spf_all'] = (m.group(1) or '+') if m else None
        out['spf_lookups'] = spf_lookups(rec)
    _, dm = doh('_dmarc.' + root, 'TXT')
    dmarc = next((t for t in dm if t.lower().startswith('v=dmarc1')), None)
    if dmarc:
        out['dmarc'] = True
        out['dmarc_rua'] = bool(_dmarc_tags(dmarc).get('rua'))
    sends = bool(spf) and bool(re.search(r'(?:^|\s)[+?~]?(?:include:|ip4:|ip6:|a\b|mx\b)', spf[0], re.I))
    if sends:
        out['dkim_checked'] = True
        with ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(lambda sel: (sel, doh(f'{sel}._domainkey.{root}', 'TXT')[1] or doh(f'{sel}._domainkey.{root}', 'CNAME')[1]), DKIM_SELECTORS))
        out['dkim_selectors'] = [sel for sel, ans in results if any(('p=' in a) or a.endswith('.') or '.' in a for a in ans)]
    if has_mx:
        _, sts = doh('_mta-sts.' + root, 'TXT')
        out['mta_sts'] = any(t.lower().startswith('v=stsv1') for t in sts)
        _, rpt = doh('_smtp._tls.' + root, 'TXT')
        out['tls_rpt'] = any('v=tlsrptv1' in t.lower() for t in rpt)
    return out


def run(session, root, fingerprints, budget=BUDGET_SECONDS):
    t0 = time.monotonic()
    out = {'domain': root, 'ct_source': None, 'ct_total': 0, 'checked': 0, 'takeover': [], 'dangling': [],
           'email': {}, 'partial': False}
    ex = ThreadPoolExecutor(max_workers=8)
    try:
        email_f = ex.submit(analyze_email, root)
        subs, source = ct_subdomains(root, timeout=min(CT_TIMEOUT, budget))
        out['ct_source'], out['ct_total'] = source, len(subs)
        futures = [ex.submit(check_subdomain, sd, session, fingerprints) for sd in subs[:MAX_SUBDOMAINS]]
        if len(subs) > MAX_SUBDOMAINS:
            out['partial'] = True
        for f in futures:
            left = budget - (time.monotonic() - t0)
            if left <= 0:
                out['partial'] = True
                break
            try:
                entry = f.result(timeout=left)
            except Exception:
                continue
            out['checked'] += 1
            if entry:
                (out['takeover'] if entry['status'] == 'rentan' else out['dangling']).append(entry)
        try:
            out['email'] = email_f.result(timeout=max(1, budget - (time.monotonic() - t0)))
        except Exception as e:
            out['email'] = {'error': f'{e.__class__.__name__}'}
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return out
