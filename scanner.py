# scanner.py - Cyber Web Scanner v2
# Prinsip: setiap temuan berasal dari respons HTTP live dan disertai bukti.
import re
import ssl
import sys
import json
import time
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/130.0 Safari/537.36 CyberWebScanner/2.0')

HEADER_INFO = {
    'Content-Security-Policy': 'Penting untuk mencegah serangan XSS.',
    'Strict-Transport-Security': 'Memaksa koneksi HTTPS.',
    'X-Content-Type-Options': 'Mencegah MIME-sniffing.',
    'X-Frame-Options': 'Mencegah clickjacking.',
    'Referrer-Policy': 'Membatasi kebocoran URL ke situs lain.',
}
LINK_RELS = {'stylesheet', 'icon', 'shortcut', 'preload', 'modulepreload', 'manifest', 'apple-touch-icon'}
MODULE_KEYS = ('security_headers', 'technology_info', 'robots_txt_info', 'exposed_git_info',
               'mixed_content_info', 'cookie_info', 'https_redirect_info', 'ssl_info',
               'sensitive_files', 'csp_quality', 'cors_info', 'email_security')


def _new_session():
    s = requests.Session()
    s.headers.update({
        'User-Agent': UA,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'id,en;q=0.8',
    })
    return s


def _err(e):
    return f'{e.__class__.__name__}: {str(e)[:200]}'


# --- Ambil halaman utama SATU kali, dipakai semua modul ---
FALLBACK_UAS = [UA, 'CyberWebScanner/2.0']


def fetch_main(session, url):
    """Ambil halaman utama SATU kali. Beberapa WAF menggantung koneksi dari IP data center
    untuk User-Agent tertentu, jadi bila timeout dicoba lagi dengan User-Agent cadangan."""
    last = None
    for ua in FALLBACK_UAS:
        session.headers['User-Agent'] = ua
        t0 = time.perf_counter()
        ssl_error = None
        try:
            try:
                r = session.get(url, timeout=(5, 12), verify=True)
            except requests.exceptions.SSLError as e:
                ssl_error = _err(e)
                r = session.get(url, timeout=(5, 12), verify=False)
        except requests.exceptions.Timeout as e:
            last = e
            continue
        r.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        r.ua_used = ua
        return r, ssl_error
    raise last

def detect_block(resp):
    if resp.headers.get('cf-mitigated', '').lower() == 'challenge':
        return 'Diblokir tantangan bot Cloudflare'
    if resp.status_code in (403, 429, 503):
        body = resp.text[:6000].lower()
        markers = ('just a moment', 'cf-chl', 'attention required', 'captcha', 'access denied', 'request blocked')
        if any(m in body for m in markers):
            return f'Diblokir WAF/proteksi bot (HTTP {resp.status_code})'
    return None


# --- MODUL 1: HEADER KEAMANAN ---
def check_security_headers(resp):
    h = resp.headers  # CaseInsensitiveDict: tidak peka huruf besar/kecil
    is_https = resp.url.startswith('https://')
    found, missing, notes = {}, {}, []
    csp = h.get('Content-Security-Policy', '')
    for name, desc in HEADER_INFO.items():
        val = h.get(name)
        if val:
            found[name] = val
        elif name == 'X-Frame-Options' and 'frame-ancestors' in csp.lower():
            found[name] = '(digantikan oleh CSP frame-ancestors)'
        elif name == 'Strict-Transport-Security' and not is_https:
            missing[name] = desc + ' (situs tidak dilayani lewat HTTPS)'
        else:
            missing[name] = desc
    if 'Content-Security-Policy' in missing and h.get('Content-Security-Policy-Report-Only'):
        notes.append('CSP hanya mode Report-Only (memantau, tidak memblokir).')
    age = None
    if found.get('Strict-Transport-Security'):
        m = re.search(r'max-age\s*=\s*"?(\d+)', found['Strict-Transport-Security'], re.I)
        age = int(m.group(1)) if m else 0
    return {'ditemukan': found, 'tidak_ditemukan': missing, 'catatan': notes, 'hsts_max_age': age}


# --- MODUL 2: INFORMASI TEKNOLOGI ---
def find_tech_info(resp, soup):
    h = resp.headers
    info = {}
    for key, label in (('Server', 'Server'), ('X-Powered-By', 'Powered-By'),
                       ('X-AspNet-Version', 'ASP.NET'), ('X-Generator', 'Generator')):
        if h.get(key):
            info[label] = h[key]
    if 'cf-ray' in h:
        info['CDN/WAF'] = 'Cloudflare'
    gen = soup.find('meta', attrs={'name': re.compile(r'^generator$', re.I)})
    if gen and gen.get('content'):
        info['Generator (CMS)'] = gen['content']
    return info


# --- MODUL 3: ROBOTS.TXT (di akar domain, isi divalidasi) ---
def check_robots_txt(session, base, verify):
    url = base + '/robots.txt'
    try:
        r = session.get(url, timeout=TIMEOUT, verify=verify)
    except requests.exceptions.RequestException as e:
        return {'ditemukan': False, 'url': url, 'status_code': None, 'error': _err(e)}
    ctype = r.headers.get('Content-Type', '').lower()
    text = r.text if r.status_code == 200 else ''
    valid = (r.status_code == 200 and 'html' not in ctype and not text.lstrip().startswith('<')
             and re.search(r'^\s*(user-agent|disallow|allow|sitemap)\s*:', text, re.I | re.M))
    if valid:
        lines = [l.strip() for l in text.splitlines()]
        return {
            'ditemukan': True, 'url': r.url, 'status_code': r.status_code,
            'paths': [l for l in lines if re.match(r'(dis)?allow\s*:', l, re.I)],
            'sitemaps': [l.split(':', 1)[1].strip() for l in lines if l.lower().startswith('sitemap:')],
            'isi': text[:3000],
        }
    note = None
    if r.status_code == 200:
        note = 'Server membalas 200 tetapi isinya bukan robots.txt (halaman catch-all).'
    return {'ditemukan': False, 'url': r.url, 'status_code': r.status_code, 'catatan': note}


# --- MODUL 4: DIREKTORI .GIT (isi file wajib terverifikasi) ---
def check_exposed_git(session, base, verify):
    detail = {}
    checks = (('/.git/HEAD', r'^(ref:\s*refs/|[0-9a-f]{40}\s*$)'), ('/.git/config', r'^\s*\[core\]'))
    for path, pattern in checks:
        url = base + path
        try:
            r = session.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            detail[path] = {'error': _err(e)}
            continue
        body = r.text[:500].strip() if r.status_code == 200 else ''
        ok = bool(body) and bool(re.search(pattern, body, re.I | re.M)) and not body.startswith('<')
        detail[path] = {'status_code': r.status_code, 'terverifikasi': ok}
        if ok:
            return {'ditemukan': True, 'status_code': 200, 'level_risiko': 'Kritis',
                    'url': url, 'bukti': body[:200], 'detail': detail}
    return {'ditemukan': False, 'status_code': detail.get('/.git/HEAD', {}).get('status_code'), 'detail': detail}


# --- MODUL 5: MIXED CONTENT (HTML halaman awal) ---
def check_mixed_content(resp, soup):
    scope = 'Hanya HTML halaman awal (konten dari JavaScript tidak dicek)'
    if not resp.url.startswith('https://'):
        return {'ditemukan': False, 'status': 'Bukan situs HTTPS', 'cakupan': scope}
    found = []
    for tag in soup.find_all(['img', 'script', 'iframe', 'audio', 'video', 'source', 'embed', 'object', 'link', 'form']):
        if tag.name == 'link':
            rels = {x.lower() for x in (tag.get('rel') or [])}
            if not rels & LINK_RELS:
                continue
            u = tag.get('href')
        elif tag.name == 'form':
            u = tag.get('action')
        elif tag.name == 'object':
            u = tag.get('data')
        else:
            u = tag.get('src')
        if u and u.strip().lower().startswith('http://'):
            found.append(f'<{tag.name}> {u.strip()}')
    found = list(dict.fromkeys(found))
    res = {'ditemukan': bool(found), 'cakupan': scope}
    if found:
        res.update(urls=found[:50], level_risiko='Menengah')
    return res


# --- MODUL 6: COOKIE ---
def check_cookies(resp):
    try:
        raw = resp.raw.headers.getlist('Set-Cookie')
    except Exception:
        raw = []
    bad = []
    for c in raw:
        low = c.lower()
        miss = [flag for flag, key in (('Secure', 'secure'), ('HttpOnly', 'httponly'), ('SameSite', 'samesite'))
                if not re.search(r';\s*' + key, low)]
        if miss:
            bad.append({'cookie': c.split('=', 1)[0].strip(), 'tidak_ada': miss})
    return {'jumlah': len(raw), 'bermasalah': bad}


# --- MODUL 7: SERTIFIKAT SSL ---
def check_ssl(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                tls = s.version()
        exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', '-')
        return {'valid': True, 'issuer': issuer, 'berlaku_sampai': exp.strftime('%Y-%m-%d'),
                'sisa_hari': (exp - datetime.now(timezone.utc)).days, 'tls_version': tls}
    except ssl.SSLCertVerificationError as e:
        return {'valid': False, 'error': getattr(e, 'verify_message', None) or str(e)[:200]}
    except (OSError, ValueError) as e:
        return {'valid': None, 'error': 'Tidak dapat memeriksa: ' + _err(e)}


# --- MODUL 8: REDIRECT HTTP KE HTTPS ---
def check_https_redirect(session, host):
    try:
        r = session.get(f'http://{host}/', timeout=TIMEOUT, verify=False)
        return {'http_ke_https': r.url.startswith('https://'), 'url_akhir': r.url}
    except requests.exceptions.RequestException as e:
        return {'http_ke_https': None, 'error': _err(e)}


# --- MODUL 9: FILE SENSITIF LAIN (isi divalidasi) ---
SENSITIVE_FILES = {
    '/.env': r'^[A-Z0-9_]+\s*=',
    '/.DS_Store': r'^\x00\x00\x00\x01Bud1',
    '/config.json': r'[:{]',
    '/.well-known/security.txt': r'(?i)contact\s*:',
}

def check_sensitive_files(session, base, verify):
    hits, checked = [], {}
    for path, pattern in SENSITIVE_FILES.items():
        url = base + path
        try:
            r = session.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            checked[path] = _err(e); continue
        body = r.text[:800] if r.status_code == 200 else ''
        ok = (r.status_code == 200 and not body.lstrip().lower().startswith('<!doctype')
              and not body.lstrip().startswith('<') and bool(re.search(pattern, body, re.M)))
        checked[path] = f'HTTP {r.status_code}' + (' (cocok)' if ok else '')
        if ok:
            info = 'security.txt (praktik baik, bukan risiko)' if path == '/.well-known/security.txt' else None
            hits.append({'path': path, 'url': url, 'bukti': body[:120].strip(), 'catatan': info})
    return {'terekspos': [h for h in hits if '/.well-known' not in h['path']],
            'security_txt': any('/.well-known' in h['path'] for h in hits),
            'diperiksa': checked}


# --- MODUL 10: KUALITAS CSP ---
def analyze_csp(csp):
    if not csp:
        return {'ada': False}
    low = csp.lower()
    weak = []
    if 'unsafe-inline' in low: weak.append("'unsafe-inline' (mengizinkan skrip/style inline)")
    if 'unsafe-eval' in low: weak.append("'unsafe-eval' (mengizinkan eval)")
    if re.search(r'(default|script)-src[^;]*\*', low): weak.append('wildcard * pada sumber skrip')
    return {'ada': True, 'kelemahan': weak}


# --- MODUL 11: SALAH KONFIGURASI CORS ---
def check_cors(session, url, verify):
    probe = 'https://evil.example.com'
    try:
        r = session.get(url, timeout=TIMEOUT, verify=verify, headers={'Origin': probe})
    except requests.exceptions.RequestException as e:
        return {'rentan': None, 'error': _err(e)}
    acao = r.headers.get('Access-Control-Allow-Origin', '')
    acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
    reflected = acao == probe
    return {'rentan': bool(reflected and acac == 'true'),
            'allow_origin': acao or '(tidak ada)',
            'refleksi_origin': reflected, 'allow_credentials': acac == 'true'}


# --- MODUL 12: SPF & DMARC (via DNS-over-HTTPS) ---
def _dns_txt(name):
    try:
        r = requests.get('https://cloudflare-dns.com/dns-query',
                         params={'name': name, 'type': 'TXT'},
                         headers={'accept': 'application/dns-json'}, timeout=TIMEOUT)
        return [a.get('data', '').strip('"') for a in r.json().get('Answer', [])]
    except Exception:
        return None

def check_email_security(host):
    parts = host.lower().strip('.').split('.')
    sld = {'co', 'ac', 'go', 'or', 'sch', 'web', 'my', 'biz', 'mil', 'net', 'com', 'org', 'edu', 'gov', 'ponpes', 'desa'}
    n = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in sld else 2
    root = '.'.join(parts[-n:])
    spf_rec = _dns_txt(root)
    dmarc_rec = _dns_txt('_dmarc.' + root)
    if spf_rec is None and dmarc_rec is None:
        return {'domain': root, 'error': 'Lookup DNS gagal'}
    spf = next((t for t in (spf_rec or []) if t.lower().startswith('v=spf1')), None)
    dmarc = next((t for t in (dmarc_rec or []) if t.lower().startswith('v=dmarc1')), None)
    pol = None
    if dmarc:
        m = re.search(r'\bp\s*=\s*(none|quarantine|reject)', dmarc, re.I)
        pol = m.group(1).lower() if m else None
    return {'domain': root, 'spf': bool(spf), 'dmarc': bool(dmarc), 'dmarc_policy': pol}

# --- PERHITUNGAN SKOR (setiap pengurangan tercatat) ---
def calculate_security_score(results):
    if not results.get('valid', True):
        return {'score': 0, 'grade': 'N/A', 'findings': [{
            'finding': 'Pemindaian tidak valid: ' + results.get('invalid_reason', '-'),
            'recommendation': 'Skor tidak dihitung agar tidak menyesatkan. Coba lagi nanti atau pastikan situs tidak memblokir pemindai.',
        }]}
    score = 100
    findings = []

    def add(points, level, text, rec):
        nonlocal score
        score -= points
        findings.append({'finding': f'Risiko {level}: {text}', 'recommendation': rec, 'poin': -points})

    is_https = str(results.get('evidence', {}).get('final_url', '')).startswith('https://')

    if results.get('exposed_git_info', {}).get('ditemukan'):
        add(50, 'Kritis', 'Direktori .git terekspos (isi file terverifikasi).',
            'Hapus folder .git dari server atau blokir akses ke /.git/ di web server.')

    ssl_info = results.get('ssl_info', {})
    if not is_https:
        add(30, 'Tinggi', 'Situs tidak dilayani lewat HTTPS.',
            "Pasang sertifikat TLS (mis. Let's Encrypt) dan alihkan semua trafik ke HTTPS.")
    elif ssl_info.get('valid') is False:
        add(30, 'Tinggi', f"Sertifikat SSL tidak valid ({ssl_info.get('error', '-')}).",
            'Perbaiki atau perbarui sertifikat TLS agar dipercaya browser.')
    elif isinstance(ssl_info.get('sisa_hari'), int) and ssl_info['sisa_hari'] < 14:
        add(5, 'Rendah', f"Sertifikat SSL kedaluwarsa dalam {ssl_info['sisa_hari']} hari.",
            'Perpanjang sertifikat dan aktifkan perpanjangan otomatis.')

    if is_https and results.get('https_redirect_info', {}).get('http_ke_https') is False:
        add(10, 'Menengah', 'Versi http:// tidak dialihkan ke https://.', 'Tambahkan redirect 301 dari HTTP ke HTTPS.')

    sh = results.get('security_headers', {})
    missing = sh.get('tidak_ditemukan', {})
    if is_https and 'Strict-Transport-Security' in missing:
        add(15, 'Tinggi', 'Header Strict-Transport-Security (HSTS) tidak ada.',
            "Tambahkan 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
    age = sh.get('hsts_max_age')
    if isinstance(age, int) and age < 15552000:
        add(5, 'Rendah', f'HSTS max-age terlalu pendek ({age} detik).', 'Naikkan max-age minimal 15552000 (6 bulan).')
    if 'Content-Security-Policy' in missing:
        add(10, 'Menengah', 'Header Content-Security-Policy tidak ada.', "Tambahkan 'Content-Security-Policy' sesuai sumber aset situs.")
    if 'X-Frame-Options' in missing:
        add(10, 'Menengah', 'Header X-Frame-Options tidak ada (dan tidak ada CSP frame-ancestors).',
            "Tambahkan 'X-Frame-Options: DENY' atau CSP 'frame-ancestors'.")
    if 'X-Content-Type-Options' in missing:
        add(10, 'Menengah', 'Header X-Content-Type-Options tidak ada.', "Tambahkan 'X-Content-Type-Options: nosniff'.")
    if 'Referrer-Policy' in missing:
        add(5, 'Rendah', 'Header Referrer-Policy tidak ada.', "Tambahkan 'Referrer-Policy: strict-origin-when-cross-origin'.")

    tech = results.get('technology_info', {})
    leak = tech.get('Powered-By') or tech.get('ASP.NET')
    if leak:
        add(5, 'Rendah', f'Header membocorkan teknologi backend ({leak}).', "Hapus header 'X-Powered-By' / 'X-AspNet-Version'.")
    server = str(tech.get('Server', ''))
    if re.search(r'\d+\.\d+', server):
        add(5, 'Rendah', f'Header Server membocorkan versi ({server}).', 'Sembunyikan versi server (mis. server_tokens off di Nginx).')

    mc = results.get('mixed_content_info', {})
    if mc.get('ditemukan'):
        add(10, 'Menengah', f"Ditemukan {len(mc.get('urls', []))} aset Mixed Content.", 'Muat semua aset lewat HTTPS.')

    bad = results.get('cookie_info', {}).get('bermasalah', [])
    if bad:
        names = ', '.join(c['cookie'] for c in bad[:5])
        add(5, 'Rendah', f'Cookie tanpa flag keamanan lengkap ({names}).', 'Set flag Secure, HttpOnly, dan SameSite.')

    sf = results.get('sensitive_files', {})
    for h in sf.get('terekspos', []):
        add(40, 'Kritis', f"File sensitif terekspos ({h['path']}).",
            f"Blokir akses publik ke {h['path']} di web server.")

    csp_q = results.get('csp_quality', {})
    for w in csp_q.get('kelemahan', []):
        add(5, 'Rendah', f'CSP lemah: {w}.', 'Perketat CSP; hindari unsafe-inline/unsafe-eval dan wildcard.')

    cors = results.get('cors_info', {})
    if cors.get('rentan'):
        add(20, 'Tinggi', 'CORS salah konfigurasi: origin sembarang dipantulkan dengan kredensial.',
            'Jangan pantulkan Origin; pakai allowlist dan hindari Allow-Credentials dengan Origin dinamis.')

    em = results.get('email_security', {})
    if em and not em.get('error'):
        if not em.get('spf'):
            add(5, 'Rendah', f"Domain {em['domain']} tidak punya SPF.", 'Tambahkan record SPF (v=spf1 ...).')
        if not em.get('dmarc'):
            add(5, 'Rendah', f"Domain {em['domain']} tidak punya DMARC.", 'Tambahkan record DMARC (v=DMARC1; p=...).')
        elif em.get('dmarc_policy') == 'none':
            add(3, 'Rendah', f"DMARC domain {em['domain']} hanya p=none (memantau saja).", 'Naikkan ke p=quarantine atau p=reject.')
    score = max(0, score)
    grade = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
    if not findings:
        findings.append({'finding': 'Tidak ditemukan masalah pada pemeriksaan dasar.',
                         'recommendation': 'Pertahankan konfigurasi dan pindai ulang secara berkala.'})
    return {'score': score, 'grade': grade, 'findings': findings}


# --- FUNGSI UTAMA ---
def run_full_scan(target_url):
    raw = (target_url or '').strip()
    auto_scheme = not re.match(r'^https?://', raw, re.I)
    url = 'https://' + raw if auto_scheme else raw
    session = _new_session()
    results = {'target': url, 'valid': True,
               'scanned_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    try:
        try:
            resp, ssl_err = fetch_main(session, url)
        except requests.exceptions.RequestException as e0:
            if not auto_scheme or isinstance(e0, requests.exceptions.Timeout):
                raise
            url = 'http://' + raw
            results['target'] = url
            resp, ssl_err = fetch_main(session, url)
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.Timeout):
            msg = 'Situs tidak merespons dalam batas waktu. Kemungkinan proteksi bot situs memblokir server pemindai (IP data center), walaupun situs bisa dibuka di browser.'
        else:
            msg = f'Tidak dapat terhubung ke situs ({e.__class__.__name__}).'
        results.update(valid=False, invalid_reason=msg)
        for k in MODULE_KEYS:
            results[k] = {'error': msg}
        results['score_info'] = calculate_security_score(results)
        return results

    p = urlparse(resp.url)
    base = f'{p.scheme}://{p.netloc}'
    verify = ssl_err is None
    results['evidence'] = {
        'final_url': resp.url,
        'status_code': resp.status_code,
        'response_time_ms': resp.elapsed_ms,
        'user_agent': getattr(resp, 'ua_used', UA),
        'redirects': [f'{h.status_code} {h.url}' for h in resp.history],
        'headers': dict(resp.headers),
    }
    block = detect_block(resp)
    if block or resp.status_code >= 500:
        results.update(valid=False, invalid_reason=block or f'Server membalas HTTP {resp.status_code}.')

    soup = BeautifulSoup(resp.text, 'html.parser')
    results['security_headers'] = check_security_headers(resp)
    results['technology_info'] = find_tech_info(resp, soup)
    results['mixed_content_info'] = check_mixed_content(resp, soup)
    results['cookie_info'] = check_cookies(resp)
    results['csp_quality'] = analyze_csp(resp.headers.get('Content-Security-Policy', ''))

    jobs = {
        'robots_txt_info': lambda: check_robots_txt(session, base, verify),
        'exposed_git_info': lambda: check_exposed_git(session, base, verify),
        'https_redirect_info': lambda: check_https_redirect(session, p.hostname),
        'sensitive_files': lambda: check_sensitive_files(session, base, verify),
        'cors_info': lambda: check_cors(session, resp.url, verify),
        'email_security': lambda: check_email_security(p.hostname),
    }
    if p.scheme != 'https':
        results['ssl_info'] = {'valid': None, 'error': 'Situs tidak memakai HTTPS'}
    elif ssl_err:
        results['ssl_info'] = {'valid': False, 'error': ssl_err}
    else:
        jobs['ssl_info'] = lambda: check_ssl(p.hostname, p.port or 443)

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {k: ex.submit(fn) for k, fn in jobs.items()}
        for k, f in futures.items():
            try:
                results[k] = f.result()
            except Exception as e:
                results[k] = {'error': _err(e)}

    results['score_info'] = calculate_security_score(results)
    return results


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    print(json.dumps(run_full_scan(target), indent=2))