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
               'sensitive_files', 'csp_quality', 'cors_info', 'email_security', 'cache_info', 'caa_info', 'tls_old_info', 'subdomain_info')


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
    h = resp.headers
    if h.get('cf-mitigated', '').lower() == 'challenge':
        return 'Diblokir tantangan bot Cloudflare'
    vm = h.get('x-vercel-mitigated', '').lower()
    if vm:
        return f'Diblokir Vercel Security Checkpoint ({vm})'
    if resp.status_code == 429:
        return 'Dibatasi server (HTTP 429: terlalu banyak permintaan). Coba lagi beberapa menit lagi.'
    if resp.status_code in (401, 403, 407, 503):
        body = resp.text[:6000].lower()
        markers = ('just a moment', 'cf-chl', 'attention required', 'captcha', 'access denied', 'request blocked',
                   'security checkpoint', 'checking your browser', 'ddos protection', 'request unsuccessful', 'bot protection')
        if any(m in body for m in markers):
            return f'Diblokir WAF/proteksi bot (HTTP {resp.status_code})'
        return f'Server menolak pemindai (HTTP {resp.status_code}); header halaman penolakan tidak mewakili situs.'
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
    dirs = {}
    for part in csp.split(';'):
        bits = part.strip().split()
        if bits:
            dirs[bits[0].lower()] = [b.lower() for b in bits[1:]]
    script = dirs.get('script-src', dirs.get('default-src', []))
    style = dirs.get('style-src', dirs.get('default-src', []))
    weak, notes = [], []
    has_nonce_hash = any(x.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for x in script)
    if "'unsafe-inline'" in script and not has_nonce_hash:
        weak.append("'unsafe-inline' pada script-src (mengizinkan skrip inline)")
    if "'unsafe-eval'" in script:
        weak.append("'unsafe-eval' pada script-src (mengizinkan eval)")
    if any(x in ('*', 'http:', 'https:', 'data:') for x in script):
        weak.append('sumber skrip terlalu luas (*, http:, https:, atau data:)')
    if "'unsafe-inline'" in style:
        notes.append("'unsafe-inline' pada style-src berisiko rendah dan tidak mengurangi skor (sesuai Mozilla Observatory)")
    kurang = []
    if 'object-src' not in dirs and 'default-src' not in dirs:
        kurang.append('object-src')
    elif 'object-src' in dirs and "'none'" not in dirs['object-src']:
        kurang.append("object-src 'none'")
    if 'base-uri' not in dirs:
        kurang.append('base-uri')
    if 'frame-ancestors' not in dirs:
        kurang.append('frame-ancestors')
    return {'ada': True, 'kelemahan': weak, 'kurang_direktif': kurang, 'catatan': notes}

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


# --- MODUL 14: DNS CAA ---
def check_caa(host):
    root = host.lower().strip('.')
    # Ambil CAA di domain dan satu tingkat di atasnya (CAA bisa diwarisi)
    labels = root.split('.')
    names = [root]
    if len(labels) > 2:
        names.append('.'.join(labels[-2:]))
    issuers = []
    for name in names:
        recs = _dns_rr(name, 'CAA')
        if recs:
            for r in recs:
                issuers.append(r)
            break
    clean = [x for x in issuers if re.search(r'\b(issue|issuewild|iodef)\b', x, re.I)]
    cas = []
    for x in clean:
        m = re.search(r'"([^"]+)"', x)
        if m and m.group(1).strip():
            cas.append(m.group(1).strip())
    return {'ada': bool(clean), 'issuers': clean[:10], 'ca': cas[:10]}


# --- MODUL 15: TLS LAMA (1.0/1.1 masih diterima?) ---
def check_old_tls(host, port=443):
    import ssl as _ssl
    try:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        try:
            ctx.maximum_version = _ssl.TLSVersion.TLSv1_1
            ctx.minimum_version = _ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            return {'tls_lama_diterima': None, 'catatan': 'Tidak dapat diuji di lingkungan ini'}
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return {'tls_lama_diterima': True, 'versi': ss.version()}
    except (_ssl.SSLError, OSError):
        return {'tls_lama_diterima': False}
    except Exception as e:
        return {'tls_lama_diterima': None, 'catatan': _err(e)}

# --- MODUL 16: SUBDOMAIN TAKEOVER (PASIF) ---
SUBDOMAIN_PREFIXES = ('www', 'api', 'app', 'blog', 'mail', 'dev', 'staging', 'cdn', 'shop', 'docs', 'test', 'portal')

# layanan pihak ketiga -> (penanda CNAME, fingerprint "layanan kosong")
TAKEOVER_FINGERPRINTS = (
    ('github.io', "there isn't a github pages site here"),
    ('github.io', 'for root urls (like http://example.com/) you must provide an index'),
    ('herokudns.com', "no such app"),
    ('herokuapp.com', "no such app"),
    ('s3.amazonaws.com', 'nosuchbucket'),
    ('amazonaws.com', 'nosuchbucket'),
    ('ghost.io', 'the thing you were looking for is no longer here'),
    ('cargocollective.com', "404 not found"),
    ('wordpress.com', 'do you want to register'),
    ('pantheonsite.io', 'the gods are wise'),
    ('zendesk.com', 'help center closed'),
    ('readthedocs.io', "unknown domain"),
    ('netlify.app', 'not found - request id'),
    ('fastly.net', 'fastly error: unknown domain'),
    ('surge.sh', 'project not found'),
    ('bitbucket.io', 'repository not found'),
    ('helpscoutdocs.com', 'no settings were found for this company'),
    ('wpengine.com', "the site you were looking for couldn't be found"),
)
THIRD_PARTY_HOSTS = tuple(sorted(set(h for h, _ in TAKEOVER_FINGERPRINTS)))

def check_subdomain_takeover(session, root, verify):
    """Pasif: untuk subdomain umum yang CNAME-nya mengarah ke layanan pihak ketiga,
    cek apakah layanan tujuannya kosong (pola 'dangling'). Hanya membaca DNS & HTTP GET.
    Tidak pernah mengklaim atau mendaftarkan apa pun."""
    base = '.'.join(root.split('.')[-2:]) if root.count('.') >= 1 else root
    hasil, rentan = [], []
    for pre in SUBDOMAIN_PREFIXES:
        fqdn = f'{pre}.{base}'
        cnames = _dns_rr(fqdn, 'CNAME')
        if not cnames:
            continue
        target = cnames[0].strip().rstrip('.').lower()
        host = next((h for h in THIRD_PARTY_HOSTS if target.endswith(h)), None)
        if not host:
            continue  # CNAME internal / bukan layanan yang kita kenali -> abaikan
        entry = {'subdomain': fqdn, 'cname': target, 'layanan': host, 'status': 'Perlu dicek manual'}
        try:
            r = session.get(f'https://{fqdn}', timeout=TIMEOUT, verify=False, allow_redirects=True)
            body = (r.text or '')[:8000].lower()
            fp = next((p for h, p in TAKEOVER_FINGERPRINTS if h == host and p in body), None)
            if fp:
                entry['status'] = 'Rentan'
                entry['bukti'] = fp
                rentan.append(entry)
            elif r.status_code < 400:
                entry['status'] = 'Aktif (bukan masalah)'
            else:
                entry['status'] = f'Perlu dicek manual (HTTP {r.status_code})'
        except requests.exceptions.RequestException:
            entry['status'] = 'Perlu dicek manual (tidak merespons)'
        hasil.append(entry)
    return {'diperiksa': hasil, 'rentan': rentan, 'base': base}

# --- MODUL 13: HEADER CACHE HALAMAN SENSITIF ---
SENSITIVE_PATHS = ('/dashboard', '/account', '/profile', '/admin', '/settings')

def check_cache_headers(session, base, verify, home_text='', home_len=0):
    """Halaman yang mungkin berisi data pengguna tidak boleh di-cache publik.
    Hanya membaca header respons; tidak mengirim data atau login.
    Menolak soft-200: path yang isinya sama dengan beranda (situs catch-all/SPA)
    tidak dinilai, karena itu bukan halaman tersendiri."""
    hasil = []
    home_head = (home_text or '')[:2000]
    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            r = session.get(url, timeout=TIMEOUT, verify=verify, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if r.status_code != 200:
            continue  # redirect ke login / 404 = aman, tidak dinilai
        body = r.text or ''
        # Soft-200: isinya sama/sangat mirip dengan beranda -> catch-all, lewati.
        if home_len and abs(len(body) - home_len) < max(40, home_len * 0.02):
            continue
        if home_head and body[:2000] == home_head:
            continue
        ctype = r.headers.get('Content-Type', '').lower()
        if 'html' not in ctype and ctype:
            continue  # bukan halaman HTML
        cc = r.headers.get('Cache-Control', '').lower()
        aman = any(k in cc for k in ('no-store', 'private', 'no-cache'))
        hasil.append({'path': path, 'cache_control': r.headers.get('Cache-Control', '(tidak ada)'), 'aman': aman})
    bermasalah = [h for h in hasil if not h['aman']]
    return {'diperiksa': hasil, 'bermasalah': bermasalah}

# --- MODUL 12: SPF & DMARC (via DNS-over-HTTPS) ---
def _dns_txt(name):
    try:
        r = requests.get('https://cloudflare-dns.com/dns-query',
                         params={'name': name, 'type': 'TXT'},
                         headers={'accept': 'application/dns-json'}, timeout=TIMEOUT)
        return [a.get('data', '').strip('"') for a in r.json().get('Answer', [])]
    except Exception:
        return None

def _dns_rr(name, rrtype):
    try:
        r = requests.get('https://cloudflare-dns.com/dns-query',
                         params={'name': name, 'type': rrtype},
                         headers={'accept': 'application/dns-json'}, timeout=TIMEOUT)
        return [a.get('data', '').strip() for a in r.json().get('Answer', [])]
    except Exception:
        return None


def check_email_security(host):
    h0 = host.lower().strip('.')
    platforms = ('onrender.com', 'vercel.app', 'herokuapp.com', 'github.io', 'netlify.app', 'pages.dev',
                 'web.app', 'firebaseapp.com', 'azurewebsites.net', 'fly.dev', 'railway.app', 'replit.app',
                 'glitch.me', 'appspot.com', 'blogspot.com', 'wordpress.com')
    plat = next((p for p in platforms if h0.endswith('.' + p)), None)
    if plat:
        return {'domain': h0, 'error': f'Dilewati karena ini subdomain platform {plat}; DNS email dikelola penyedia platform'}
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

    if results.get('tls_old_info', {}).get('tls_lama_diterima') is True:
        add(10, 'Tinggi', 'Server masih menerima TLS 1.0/1.1 yang sudah usang.',
            'Nonaktifkan TLS 1.0 dan 1.1; izinkan hanya TLS 1.2 ke atas.')
    if is_https and results.get('caa_info', {}) and not results['caa_info'].get('ada') and not results['caa_info'].get('error'):
        add(3, 'Rendah', 'Domain tidak punya DNS CAA.',
            'Tambahkan record CAA untuk membatasi CA mana yang boleh menerbitkan sertifikat.')
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

    for h in results.get('cache_info', {}).get('bermasalah', []):
        add(15, 'Tinggi', f"Halaman {h['path']} dapat di-cache (Cache-Control: {h['cache_control']}).",
            "Set 'Cache-Control: no-store' pada halaman berisi data pengguna agar tidak tersimpan di cache bersama/CDN.")
    bad = results.get('cookie_info', {}).get('bermasalah', [])
    if bad:
        names = ', '.join(c['cookie'] for c in bad[:5])
        add(5, 'Rendah', f'Cookie tanpa flag keamanan lengkap ({names}).', 'Set flag Secure, HttpOnly, dan SameSite.')

    for sd in results.get('subdomain_info', {}).get('rentan', []):
        add(40, 'Kritis', f"Subdomain {sd['subdomain']} rentan diambil alih (dangling CNAME ke {sd['layanan']}).",
            f"Hapus record DNS untuk {sd['subdomain']} atau klaim kembali layanan di {sd['layanan']}.")
    sf = results.get('sensitive_files', {})
    for h in sf.get('terekspos', []):
        add(40, 'Kritis', f"File sensitif terekspos ({h['path']}).",
            f"Blokir akses publik ke {h['path']} di web server.")

    csp_q = results.get('csp_quality', {})
    for w in csp_q.get('kelemahan', []):
        add(5, 'Rendah', f'CSP lemah: {w}.', 'Perketat CSP; hindari unsafe-inline/unsafe-eval dan wildcard.')
    for d in csp_q.get('kurang_direktif', []):
        add(3, 'Rendah', f'CSP belum menetapkan {d}.', f"Tambahkan direktif {d} pada Content-Security-Policy.")

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
    alt = resp.headers.get('alt-svc', '')
    results['protocol_info'] = {'http3': 'h3' in alt.lower(), 'alt_svc': alt[:200]}

    jobs = {
        'robots_txt_info': lambda: check_robots_txt(session, base, verify),
        'exposed_git_info': lambda: check_exposed_git(session, base, verify),
        'https_redirect_info': lambda: check_https_redirect(session, p.hostname),
        'sensitive_files': lambda: check_sensitive_files(session, base, verify),
        'cors_info': lambda: check_cors(session, resp.url, verify),
        'email_security': lambda: check_email_security(p.hostname),
        'cache_info': lambda: check_cache_headers(session, base, verify, resp.text, len(resp.text or '')),
        'caa_info': lambda: check_caa(p.hostname),
        'subdomain_info': lambda: check_subdomain_takeover(session, p.hostname, verify),
    }
    if p.scheme != 'https':
        results['ssl_info'] = {'valid': None, 'error': 'Situs tidak memakai HTTPS'}
    elif ssl_err:
        results['ssl_info'] = {'valid': False, 'error': ssl_err}
    else:
        jobs['ssl_info'] = lambda: check_ssl(p.hostname, p.port or 443)
        jobs['tls_old_info'] = lambda: check_old_tls(p.hostname, p.port or 443)

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