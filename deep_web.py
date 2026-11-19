"""Mode B: pemeriksaan web mendalam (tanpa browser headless).

Mengunduh file JavaScript milik situs yang dimuat halaman awal lalu memeriksa isinya, serta mencari
file dan endpoint yang sering tertinggal di produksi. Semua permintaan adalah GET/POST biasa
bervolume rendah lewat sesi yang sudah dipasangi pengaman SSRF; tidak ada payload eksploitasi.
Setiap temuan divalidasi dari ISI respons, bukan hanya status HTTP, agar situs yang membalas
200 untuk semua alamat tidak menghasilkan temuan palsu.
"""
import base64
import json
import re
import secrets as _rand
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

MAX_SCRIPTS = 12
JS_MAX_BYTES = 2 * 1024 * 1024
INLINE_MAX_CHARS = 1_000_000
BUDGET_SECONDS = 25
REQ_TIMEOUT = 6

# (jenis, pola, tingkat, keyakinan). critical = kunci rahasia; low = kunci publik yang perlu dibatasi.
SECRET_PATTERNS = (
    ('AWS access key', r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', 'critical', 'high'),
    ('Stripe secret key', r'\b[sr]k_live_[0-9A-Za-z]{20,}\b', 'critical', 'high'),
    ('OpenAI API key', r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b', 'critical', 'medium'),
    ('Anthropic API key', r'\bsk-ant-[A-Za-z0-9_-]{30,}\b', 'critical', 'high'),
    ('GitHub token', r'\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b', 'critical', 'high'),
    ('Slack token', r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', 'critical', 'high'),
    ('SendGrid API key', r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b', 'critical', 'high'),
    ('Mailgun API key', r'\bkey-[0-9a-f]{32}\b', 'critical', 'medium'),
    ('Midtrans server key', r'\b(?:SB-)?Mid-server-[A-Za-z0-9_-]{20,}\b', 'critical', 'high'),
    ('Xendit secret key', r'\bxnd_(?:production|development)_[A-Za-z0-9]{40,}\b', 'critical', 'high'),
    ('Private key', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'critical', 'high'),
    ('Google API key', r'\bAIza[0-9A-Za-z_-]{35}\b', 'low', 'medium'),
)
JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}')

# (nama, pola versi, batas aman / 'eol' / None=aturan khusus, penjelasan)
LIB_RULES = (
    ('jQuery UI', r'jQuery UI - v(\d+\.\d+\.\d+)', (1, 13, 0),
     'XSS pada beberapa widget (CVE-2021-41182 dan sejenisnya); perbarui ke 1.13 atau lebih baru'),
    ('jQuery', r'jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)', (3, 5, 0),
     'XSS saat memproses HTML (CVE-2020-11022, CVE-2020-11023); perbarui ke 3.5.0 atau lebih baru'),
    ('Bootstrap', r'Bootstrap v(\d+\.\d+\.\d+)', None,
     'XSS pada tooltip dan popover (CVE-2019-8331); perbarui ke 3.4.1, 4.3.1, atau lebih baru'),
    ('AngularJS', r'AngularJS v(1\.\d+\.\d+)', 'eol',
     'AngularJS 1.x tidak lagi didukung sejak Januari 2022 dan tidak menerima perbaikan keamanan'),
    ('Moment.js', r'//! version : (\d+\.\d+\.\d+)', (2, 29, 4),
     'ReDoS saat mem-parsing tanggal (CVE-2022-31129); perbarui ke 2.29.4 atau lebih baru'),
)

SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s\'"]+)')
# Layanan yang memang tidak mendukung SRI (skrip dinamis), dikecualikan agar laporan tidak berisik.
SRI_EXEMPT = ('googletagmanager.com', 'google-analytics.com', 'gstatic.com', 'google.com', 'recaptcha.net',
              'challenges.cloudflare.com', 'js.stripe.com', 'vercel-scripts.com', 'vercel-insights.com',
              'paypal.com', 'paypalobjects.com', 'midtrans.com', 'facebook.net', 'clarity.ms', 'hotjar.com')

BACKUP_NAMES = ('backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
                'site.zip', 'www.zip', 'public_html.zip', 'html.zip')
CONFIG_FILES = {
    '/.env.local': (r'^[A-Z0-9_]+\s*=', 'File environment (.env.local)'),
    '/.env.production': (r'^[A-Z0-9_]+\s*=', 'File environment (.env.production)'),
    '/.env.backup': (r'^[A-Z0-9_]+\s*=', 'File environment (.env.backup)'),
    '/.git-credentials': (r'https?://[^\s:/]+:[^\s@/]+@', 'Kredensial git'),
    '/.npmrc': (r'_authToken\s*=', 'Token npm'),
    '/wp-config.php.bak': (r'DB_PASSWORD', 'Backup konfigurasi WordPress'),
}
# jalur: (pola isi, jenis, boleh HTML)
OPS_ENDPOINTS = {
    '/phpinfo.php': (r'phpinfo\(\)', 'Halaman phpinfo', True),
    '/info.php': (r'phpinfo\(\)', 'Halaman phpinfo', True),
    '/actuator/env': (r'"propertySources"', 'Spring Boot Actuator /env', False),
    '/server-status': (r'Apache Server Status for', 'Apache server-status', True),
    '/debug/pprof/': (r'Types of profiles available', 'Go pprof', True),
    '/metrics': (r'^# (?:HELP|TYPE) \w+', 'Metrik Prometheus', False),
}
API_DOC_PATHS = ('/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/swagger-ui.html',
                 '/swagger-ui/', '/docs', '/redoc')
GRAPHQL_PATHS = ('/graphql', '/api/graphql')
DEBUG_MARKERS = ('traceback (most recent call last)', 'werkzeug debugger', 'debug = true</code>',
                 'whoops! there was an error', 'symfony\\component\\errorhandler', 'stack trace:</',
                 "server error in '/' application", 'at org.springframework', 'nextjs__container_errors')


class _OutOfTime(Exception):
    pass


class _Ctx:
    def __init__(self, session, verify, budget):
        self.s, self.verify = session, verify
        self.deadline = time.monotonic() + budget
        self.partial = False

    def _timeout(self):
        left = self.deadline - time.monotonic()
        if left <= 1:
            self.partial = True
            raise _OutOfTime()
        return min(REQ_TIMEOUT, left)

    def first_bytes(self, url, n=8192, any_status=False):
        r = self.s.get(url, timeout=self._timeout(), verify=self.verify, allow_redirects=False, stream=True)
        try:
            data = r.raw.read(n, decode_content=True) if (any_status or r.status_code == 200) else b''
        finally:
            r.close()
        return r, data

    def post_json(self, url, payload):
        return self.s.post(url, json=payload, timeout=self._timeout(), verify=self.verify, allow_redirects=False)


def mask(value):
    v = value.strip()
    return v[:6] + '…' + v[-4:] if len(v) > 14 else v[:3] + '…'


def _short(url):
    p = urlparse(url)
    path = p.path or '/'
    return path if len(path) <= 80 else '…' + path[-77:]


def _ver(s):
    return tuple(int(x) for x in s.split('.')[:3])


def _jwt_payload(segment):
    try:
        raw = base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def find_secrets(text, where):
    found = []
    for kind, pattern, level, conf in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            found.append({'type': kind, 'file': where, 'masked': mask(m.group(0)), 'severity': level, 'confidence': conf})
    for m in JWT_RE.finditer(text):
        payload = _jwt_payload(m.group(1))
        if payload and payload.get('role') == 'service_role':
            found.append({'type': 'Supabase service_role key', 'file': where, 'masked': mask(m.group(0)),
                          'severity': 'critical', 'confidence': 'high'})
    return found


def _bootstrap_vulnerable(v):
    return v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1)


def find_libraries(text):
    out = []
    for name, pattern, rule, issue in LIB_RULES:
        m = re.search(pattern, text)
        if not m:
            continue
        v = _ver(m.group(1))
        vulnerable = (rule == 'eol') or (rule is None and _bootstrap_vulnerable(v)) or (isinstance(rule, tuple) and v < rule)
        if vulnerable:
            out.append({'name': name, 'version': m.group(1), 'issue': issue})
    return out


def _debug_kind(head, ctype):
    text = head.decode('utf-8', 'ignore').lower()
    return next((m for m in DEBUG_MARKERS if m in text), None)


def _backup_kind(head, ctype):
    if not head or 'html' in ctype.lower():
        return None
    if head.startswith(b'PK\x03\x04'):
        return 'Arsip ZIP'
    if head.startswith(b'\x1f\x8b'):
        return 'Arsip GZIP/TAR.GZ'
    if head.startswith(b'Rar!'):
        return 'Arsip RAR'
    if re.search(r'(-- MySQL dump|PostgreSQL database dump|CREATE TABLE|INSERT INTO)', head.decode('utf-8', 'ignore'), re.I):
        return 'Dump database SQL'
    return None


def _text_rule(pattern, kind, allow_html=False):
    def check(head, ctype):
        text = head.decode('utf-8', 'ignore')
        if not text:
            return None
        if not allow_html and ('html' in ctype.lower() or text.lstrip().startswith('<')):
            return None
        return kind if re.search(pattern, text, re.I | re.M) else None
    return check


def _api_doc_kind(head, ctype):
    text = head.decode('utf-8', 'ignore')
    if re.search(r'"(?:openapi|swagger)"\s*:\s*"\d', text):
        return 'Spesifikasi OpenAPI/Swagger'
    if re.search(r'swagger-ui|<redoc|redoc\.standalone', text, re.I):
        return 'Swagger UI / ReDoc'
    return None


def _same_site(host, page_host):
    def root(h):
        return '.'.join(h.split('.')[-2:])
    return host == page_host or root(host) == root(page_host)


def _collect_scripts(soup, page_url, page_host):
    scripts, no_sri = [], set()
    for tag in soup.find_all('script'):
        src = (tag.get('src') or '').strip()
        if not src:
            continue
        full = urljoin(page_url, src)
        p = urlparse(full)
        host = (p.hostname or '').lower()
        if p.scheme not in ('http', 'https') or not host:
            continue
        if _same_site(host, page_host):
            if full not in scripts:
                scripts.append(full)
        elif not tag.get('integrity') and not any(host == d or host.endswith('.' + d) for d in SRI_EXEMPT):
            no_sri.add(host)
    return scripts, no_sri


def _check_sourcemap(ctx, map_url):
    r, data = ctx.first_bytes(map_url, 2048)
    text = data.decode('utf-8', 'ignore').lstrip()
    return r.status_code == 200 and text.startswith('{') and ('"mappings"' in text or '"sources"' in text)


def _analyze_script(ctx, url, guess_map):
    r = ctx.s.get(url, timeout=ctx._timeout(), verify=ctx.verify, stream=True)
    try:
        if r.status_code != 200:
            return None
        data = r.raw.read(JS_MAX_BYTES, decode_content=True)
    finally:
        r.close()
    text = data.decode('utf-8', 'ignore')
    res = {'secrets': find_secrets(text, _short(url)), 'libraries': find_libraries(text), 'sourcemaps': []}
    candidates = []
    header = r.headers.get('SourceMap') or r.headers.get('X-SourceMap')
    if header:
        candidates.append(urljoin(url, header))
    m = SOURCEMAP_RE.search(text[-4000:])
    if m and not m.group(1).startswith('data:'):
        candidates.append(urljoin(url, m.group(1)))
    if not candidates and guess_map:
        candidates.append(url.split('?')[0] + '.map')
    if candidates and _check_sourcemap(ctx, candidates[0]):
        res['sourcemaps'].append(_short(candidates[0]))
    return res


def _probes(host):
    label = host.split('.')[-2] if host.count('.') >= 1 else host
    items = []
    for name in dict.fromkeys(BACKUP_NAMES + (f'{host}.zip', f'{label}.zip', f'{label}.sql')):
        items.append(('backups', '/' + name, _backup_kind, False))
    for path, (pattern, kind) in CONFIG_FILES.items():
        items.append(('config_files', path, _text_rule(pattern, kind), False))
    for path, (pattern, kind, allow_html) in OPS_ENDPOINTS.items():
        items.append(('ops', path, _text_rule(pattern, kind, allow_html), False))
    for path in API_DOC_PATHS:
        items.append(('api_docs', path, _api_doc_kind, False))
    items.append(('debug', '/__cws_probe_' + _rand.token_hex(4), _debug_kind, True))
    return items


def _run_probe(ctx, base, item):
    category, path, validator, any_status = item
    r, head = ctx.first_bytes(base + path, 8192, any_status)
    kind = validator(head, r.headers.get('Content-Type', ''))
    return category, ({'path': path if category != 'debug' else '(halaman error)', 'kind': kind} if kind else None)


def _probe_graphql(ctx, base, path):
    r = ctx.post_json(base + path, {'query': 'query{__schema{queryType{name}}}'})
    if r.status_code != 200 or 'json' not in r.headers.get('Content-Type', '').lower():
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if isinstance(data, dict) and isinstance(data.get('data'), dict) and data['data'].get('__schema'):
        return {'path': path, 'kind': 'Introspeksi GraphQL aktif'}
    return None


def run(session, base, resp, soup, verify, budget=BUDGET_SECONDS):
    ctx = _Ctx(session, verify, budget)
    page_host = (urlparse(resp.url).hostname or '').lower()
    out = {'js_checked': 0, 'js_total': 0, 'secrets': [], 'sourcemaps': [], 'libraries': [], 'backups': [],
           'config_files': [], 'debug': [], 'ops': [], 'api_docs': [], 'graphql': [], 'sri_missing': [],
           'partial': False, 'notes': []}
    scripts, no_sri = _collect_scripts(soup, resp.url, page_host)
    out['js_total'] = len(scripts)
    out['sri_missing'] = sorted(no_sri)
    inline = '\n'.join(t.get_text() or '' for t in soup.find_all('script') if not t.get('src'))[:INLINE_MAX_CHARS]
    out['secrets'].extend(find_secrets(inline, 'HTML (skrip inline)'))
    out['libraries'].extend(find_libraries(inline))

    jobs = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for i, url in enumerate(scripts[:MAX_SCRIPTS]):
            jobs.append(('js', ex.submit(_analyze_script, ctx, url, i < 2)))
        for item in _probes(page_host):
            jobs.append(('probe', ex.submit(_run_probe, ctx, base, item)))
        for path in GRAPHQL_PATHS:
            jobs.append(('graphql', ex.submit(_probe_graphql, ctx, base, path)))
        for kind, fut in jobs:
            try:
                res = fut.result()
            except (_OutOfTime, requests.exceptions.RequestException):
                continue
            except Exception as e:
                out['notes'].append(f'{e.__class__.__name__}: {str(e)[:120]}')
                continue
            if not res:
                continue
            if kind == 'js':
                out['js_checked'] += 1
                for key in ('secrets', 'libraries', 'sourcemaps'):
                    out[key].extend(res[key])
            elif kind == 'probe':
                category, entry = res
                if entry:
                    out[category].append(entry)
            else:
                out['graphql'].append(res)

    seen, uniq = set(), []
    for x in out['secrets']:
        key = (x['type'], x['masked'])
        if key not in seen:
            seen.add(key)
            uniq.append(x)
    out['secrets'] = uniq
    out['libraries'] = list({x['name']: x for x in out['libraries']}.values())
    out['debug'] = out['debug'][:1]
    out['partial'] = ctx.partial
    return out
