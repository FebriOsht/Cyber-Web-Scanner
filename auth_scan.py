"""Mode D: pemeriksaan terautentikasi (terminal saja, untuk situs milik sendiri)."""
import base64
import json
import re
import secrets
import time

import requests

from ssrf_guard import check_url, guard_session


class AuthConfig:
    def __init__(self, data):
        self.accounts = data.get('accounts') or []
        self.login = data.get('login') or {}
        self.object_urls = data.get('object_urls') or []
        self.reset = data.get('reset') or {}

    @property
    def ok(self):
        return len(self.accounts) >= 1


EXAMPLE = {
    "accounts": [
        {"name": "A", "cookies": {"session": "paste-account-A-session-cookie"}},
        {"name": "B", "cookies": {"session": "paste-account-B-session-cookie"}},
    ],
    "object_urls": [
        {"as": "A", "url": "https://example.com/api/orders/1001", "owned_by_other": "https://example.com/api/orders/2002"}
    ],
    "login": {"url": "https://example.com/api/login", "method": "POST",
              "json": {"email": "a@example.com", "password": "wrong-on-purpose"}},
    "reset": {"url": "https://example.com/api/forgot-password", "method": "POST",
              "json": {"email": "a@example.com"}}
}


def _session(verify):
    s = requests.Session()
    s.headers['User-Agent'] = 'CyberWebScanner/2.0 (authenticated, owner-verified)'
    s.verify = verify
    return guard_session(s)


def verify_ownership(host):
    token = 'cws-' + secrets.token_hex(16)
    return token, {
        'file': f'https://{host}/.well-known/cws-verify-{token}.txt  (isi file: {token})',
        'dns': f'TXT record di _cws-verify.{host} dengan nilai: {token}',
    }


def confirm_ownership(host, token, verify=True):
    s = _session(verify)
    try:
        r = s.get(f'https://{host}/.well-known/cws-verify-{token}.txt', timeout=8, allow_redirects=False)
        if r.status_code == 200 and token in (r.text or '')[:200]:
            return True, 'file'
    except requests.exceptions.RequestException:
        pass
    try:
        import dns_email
        _, txt = dns_email.doh(f'_cws-verify.{host}', 'TXT')
        if any(token in t for t in txt):
            return True, 'dns'
    except Exception:
        pass
    return False, None


def _acc_session(acc, verify):
    s = _session(verify)
    for k, v in (acc.get('cookies') or {}).items():
        s.cookies.set(k, v)
    s.headers.update(acc.get('headers') or {})
    return s


def check_idor(cfg, verify):
    findings = []
    sessions = {a['name']: _acc_session(a, verify) for a in cfg.accounts}
    for item in cfg.object_urls:
        other = item.get('owned_by_other')
        who = item.get('as')
        if not other or who not in sessions:
            continue
        check_url(other)
        try:
            r = sessions[who].get(other, timeout=10, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        body = (r.text or '')[:4000]
        if r.status_code == 200 and ('json' in r.headers.get('Content-Type', '').lower() or len(body) > 200):
            findings.append({'url': other, 'as': who, 'status': r.status_code})
    return findings


def check_rate_limit(cfg, verify):
    lg = cfg.login
    if not lg.get('url'):
        return None
    check_url(lg['url'])
    s = _session(verify)
    codes = []
    for _ in range(8):
        try:
            r = s.request(lg.get('method', 'POST'), lg['url'], json=lg.get('json'), data=lg.get('data'), timeout=8, allow_redirects=False)
            codes.append(r.status_code)
            if r.status_code == 429:
                break
        except requests.exceptions.RequestException:
            break
        time.sleep(0.3)
    return {'attempts': len(codes), 'codes': codes, 'limited': 429 in codes}


def check_session_tokens(cfg, verify):
    issues = []
    for a in cfg.accounts:
        for k, v in (a.get('cookies') or {}).items():
            if re.search(r'(sess|sid|token|auth|jwt)', k, re.I) and re.match(r'^eyJ[A-Za-z0-9_-]+\.', v or ''):
                try:
                    head = json.loads(base64.urlsafe_b64decode(v.split('.')[0] + '=='))
                    if str(head.get('alg', '')).lower() == 'none':
                        issues.append({'account': a['name'], 'issue': 'JWT memakai alg: none'})
                except Exception:
                    pass
    return issues


def check_host_header(cfg, verify):
    rs = cfg.reset
    if not rs.get('url'):
        return None
    check_url(rs['url'])
    s = _session(verify)
    marker = 'cws-hosttest.example'
    try:
        r = s.request(rs.get('method', 'POST'), rs['url'], json=rs.get('json'), data=rs.get('data'),
                      headers={'X-Forwarded-Host': marker}, timeout=8, allow_redirects=False)
    except requests.exceptions.RequestException:
        return None
    return {'reflected': marker in (r.text or '')[:4000]}


def run(cfg, verify=True):
    out = {'idor': [], 'rate_limit': None, 'session': [], 'host_header': None, 'notes': []}
    for name, fn in (('idor', check_idor), ('rate_limit', check_rate_limit), ('host_header', check_host_header)):
        try:
            out[name] = fn(cfg, verify)
        except Exception as e:
            out['notes'].append(f'{name}: {e.__class__.__name__}')
    out['session'] = check_session_tokens(cfg, verify)
    return out


def findings(r):
    out = []
    for x in r.get('idor', []):
        out.append(('AUTH-IDOR', 30, 'Tinggi', f"Kontrol akses bocor: akun {x['as']} dapat membaca objek milik akun lain ({x['url']}).",
                    'Pastikan setiap endpoint memeriksa bahwa objek yang diminta milik pengguna yang login.', 'identity', 'senior', 'high'))
    rl = r.get('rate_limit')
    if rl and not rl.get('limited') and rl.get('attempts', 0) >= 5:
        out.append(('AUTH-NO-RATE-LIMIT', 10, 'Menengah', f"Login tidak membatasi percobaan ({rl['attempts']} percobaan tanpa HTTP 429).",
                    'Batasi percobaan login per akun dan per IP; tambahkan penundaan atau CAPTCHA.', 'identity', 'beginner', 'medium'))
    for x in r.get('session', []):
        out.append(('AUTH-WEAK-JWT', 10, 'Menengah', f"Token sesi akun {x['account']} lemah: {x['issue']}.",
                    'Pakai algoritma tanda tangan yang kuat dan verifikasi setiap token.', 'identity', 'senior', 'high'))
    hh = r.get('host_header')
    if hh and hh.get('reflected'):
        out.append(('AUTH-HOST-HEADER', 10, 'Menengah', 'Alur reset memantulkan header Host dari penyerang.',
                    'Bangun tautan reset dari alamat situs yang tetap di server, bukan dari header Host.', 'identity', 'senior', 'medium'))
    return out
