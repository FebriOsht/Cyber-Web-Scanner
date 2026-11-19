"""Mode C: pemeriksaan repositori (hanya lewat cli.py, di komputer pemilik kode).

Membaca folder proyek: dependensi rentan (OSV.dev), paket yang tidak ada di registry (sering
dikarang AI), kunci rahasia di kode dan riwayat git, file .env yang ter-commit, workflow CI/CD
berisiko, Dockerfile, dan beberapa pola kode berisiko. Isi kode tidak dikirim ke mana pun; yang
dikirim ke internet hanya nama dan versi paket (ke OSV.dev dan registry npm/PyPI), dan itu dapat
dimatikan dengan online=False.
"""
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from deep_web import find_secrets

SKIP_DIRS = {'node_modules', '.git', '.next', 'dist', 'build', 'out', 'venv', '.venv', 'env', '__pycache__', '.vercel',
             'coverage', '.turbo', '.cache', 'prisma-generated', '.pytest_cache', '.svelte-kit', '.nuxt', '.output'}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5000
HISTORY_MAX_LINES = 400_000
LOCK_NAMES = ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'npm-shrinkwrap.json')
TEXT_SKIP_NAMES = set(LOCK_NAMES) | {'poetry.lock', 'Pipfile.lock'}
ENV_FILE_RE = re.compile(r'(^|/)\.env(\.[\w.-]+)?$')
ENV_SAFE_RE = re.compile(r'(example|sample|template|dist|defaults?)$', re.I)
PUBLIC_SECRET_RE = re.compile(r'\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD)[A-Z0-9_]*\b')
REQ_PINNED_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)')
REQ_NAME_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)')
SKIP_SPECS = ('file:', 'link:', 'workspace:', 'git', 'http', 'npm:', 'github:', 'portal:')
INJECT_RE = re.compile(r'\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|pages)\.[\w.]*(?:title|body|message|label|name|ref)|github\.head_ref)\s*\}\}')
SEV_POINTS = {'CRITICAL': ('Tinggi', 20), 'HIGH': ('Tinggi', 10), 'MODERATE': ('Menengah', 5), 'MEDIUM': ('Menengah', 5), 'LOW': ('Rendah', 2)}
SEV_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW']
DEP_POINTS_CAP = 40


def _files(root):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name
            n += 1
            if n >= MAX_FILES:
                return


def _read_text(p):
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b'\0' in data[:2048]:
        return None
    return data.decode('utf-8', 'ignore')


def _git(root, *args, timeout=60):
    try:
        r = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.decode('utf-8', 'ignore') if r.returncode == 0 else None


def _dedupe(items):
    seen, out = set(), []
    for x in items:
        key = (x['type'], x['masked'])
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def _history_secrets(root, deadline):
    try:
        proc = subprocess.Popen(['git', '-C', str(root), 'log', '--all', '-p', '--no-color', '-U0', '--no-ext-diff',
                                 '--format=commit %H'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return [], False
    found, commit, path, lines, partial = [], '', '', 0, False
    try:
        for raw in proc.stdout:
            lines += 1
            if lines > HISTORY_MAX_LINES or time.monotonic() > deadline:
                partial = True
                break
            line = raw.decode('utf-8', 'ignore').rstrip('\r\n')
            if line.startswith('commit '):
                commit = line[7:15]
            elif line.startswith('+++ '):
                path = line[6:] if line.startswith('+++ b/') else line[4:]
            elif line.startswith('+') and path:
                for f in find_secrets(line[1:], path):
                    f['commit'] = commit
                    found.append(f)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.wait()
    return found, partial


def _npm_packages(pkg_dir):
    pj = json.loads((pkg_dir / 'package.json').read_text(encoding='utf-8', errors='ignore') or '{}')
    direct = {**(pj.get('dependencies') or {}), **(pj.get('devDependencies') or {})}
    pkgs, approx = [], False
    lock = pkg_dir / 'package-lock.json'
    if lock.exists():
        data = json.loads(lock.read_text(encoding='utf-8', errors='ignore') or '{}')
        for key, v in (data.get('packages') or {}).items():
            if not key or not isinstance(v, dict) or v.get('dev') or v.get('link') or 'version' not in v:
                continue
            pkgs.append((v.get('name') or key.rsplit('node_modules/', 1)[-1], v['version'], 'npm'))
    else:
        approx = True
        for name, spec in (pj.get('dependencies') or {}).items():
            m = re.match(r'^[\^~=v]?\s*(\d+\.\d+\.\d+)', str(spec).strip())
            if m:
                pkgs.append((name, m.group(1), 'npm'))
    has_lock = any((pkg_dir / n).exists() for n in LOCK_NAMES)
    return pkgs, direct, has_lock, approx


def _osv_query(pkgs):
    """{(nama, versi, ekosistem): {'ids', 'severity', 'summary'}} untuk paket yang punya kerentanan."""
    hits = {}
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        r = requests.post('https://api.osv.dev/v1/querybatch', timeout=25, json={
            'queries': [{'package': {'name': n, 'ecosystem': e}, 'version': v} for n, v, e in chunk]})
        r.raise_for_status()
        for key, res in zip(chunk, r.json().get('results', [])):
            ids = [x['id'] for x in (res or {}).get('vulns', []) or []]
            if ids:
                hits[key] = ids
    uniq = list(dict.fromkeys(i for ids in hits.values() for i in ids))[:80]

    def detail(vid):
        try:
            d = requests.get(f'https://api.osv.dev/v1/vulns/{vid}', timeout=10).json()
        except (requests.RequestException, ValueError):
            return vid, ('MODERATE', '')
        sev = str((d.get('database_specific') or {}).get('severity') or 'MODERATE').upper()
        return vid, (sev if sev in SEV_ORDER else 'MODERATE', (d.get('summary') or '')[:160])

    with ThreadPoolExecutor(max_workers=8) as ex:
        details = dict(ex.map(detail, uniq))
    out = {}
    for key, ids in hits.items():
        worst = min((details.get(i, ('MODERATE', '')) for i in ids), key=lambda s: SEV_ORDER.index(s[0]))
        out[key] = {'ids': ids, 'severity': worst[0], 'summary': worst[1]}
    return out


def _registry_exists(name, eco):
    """True/False bila registry menjawab jelas; None bila tidak bisa dipastikan."""
    if eco == 'npm':
        url = 'https://registry.npmjs.org/' + name.replace('/', '%2F')
    else:
        url = f'https://pypi.org/pypi/{name}/json'
    try:
        r = requests.get(url, timeout=6, headers={'Accept': 'application/json'})
    except requests.RequestException:
        return None
    if r.status_code == 404:
        return False
    return True if r.status_code < 400 else None


def _workflow_issues(root):
    issues = []
    wdir = root / '.github' / 'workflows'
    if not wdir.is_dir():
        return issues
    for f in sorted(list(wdir.glob('*.yml')) + list(wdir.glob('*.yaml'))):
        text = _read_text(f) or ''
        rel = f.relative_to(root).as_posix()
        if 'pull_request_target' in text and re.search(r'ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)', text):
            issues.append({'id': 'CI-PRT-CHECKOUT', 'file': rel})
        m = INJECT_RE.search(text)
        if m:
            issues.append({'id': 'CI-SCRIPT-INJECTION', 'file': rel, 'detail': m.group(1)})
        if re.search(r'echo[^\n]*\$\{\{\s*secrets\.', text):
            issues.append({'id': 'CI-SECRET-ECHO', 'file': rel})
        unpinned = sorted({f'{a}@{b}' for a, b in re.findall(r'uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)', text)
                           if not re.fullmatch(r'[0-9a-f]{40}', b) and not a.startswith(('actions/', 'github/'))})
        if unpinned:
            issues.append({'id': 'CI-UNPINNED-ACTION', 'file': rel, 'detail': ', '.join(unpinned[:5])})
        if not re.search(r'^permissions\s*:', text, re.M) or re.search(r'permissions\s*:\s*write-all', text):
            issues.append({'id': 'CI-BROAD-PERMISSIONS', 'file': rel})
    return issues


def _docker_issues(root, files):
    issues = []
    dockerfiles = [p for p in files if p.name == 'Dockerfile' or p.name.startswith('Dockerfile.') or p.name.endswith('.Dockerfile')][:5]
    ignore = _read_text(root / '.dockerignore') or ''
    has_env = any(ENV_FILE_RE.search(p.relative_to(root).as_posix()) and not ENV_SAFE_RE.search(p.name) for p in files)
    for f in dockerfiles:
        text = _read_text(f) or ''
        rel = f.relative_to(root).as_posix()
        users = re.findall(r'^\s*USER\s+(\S+)', text, re.M | re.I)
        if not users or users[-1].lower() in ('root', '0'):
            issues.append({'id': 'DOCKER-ROOT', 'file': rel})
        m = re.search(r'^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[= ]\s*(\S+)', text, re.M | re.I)
        if m and not m.group(2).startswith('$'):
            issues.append({'id': 'DOCKER-SECRET-ENV', 'file': rel, 'detail': m.group(1)})
        if has_env and re.search(r'^\s*(?:COPY|ADD)\s+\.\s+', text, re.M | re.I) and not re.search(r'(^|\n)\s*\.env', ignore):
            issues.append({'id': 'DOCKER-ENV-COPY', 'file': rel})
    return issues


def _code_issues(texts):
    hits = []
    for rel, text in texts:
        if rel.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte')) or ENV_FILE_RE.search(rel):
            for m in PUBLIC_SECRET_RE.finditer(text):
                hits.append({'id': 'PUBLIC-ENV-SECRET', 'file': rel, 'detail': m.group(0)})
        if rel.endswith('.py'):
            if re.search(r'\.run\([^)\n]*debug\s*=\s*True', text):
                hits.append({'id': 'DEBUG-IN-CODE', 'file': rel, 'detail': 'app.run(debug=True)'})
            if rel.endswith('settings.py') and re.search(r'^\s*DEBUG\s*=\s*True\b', text, re.M):
                hits.append({'id': 'DEBUG-IN-CODE', 'file': rel, 'detail': 'DEBUG = True'})
    return hits


def run(path, online=True, history=True, budget=90):
    t0 = time.monotonic()
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        return {'error': f'Folder tidak ditemukan: {root}'}
    out = {'path': str(root), 'git': (root / '.git').exists(), 'online': online, 'files_scanned': 0, 'manifests': [],
           'deps': {'checked': 0, 'vulnerable': [], 'approx': False}, 'missing_packages': [], 'scoped_missing': [],
           'lockfile_missing': [], 'secrets': [], 'history_secrets': [], 'history_partial': False, 'env_files': [],
           'env_files_history': [], 'workflows': [], 'docker': [], 'code': [], 'notes': []}
    files = list(_files(root))
    texts = []
    for p in files:
        if p.name in TEXT_SKIP_NAMES:
            continue
        t = _read_text(p)
        if t is not None:
            texts.append((p.relative_to(root).as_posix(), t))
    out['files_scanned'] = len(texts)

    current = [f for rel, t in texts for f in find_secrets(t, rel)]
    history_found = []
    if out['git'] and history:
        history_found, out['history_partial'] = _history_secrets(root, t0 + budget * 0.6)
        tracked = (_git(root, 'ls-files') or '').splitlines()
        out['env_files'] = [n for n in tracked if ENV_FILE_RE.search(n) and not ENV_SAFE_RE.search(n)]
        added = (_git(root, 'log', '--all', '--diff-filter=A', '--name-only', '--format=') or '').splitlines()
        out['env_files_history'] = sorted({n for n in added if n and ENV_FILE_RE.search(n) and not ENV_SAFE_RE.search(n)} - set(out['env_files']))
    out['secrets'] = _dedupe(current)
    current_keys = {(x['type'], x['masked']) for x in out['secrets']}
    out['history_secrets'] = _dedupe([x for x in history_found if (x['type'], x['masked']) not in current_keys])

    pkgs, direct_npm, direct_py = [], {}, []
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.name == 'package.json':
            try:
                pk, direct, has_lock, approx = _npm_packages(p.parent)
            except (OSError, ValueError):
                continue
            out['manifests'].append(rel)
            pkgs += pk
            direct_npm.update(direct)
            if not has_lock:
                out['lockfile_missing'].append(rel)
            out['deps']['approx'] = out['deps']['approx'] or approx
        elif re.fullmatch(r'requirements.*\.txt', p.name):
            out['manifests'].append(rel)
            for line in (_read_text(p) or '').splitlines():
                if line.strip().startswith(('#', '-')) or '://' in line:
                    continue
                m = REQ_PINNED_RE.match(line)
                if m:
                    pkgs.append((m.group(1), m.group(2), 'PyPI'))
                n = REQ_NAME_RE.match(line)
                if n:
                    direct_py.append(n.group(1))
    pkgs = list(dict.fromkeys(pkgs))[:3000]
    out['deps']['checked'] = len(pkgs)

    if online and pkgs:
        try:
            vulns = _osv_query(pkgs)
        except (requests.RequestException, ValueError) as e:
            vulns = {}
            out['notes'].append(f'OSV.dev tidak dapat dihubungi ({e.__class__.__name__}); dependensi tidak diperiksa.')
        out['deps']['vulnerable'] = sorted(
            [{'name': n, 'version': v, 'ecosystem': e, **info} for (n, v, e), info in vulns.items()],
            key=lambda x: SEV_ORDER.index(x['severity']))
    if online:
        names = [(n, 'npm') for n, spec in direct_npm.items() if not str(spec).startswith(SKIP_SPECS)]
        names += [(n, 'PyPI') for n in direct_py]
        names = list(dict.fromkeys(names))[:150]
        with ThreadPoolExecutor(max_workers=8) as ex:
            checked = list(ex.map(lambda x: (x, _registry_exists(*x)), names))
        for (name, eco), ok in checked:
            if ok is False:
                (out['scoped_missing'] if name.startswith('@') else out['missing_packages']).append({'name': name, 'ecosystem': eco})

    out['workflows'] = _workflow_issues(root)
    out['docker'] = _docker_issues(root, files)
    out['code'] = _code_issues(texts)
    out['duration_s'] = round(time.monotonic() - t0, 1)
    return out


CI_RULES = {
    'CI-PRT-CHECKOUT': (20, 'Tinggi', 'Workflow memakai pull_request_target sambil men-checkout kode dari pull request ({file}).',
                        'Jangan checkout kode PR di pull_request_target; pakai pull_request, atau pisahkan job tanpa akses secret.'),
    'CI-SCRIPT-INJECTION': (15, 'Tinggi', 'Input dari pengguna dipakai langsung di workflow ({file}: {detail}).',
                            'Simpan nilai itu ke variabel env lalu rujuk sebagai "$VAR" di skrip, bukan langsung lewat ekspresi ${{ }}.'),
    'CI-SECRET-ECHO': (10, 'Menengah', 'Workflow mencetak secret ke log ({file}).',
                       'Jangan echo secret; GitHub hanya menyamarkan nilai yang persis sama.'),
    'CI-UNPINNED-ACTION': (3, 'Rendah', 'Action pihak ketiga tidak di-pin ke commit SHA ({file}: {detail}).',
                           'Pin action ke SHA 40 karakter agar perubahan versi tidak masuk diam-diam.'),
    'CI-BROAD-PERMISSIONS': (3, 'Rendah', 'Workflow tidak membatasi permissions token ({file}).',
                             "Tambahkan 'permissions: contents: read' di tingkat atas dan naikkan per job bila perlu."),
}
DOCKER_RULES = {
    'DOCKER-ROOT': (10, 'Menengah', 'Container berjalan sebagai root ({file}).', 'Tambahkan pengguna non-root dan instruksi USER di Dockerfile.'),
    'DOCKER-SECRET-ENV': (15, 'Tinggi', 'Rahasia ditulis langsung di Dockerfile ({file}: {detail}).',
                          'Gunakan secret saat runtime atau build secret, bukan ENV/ARG berisi nilai.'),
    'DOCKER-ENV-COPY': (10, 'Menengah', 'COPY . ikut menyalin file .env ke image ({file}).', 'Tambahkan .env ke .dockerignore.'),
}


def findings(r):
    """Daftar temuan (id, poin, tingkat, teks, rekomendasi, kategori, track, keyakinan)."""
    out = []
    for x in r.get('secrets', []):
        if x.get('severity') == 'critical':
            out.append(('REPO-SECRET', 40, 'Kritis', f"Kunci rahasia di kode: {x['type']} ({x['masked']}, {x['file']}).",
                        'Cabut (revoke) kunci itu, buat yang baru, simpan di variabel lingkungan atau secret manager, lalu hapus dari kode.',
                        'code', 'beginner', x.get('confidence', 'high')))
        else:
            out.append(('REPO-PUBLIC-KEY', 3, 'Rendah', f"Kunci publik di kode: {x['type']} ({x['masked']}, {x['file']}).",
                        'Pastikan kunci ini dibatasi (HTTP referrer, API yang diizinkan, kuota) di konsol penyedianya.', 'code', 'beginner', 'medium'))
    for x in r.get('history_secrets', []):
        if x.get('severity') == 'critical':
            out.append(('REPO-SECRET-HISTORY', 40, 'Kritis',
                        f"Kunci rahasia masih tersimpan di riwayat git: {x['type']} ({x['masked']}, {x['file']}, commit {x.get('commit', '?')}).",
                        'Cabut dan ganti kunci itu. Menghapusnya dari kode terbaru tidak menghapusnya dari riwayat, dan salinannya mungkin sudah tersebar.',
                        'code', 'beginner', x.get('confidence', 'high')))
    for n in r.get('env_files', []):
        out.append(('REPO-ENV-COMMITTED', 40, 'Kritis', f'File {n} ter-commit ke repositori.',
                    'Hapus dari git (git rm --cached), tambahkan ke .gitignore, lalu ganti semua rahasia di dalamnya.', 'code', 'beginner', 'high'))
    for n in r.get('env_files_history', []):
        out.append(('REPO-ENV-HISTORY', 15, 'Tinggi', f'File {n} pernah ter-commit dan masih ada di riwayat git.',
                    'Ganti semua rahasia yang pernah ada di file itu.', 'code', 'beginner', 'high'))
    used, extra = 0, 0
    for d in r.get('deps', {}).get('vulnerable', []):
        level, pts = SEV_POINTS.get(d['severity'], ('Menengah', 5))
        if used + pts > DEP_POINTS_CAP:
            extra += 1
            continue
        used += pts
        summary = f": {d['summary']}" if d.get('summary') else ''
        out.append(('DEP-VULN', pts, level, f"Dependensi rentan: {d['name']} {d['version']} ({d['ecosystem']}, {', '.join(d['ids'][:2])}){summary}.",
                    f"Perbarui {d['name']} ke versi yang sudah diperbaiki (lihat {d['ids'][0]} di osv.dev).", 'code', 'beginner', 'high'))
    if extra:
        out.append(('DEP-VULN-MORE', 0, 'Rendah', f'Ada {extra} dependensi rentan lain (tidak dihitung lagi ke skor agar tidak berlebihan).',
                    'Jalankan npm audit atau pip-audit untuk daftar lengkap.', 'code', 'beginner', 'high'))
    for x in r.get('missing_packages', []):
        out.append(('PKG-NOT-FOUND', 20, 'Tinggi', f"Paket {x['name']} ({x['ecosystem']}) tidak ada di registry publik; nama paket bisa jadi dikarang AI.",
                    'Pastikan nama paket benar. Penyerang bisa mendaftarkan nama yang belum ada lalu menyisipkan kode berbahaya.', 'code', 'beginner', 'high'))
    if r.get('scoped_missing'):
        names = ', '.join(x['name'] for x in r['scoped_missing'][:3])
        out.append(('PKG-SCOPED-PRIVATE', 3, 'Rendah', f'Paket bercakupan tidak ada di registry publik ({names}).',
                    'Bila itu paket privat, pastikan .npmrc mengarah ke registry privat untuk scope tersebut agar tidak terkena dependency confusion.',
                    'code', 'senior', 'medium'))
    if r.get('lockfile_missing'):
        out.append(('LOCKFILE-MISSING', 3, 'Rendah', f"Tidak ada lockfile untuk {', '.join(r['lockfile_missing'][:3])}.",
                    'Commit lockfile (package-lock.json, pnpm-lock.yaml, atau yarn.lock) agar versi dependensi terkunci.', 'code', 'senior', 'high'))
    seen = set()
    for x in r.get('workflows', []):
        if x['id'] in ('CI-UNPINNED-ACTION', 'CI-BROAD-PERMISSIONS') and x['id'] in seen:
            continue
        seen.add(x['id'])
        pts, level, text, rec = CI_RULES[x['id']]
        out.append((x['id'], pts, level, text.format(file=x['file'], detail=x.get('detail', '')), rec, 'code', 'senior',
                    'medium' if x['id'] == 'CI-SCRIPT-INJECTION' else 'high'))
    for x in r.get('docker', []):
        pts, level, text, rec = DOCKER_RULES[x['id']]
        out.append((x['id'], pts, level, text.format(file=x['file'], detail=x.get('detail', '')), rec, 'ops', 'beginner', 'high'))
    seen_vars = set()
    for x in r.get('code', []):
        if x['id'] == 'PUBLIC-ENV-SECRET' and x['detail'] not in seen_vars:
            seen_vars.add(x['detail'])
            out.append(('PUBLIC-ENV-SECRET', 15, 'Tinggi', f"Variabel rahasia diberi awalan publik: {x['detail']} ({x['file']}).",
                        'Variabel berawalan NEXT_PUBLIC_, VITE_, atau REACT_APP_ ikut dikirim ke browser. Hapus awalannya dan pakai hanya di sisi server.',
                        'code', 'beginner', 'high'))
    debug = [x for x in r.get('code', []) if x['id'] == 'DEBUG-IN-CODE']
    if debug:
        out.append(('DEBUG-IN-CODE', 10, 'Menengah', f"Mode debug menyala di kode ({debug[0]['file']}: {debug[0]['detail']}).",
                    'Matikan debug untuk produksi, misalnya lewat variabel lingkungan.', 'code', 'beginner', 'medium'))
    return out


def score(r):
    """Penilaian untuk pemeriksaan repositori saja (tanpa situs)."""
    from scanner import CATEGORY_LABELS, SEVERITY, coverage_info, grade_from
    items, total = [], 100
    for fid, pts, level, text, rec, cat, track, conf in findings(r):
        total -= pts
        items.append({'id': fid, 'finding': f'Risiko {level}: {text}', 'title': text, 'recommendation': rec, 'poin': -pts,
                      'points': -pts, 'level': level, 'severity': SEVERITY[level], 'category': cat, 'track': track, 'confidence': conf})
    total = max(0, total)
    criticals = sum(1 for x in items if x['severity'] == 'critical')
    grade = grade_from(total, criticals)
    if not items:
        items.append({'id': 'NO-ISSUES', 'level': 'Info', 'severity': 'info', 'points': 0, 'category': 'code', 'track': 'beginner',
                      'confidence': 'high', 'finding': 'Tidak ditemukan masalah pada pemeriksaan repositori.',
                      'recommendation': 'Jalankan ulang secara berkala, misalnya di CI.'})
    subscores = {c: (max(0, 100 + sum(x['points'] for x in items if x['category'] == c)) if c in ('code', 'ops') else None)
                 for c in CATEGORY_LABELS}
    return {'score': total, 'grade': grade, 'grade_capped': grade != grade_from(total, 0), 'findings': items,
            'coverage': coverage_info(('repo',)), 'subscores': subscores, 'category_labels': CATEGORY_LABELS}
