# scanner.py
import requests
from bs4 import BeautifulSoup
import pprint
import urllib3

# Disable insecure warnings (karena verify=False dipakai)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- MODUL 1: PENGECEKAN HEADER KEAMANAN ---
def check_security_headers(url, session):
    headers_to_check = {
        'Content-Security-Policy': 'Penting untuk mencegah serangan XSS.',
        'Strict-Transport-Security': 'Memaksa koneksi HTTPS.',
        'X-Content-Type-Options': 'Mencegah MIME-sniffing.',
        'X-Frame-Options': 'Mencegah clickjacking.',
    }
    found_headers = {}
    missing_headers = {}
    try:
        response = session.get(url, timeout=10, verify=False)
        response_headers = {k: v for k, v in response.headers.items()}

        for header, description in headers_to_check.items():
            if header in response_headers:
                found_headers[header] = response_headers[header]
            else:
                missing_headers[header] = description

        return {'ditemukan': found_headers, 'tidak_ditemukan': missing_headers}
    except requests.exceptions.RequestException as e:
        return {'error': f"Tidak dapat terhubung. Error: {e}"}

# --- MODUL 2: PENCARIAN INFORMASI TEKNOLOGI ---
def find_tech_info(url, session):
    tech_info = {}
    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers

        if 'Server' in headers:
            tech_info['Server'] = headers['Server']
        if 'X-Powered-By' in headers:
            tech_info['Powered-By'] = headers['X-Powered-By']

        soup = BeautifulSoup(response.text, 'html.parser')
        generator_tag = soup.find('meta', {'name': 'generator'})
        if generator_tag and 'content' in generator_tag.attrs:
            tech_info['Generator (CMS)'] = generator_tag['content']

        return tech_info
    except requests.exceptions.RequestException as e:
        return {'error': f"Tidak dapat mengambil informasi. Error: {e}"}

# --- MODUL 3: PENGECEKAN ROBOTS.TXT ---
def check_robots_txt(url, session):
    robots_url = url.rstrip('/') + "/robots.txt"
    try:
        response = session.get(robots_url, timeout=10, verify=False)
        if response.status_code == 200:
            paths = [line for line in response.text.splitlines() if line.strip().lower().startswith(('disallow:', 'allow:'))]
            return {'ditemukan': True, 'paths': paths}
        else:
            return {'ditemukan': False, 'status_code': response.status_code}
    except requests.exceptions.RequestException as e:
        return {'ditemukan': False, 'error': f"Tidak dapat mengakses robots.txt. Error: {e}"}

# --- MODUL 4: PENGECEKAN DIREKTORI .GIT ---
def check_exposed_git(url, session):
    git_url = url.rstrip('/') + "/.git/HEAD"
    try:
        response = session.get(git_url, timeout=10, verify=False)
        if response.status_code in (200, 403):
            return {'ditemukan': True, 'status_code': response.status_code, 'level_risiko': 'Kritis'}
        else:
            return {'ditemukan': False}
    except requests.exceptions.RequestException:
        return {'ditemukan': False}

# --- MODUL 6: PENGECEKAN MIXED CONTENT ---
def check_mixed_content(url, session):
    mixed_content_list = []
    try:
        response = session.get(url, timeout=10, verify=False)
        if not url.startswith('https://'):
            return {'ditemukan': False, 'status': 'Bukan situs HTTPS'}

        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http://'):
                mixed_content_list.append(src)

        if mixed_content_list:
            return {'ditemukan': True, 'urls': mixed_content_list, 'level_risiko': 'Menengah'}
        else:
            return {'ditemukan': False}
    except requests.exceptions.RequestException:
        return {'ditemukan': False, 'error': 'Gagal mengambil halaman'}

# --- MODUL 5: PERHITUNGAN SKOR KEAMANAN ---
def calculate_security_score(results):
    score = 100
    findings_with_recs = []

    # Pengecekan .git
    if results.get('exposed_git_info', {}).get('ditemukan'):
        score -= 50
        findings_with_recs.append({
            'finding': "Risiko Kritis: Direktori .git terekspos.",
            'recommendation': "Segera hapus direktori .git dari server hosting Anda."
        })

    # Header keamanan
    missing_headers = results.get('security_headers', {}).get('tidak_ditemukan', {})
    if 'Strict-Transport-Security' in missing_headers:
        score -= 15
        findings_with_recs.append({
            'finding': "Risiko Tinggi: Header Strict-Transport-Security (HSTS) hilang.",
            'recommendation': "Tambahkan header 'Strict-Transport-Security'."
        })
    if 'X-Frame-Options' in missing_headers:
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Header X-Frame-Options hilang.",
            'recommendation': "Tambahkan header 'X-Frame-Options'."
        })
    if 'X-Content-Type-Options' in missing_headers:
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Header X-Content-Type-Options hilang.",
            'recommendation': "Tambahkan header 'X-Content-Type-Options'."
        })

    # Teknologi ter-expose
    tech_info = results.get('technology_info', {})
    if 'Powered-By' in tech_info and tech_info['Powered-By']:
        score -= 5
        findings_with_recs.append({
            'finding': "Risiko Rendah: Informasi versi PHP (X-Powered-By) terekspos.",
            'recommendation': "Sembunyikan header 'X-Powered-By'."
        })

    # Pengecekan Mixed Content (pastikan block ini sebelum return)
    if results.get('mixed_content_info', {}).get('ditemukan'):
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Ditemukan Mixed Content.",
            'recommendation': "Pastikan semua aset dimuat lewat HTTPS."
        })

    # Konversi skor ke grade
    grade = "A"
    if score < 60:
        grade = "F"
    elif score < 70:
        grade = "D"
    elif score < 80:
        grade = "C"
    elif score < 90:
        grade = "B"

    if not findings_with_recs:
        findings_with_recs.append({
            'finding': "Konfigurasi Keamanan Baik!",
            'recommendation': "Tidak ada masalah keamanan dasar yang ditemukan."
        })

    return {'score': max(0, score), 'grade': grade, 'findings': findings_with_recs}

# --- FUNGSI UTAMA ---
def run_full_scan(target_url):
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url

    session = requests.Session()
    session.headers.update({'User-Agent': 'MySecurityScanner/1.0'})

    scan_results = {
        'target': target_url,
        'security_headers': check_security_headers(target_url, session),
        'technology_info': find_tech_info(target_url, session),
        'robots_txt_info': check_robots_txt(target_url, session),
        'exposed_git_info': check_exposed_git(target_url, session),
        'mixed_content_info': check_mixed_content(target_url, session)
    }

    score_data = calculate_security_score(scan_results)
    
    # PERBAIKAN: Masukkan hasil skor ke dalam kunci 'score_info'
    scan_results["score_info"] = score_data 
    
    # CATATAN: Hapus kunci 'score', 'grade', dan 'findings' yang di-update di root jika Anda tidak memerlukannya.
    # Karena app.py mengharapkan 'score_info', kita hanya menambahkan itu.

    pprint.pprint(scan_results)
    return scan_results


if __name__ == "__main__":
    target_website = "darmajaya.ac.id"
    results = run_full_scan(target_website)
    pprint.pprint(results)



