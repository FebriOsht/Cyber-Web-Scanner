# VERSI DEBUG - JANGAN DIUBAH
print(">>> tasks.py versi DEBUG termuat! Pastikan pesan ini muncul di terminal Celery. <<<")

from celery import Celery
import os
import requests
from bs4 import BeautifulSoup
import json
import traceback

# Nonaktifkan peringatan SSL (Direkomendasikan)
requests.packages.urllib3.disable_warnings() 

# Inisialisasi Celery
# Ambil URL Redis dari environment variable (Render) atau fallback ke localhost jika di lokal
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery = Celery(
    "tasks",
    broker=redis_url,
    backend=redis_url
)

@celery.task(bind=True)
def run_full_scan_task(self, url):
    try:
        result = run_full_scan(url)
        print(f"[TASK SUCCESS] Done scanning: {url}")
        return result
    except Exception as e:
        return {"error": str(e)}

# =======================================================
# FUNGSI-FUNGSI PEMBANTU UNTUK PEMINDAIAN
# =======================================================

def check_security_headers(url, session):
    headers_to_check = {
        'Content-Security-Policy': 'Penting untuk mencegah serangan XSS.',
        'Strict-Transport-Security': 'Memaksa koneksi HTTPS.',
        'X-Content-Type-Options': 'Mencegah MIME-sniffing.',
        'X-Frame-Options': 'Mencegah clickjacking.',
    }
    found_headers, missing_headers = {}, {}
    try:
        response = session.get(url, timeout=10, verify=False)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        for header, desc in headers_to_check.items():
            if header.lower() in response_headers:
                found_headers[header] = response_headers[header.lower()]
            else:
                missing_headers[header] = desc
        return {'ditemukan': found_headers, 'tidak_ditemukan': missing_headers}
    except requests.exceptions.RequestException as e:
        return {'error': f"Gagal terhubung: {e}"}

def find_tech_info(url, session):
    tech_info = {}
    try:
        response = session.get(url, timeout=10, verify=False)
        headers = response.headers
        if 'Server' in headers: tech_info['Server'] = headers['Server']
        if 'X-Powered-By' in headers: tech_info['Powered-By'] = headers['X-Powered-By']
        soup = BeautifulSoup(response.text, 'html.parser')
        generator_tag = soup.find('meta', {'name': 'generator'})
        if generator_tag and 'content' in generator_tag.attrs:
            tech_info['Generator (CMS)'] = generator_tag['content']
        return tech_info
    except requests.exceptions.RequestException as e:
        return {'error': f"Gagal mengambil info teknologi: {e}"}

def check_robots_txt(url, session):
    robots_url = url.rstrip('/') + "/robots.txt"
    try:
        response = session.get(robots_url, timeout=10, verify=False)
        if response.status_code == 200:
            paths = [line for line in response.text.splitlines() if line.strip().lower().startswith(('disallow:', 'allow:'))]
            return {'ditemukan': True, 'paths': paths, 'status_code': 200}
        return {'ditemukan': False, 'status_code': response.status_code}
    except requests.exceptions.RequestException:
        return {'ditemukan': False, 'error': "Gagal mengakses robots.txt"}

def check_exposed_git(url, session):
    git_url = url.rstrip('/') + "/.git/HEAD"
    try:
        response = session.get(git_url, timeout=10, verify=False)
        if response.status_code in [200, 403]:
            return {'ditemukan': True, 'status_code': response.status_code}
        return {'ditemukan': False}
    except requests.exceptions.RequestException:
        return {'ditemukan': False}

def check_mixed_content(url, session):
    mixed_content_list = []
    try:
        response = session.get(url, timeout=10, verify=False)
        if not url.startswith('https://'):
            return {'ditemukan': False}
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http://'):
                mixed_content_list.append(src)
        if mixed_content_list:
            return {'ditemukan': True, 'urls': mixed_content_list}
        return {'ditemukan': False}
    except requests.exceptions.RequestException:
        return {'ditemukan': False}

def calculate_security_score(results):
    score = 100
    findings_with_recs = []

    if results.get('exposed_git_info', {}).get('ditemukan'):
        score -= 50
        findings_with_recs.append({
            'finding': "Risiko Kritis: Direktori .git terekspos.",
            'recommendation': "Segera hapus direktori .git dari server hosting Anda. Ini sangat berbahaya karena dapat membocorkan seluruh kode sumber."
        })
    
    missing_headers = results.get('security_headers', {}).get('tidak_ditemukan', {})
    if 'Strict-Transport-Security' in missing_headers:
        score -= 15
        findings_with_recs.append({
            'finding': "Risiko Tinggi: Header Strict-Transport-Security (HSTS) hilang.",
            'recommendation': "Tambahkan header 'Strict-Transport-Security' di file .htaccess atau konfigurasi server untuk memaksa koneksi selalu HTTPS."
        })
    if 'X-Frame-Options' in missing_headers:
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Header X-Frame-Options hilang.",
            'recommendation': "Tambahkan header 'X-Frame-Options' di file .htaccess untuk melindungi website dari serangan clickjacking."
        })
    if 'X-Content-Type-Options' in missing_headers:
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Header X-Content-Type-Options hilang.",
            'recommendation': "Tambahkan header 'X-Content-Type-Options' di file .htaccess untuk mencegah serangan MIME-sniffing."
        })

    if results.get('technology_info', {}).get('Powered-By'):
        score -= 5
        findings_with_recs.append({
            'finding': "Risiko Rendah: Informasi versi PHP (X-Powered-By) terekspos.",
            'recommendation': "Sembunyikan header 'X-Powered-By' melalui konfigurasi server (php.ini) untuk mengurangi jejak informasi."
        })

    if results.get('mixed_content_info', {}).get('ditemukan'):
        score -= 10
        findings_with_recs.append({
            'finding': "Risiko Menengah: Ditemukan Mixed Content.",
            'recommendation': "Pastikan semua aset (gambar, skrip, css) dimuat melalui HTTPS. Ubah URL dari 'http://' menjadi 'https://'."
        })

    grade = "A"
    if score < 60: grade = "F"
    elif score < 70: grade = "D"
    elif score < 80: grade = "C"
    elif score < 90: grade = "B"

    if not findings_with_recs:
        findings_with_recs.append({
            'finding': "Konfigurasi Keamanan Baik!",
            'recommendation': "Tidak ada masalah keamanan dasar yang ditemukan. Tetap perbarui perangkat lunak Anda."
        })

    return {'score': max(0, score), 'grade': grade, 'findings': findings_with_recs}

# =======================================================
# TUGAS UTAMA CELERY (SATU DEFINISI YANG BERSIH)
# =======================================================

@celery.task
def run_full_scan_task(target_url):
    """Menjalankan seluruh pemindaian di latar belakang."""
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'CyberWebScanner/1.0'})

        scan_results = {
            'target': target_url,
            'security_headers': check_security_headers(target_url, session),
            'technology_info': find_tech_info(target_url, session),
            'robots_txt_info': check_robots_txt(target_url, session),
            'exposed_git_info': check_exposed_git(target_url, session),
            'mixed_content_info': check_mixed_content(target_url, session),
        }
        
        # Pengecekan error di dalam hasil fungsi pembantu
        for key, value in scan_results.items():
            if isinstance(value, dict) and 'error' in value:
                # Jika salah satu sub-fungsi gagal (misal Gagal terhubung), kembalikan error task
                raise requests.exceptions.RequestException(value['error'])


        score_data = calculate_security_score(scan_results)
        scan_results['score_info'] = score_data
        
        return scan_results # Return hasil sukses
    
    except Exception as e:
        # Menangkap SEMUA error (termasuk RequestException yang kita raise di atas)
        print("\n==============================")
        print("!!! KESALAHAN KRITIS DI CELERY TASK !!!")
        print(f"Tipe Error: {type(e).__name__}")
        print(f"Pesan Error: {str(e)}")
        print(f"TARGET: {target_url}")
        print("TRACEBACK LENGKAP:")
        traceback.print_exc()
        print("==============================\n")
        
        # Solusi Paling Aman: return dictionary error. 
        # Flask akan melihat task.successful() == True dan membaca kunci 'error' ini.
        return {
            'error': f"Gagal menjalankan pemindaian (Task Internal). Kesalahan: {type(e).__name__}: {str(e)}. Cek log Celery worker.",
            'target': target_url

        }


