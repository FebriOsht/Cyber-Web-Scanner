from flask import Flask, render_template, request, make_response, redirect, url_for
import os
from datetime import datetime
import math
import signal  # <<-- TAMBAHAN: untuk timeout handling
from database import init_db, add_scan_result, get_all_scans

PER_PAGE = 20
# Tentukan jalur absolut ke folder 'templates'
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir)

# init_db saat start: tabel dibuat otomatis (aman dipanggil berulang)
try:
    init_db()
except Exception as e:
    print(f'[DB INIT ERROR] {e}')

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'self'; form-action 'self'; object-src 'none'")


@app.after_request
def security_headers(resp):
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resp.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    resp.headers.setdefault('Content-Security-Policy', CSP)
    return resp 

# <<-- TAMBAHAN: Class dan handler untuk timeout
class ScanTimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise ScanTimeoutError("Proses scan melebihi batas waktu 25 detik")

# =======================
# ENDPOINT UNTUK UPTIMEROBOT
# =======================
@app.route('/ping')
def ping():
    """Gunakan URL ini di UptimeRobot: https://cyberwebscanner.onrender.com/ping"""
    return "OK", 200

# =======================
# HALAMAN UTAMA
# =======================
@app.route('/')
def index():
    return render_template('index.html')

# =======================
# JALANKAN PEMINDAIAN
# =======================
@app.route("/scan", methods=["GET", "POST"])
def scan():
    # JIKA DIAKSES VIA GET (Misal: UptimeRobot atau User mengetik manual URL /scan)
    # Kita alihkan ke halaman utama agar tidak muncul Internal Server Error (500)
    if request.method == "GET":
        return redirect(url_for('index'))

    # JIKA DIAKSES VIA POST (User menekan tombol Scan)
    try:
        url = (request.form.get("url") or "").strip()

        # Jika input URL kosong
        if not url:
            return redirect(url_for('index'))


        # Timeout ditangani di level requests (timeout=8 per modul) —
        # signal.alarm dihapus karena crash di Gunicorn/multi-thread (Render).
        from scanner import run_full_scan
        result = run_full_scan(url)

        # Simpan hasil ke database
        try:
            score = result.get("score_info", {}).get("score", 0)
            grade = result.get("score_info", {}).get("grade", "N/A")
            add_scan_result(result.get("target", url), score, grade, result)
        except Exception as e:
            print(f"[DB ERROR] {e}")

        # Tampilkan hasil akhir
        return render_template("scan_result.html", results=result)

    except Exception as e:
        print(f"[SCAN ERROR] {type(e).__name__}: {e}")
        return render_template(
            "scan_result.html",
            error="Pemindaian gagal diproses. Pastikan URL benar dan website dapat diakses, lalu coba lagi."
        ), 500

# =======================
# HALAMAN RIWAYAT PEMINDAIAN
# =======================
@app.route('/history')
def history():
    # Ambil nomor halaman dari parameter URL (?page=1)
    page = request.args.get('page', 1, type=int) 
    
    # Ambil semua data dari database
    all_scans = get_all_scans() 
    
    if all_scans is None:
        all_scans = []
        
    total_scans = len(all_scans)
    offset = (page - 1) * PER_PAGE
    
    # Potong data sesuai halaman (Pagination)
    scans_for_page = all_scans[offset:offset + PER_PAGE]

    # Hitung total halaman yang dibutuhkan
    total_pages = math.ceil(total_scans / PER_PAGE) if total_scans > 0 else 0
    
    # Konversi data ke format list dictionary untuk template
    scans_list = [
        {
            "id": row["id"],
            "url": row["url"],
            "scan_date": row["scan_date"],
            "score": row["score"],
            "grade": row["grade"]
        }
        for row in scans_for_page
    ]
    
    return render_template("history.html", 
                           scans=scans_list,
                           page=page,
                           total_pages=total_pages)

# =======================
# HALAMAN DOKUMENTASI
# =======================
@app.route('/.well-known/security.txt')
def security_txt():
    import datetime as dt
    exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')
    body = (f"Contact: mailto:xfunctionoverride000@gmail.com\n"
            f"Expires: {exp}\n"
            f"Preferred-Languages: id, en\n"
            f"Canonical: {request.url_root}.well-known/security.txt\n")
    resp = make_response(body)
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return resp


@app.route('/robots.txt')
def robots_txt():
    body = "User-agent: *\nAllow: /\nDisallow: /scan\nDisallow: /history\n"
    resp = make_response(body)
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return resp

@app.route('/docs')
def docs():
    return render_template('docs.html', datetime=datetime)

# =======================
# KONFIGURASI JALANKAN APLIKASI
# =======================
if __name__ == "__main__":
    init_db()
    # Port dinamis untuk Render (default 5000 jika lokal)
    port = int(os.environ.get("PORT", 5000))
    # Matikan debug=True jika sudah stabil untuk menghemat resource
    app.run(host="0.0.0.0", port=port, debug=False)
