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
        url = request.form.get("url")

        # Jika input URL kosong
        if not url:
            return redirect(url_for('index'))

        # Tambahkan protokol otomatis jika user lupa
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        # Timeout ditangani di level requests (timeout=8 per modul) —
        # signal.alarm dihapus karena crash di Gunicorn/multi-thread (Render).
        from scanner import run_full_scan
        result = run_full_scan(url)

        # Simpan hasil ke database
        try:
            score = result.get("score_info", {}).get("score", 0)
            grade = result.get("score_info", {}).get("grade", "N/A")
            add_scan_result(url, score, grade, result)
        except Exception as e:
            print(f"[DB ERROR] {e}")

        # Tampilkan hasil akhir
        return render_template("scan_result.html", results=result)

    # <<-- TAMBAHAN: Tangkap error timeout secara khusus
    except ScanTimeoutError:
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Scan Timeout</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px; background:#f4f4f4;">
            <div style="display:inline-block; background:white; padding:30px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                <h1 style="color:#e67e22;">⏱️ PROSES SCAN TERLALU LAMA</h1>
                <p>Website yang kamu scan membutuhkan waktu terlalu lama untuk merespons (melebihi 25 detik).</p>
                <p style="color:#888; font-size:13px;">Tips: Pastikan URL yang kamu masukkan dapat diakses dan coba lagi.</p>
                <br>
                <a href="/" style="text-decoration:none; color:#3498db; font-weight:bold;">← Kembali ke Beranda</a>
            </div>
        </body>
        </html>
        """
        return make_response(html_content, 504)

    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        
        # Tampilan Error 500 yang lebih informatif jika terjadi crash pada scanner
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Kesalahan Server</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px; background:#f4f4f4;">
            <div style="display:inline-block; background:white; padding:30px; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
                <h1 style="color:#e74c3c;">❌ TERJADI KESALAHAN INTERNAL (500)</h1>
                <p>Gagal memproses pemindaian untuk URL tersebut.</p>
                <div style="text-align:left; background:#eee; padding:10px; font-family:monospace; font-size:12px;">
                    <strong>Tipe:</strong> {error_type}<br>
                    <strong>Detail:</strong> {error_detail}
                </div>
                <br>
                <a href="/" style="text-decoration:none; color:#3498db; font-weight:bold;">← Kembali ke Beranda</a>
            </div>
        </body>
        </html>
        """
        return make_response(html_content, 500)

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
