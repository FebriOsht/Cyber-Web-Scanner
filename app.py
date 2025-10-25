from flask import Flask, render_template, request, make_response # <<-- PERBAIKAN 1: Menambahkan make_response
import os
from datetime import datetime
from database import init_db, add_scan_result, get_all_scans

# Tentukan jalur absolut ke folder 'templates'
# os.path.dirname(os.path.abspath(__file__)) mendapatkan path direktori 'src'
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir) 

print("TEMPLATE_FOLDER (Explicitly Set):", app.template_folder)

# =======================
# HALAMAN UTAMA
# =======================
@app.route('/')
def index():
    return render_template('index.html')

# =======================
# JALANKAN PEMINDAIAN (langsung tanpa Celery)
# =======================
@app.route("/scan", methods=["POST"])
def scan():
    try:
        url = request.form["url"]

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        from scanner import run_full_scan
        result = run_full_scan(url)

        # Simpan hasil ke database
        try:
        # PERBAIKAN: Ambil score dan grade langsung dari 'result'
        score = result.get("score", 0) 
        grade = result.get("grade", "N/A")
        
        add_scan_result(url, score, grade, result)
    except Exception as e:
        print(f"[DB ERROR] {e}")

        # Tampilkan hasil di halaman
        # PERBAIKAN 2: Mengganti "result.html" menjadi "scan_result.html" untuk menghindari konflik cache/case-sensitivity di Render
        return render_template("scan_result.html", results=result)

    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        
        # Mengembalikan string HTML murni dengan kode 500
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Kesalahan Server</title></head>
        <body>
            <h1>❌ TERJADI KESALAHAN INTERNAL SERVER (500)</h1>
            <p><strong>TIPE ASLI:</strong> {error_type}</p>
            <p><strong>DETAIL ASLI:</strong> {error_detail}</p>
            <a href="/">Kembali ke Halaman Utama</a>
        </body>
        </html>
        """
        # make_response memastikan response memiliki status 500
        return make_response(html_content, 500) # <<-- make_response sekarang sudah terdefinisi

# =======================
# HALAMAN RIWAYAT PEMINDAIAN
# =======================
@app.route('/history')
def history():
    scans = get_all_scans()
    scans_list = [
        {
            "id": row["id"],
            "url": row["url"],
            "scan_date": row["scan_date"],
            "score": row["score"],
            "grade": row["grade"]
        }
        for row in scans
    ]
    return render_template("history.html", scans=scans_list)

# =======================
# HALAMAN DOKUMENTASI
# =======================
@app.route('/docs')
def docs():
    return render_template('docs.html', datetime=datetime)

# =======================
# JALANKAN APP
# =======================
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode)

