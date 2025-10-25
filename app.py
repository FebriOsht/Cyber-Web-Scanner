from flask import Flask, render_template, request, make_response, redirect, url_for # <<-- PERBAIKAN 1: Menambahkan make_response
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
# app.py

@app.route("/scan", methods=["POST"])
def scan():
    try:
        # PERBAIKAN: Ambil URL dari form permintaan
        url = request.form["url"]

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        # 1. PENTING: Import tugas Celery.
        from tasks import run_full_scan_task
        
        # 2. Mulai tugas asinkron
        task = run_full_scan_task.delay(url)
        
        # 3. Langsung redirect ke halaman pengecekan status
        return redirect(url_for('get_result', task_id=task.id))

    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        
        # ... (Penanganan error yang sama)
        html_content = f"""..."""
        return make_response(html_content, 500)

# =======================
# JALUR 2: CEK STATUS PEMINDAIAN ASINKRON
# =======================
@app.route('/result/<task_id>')
def get_result(task_id):
    # PENTING: Impor tugas Celery
    from tasks import run_full_scan_task 
    
    task = run_full_scan_task.AsyncResult(task_id)

    if task.state == 'PENDING' or task.state == 'STARTED':
        # Tugas belum selesai. Render halaman status/loading.
        # Catatan: Asumsi file loading page Anda bernama 'status.html'
        return render_template('status.html', task_id=task_id) 
        
    elif task.state == 'SUCCESS':
        # Tugas berhasil. Tampilkan hasilnya.
        results = task.result 
        return render_template('scan_result.html', results=results)
        
    else:
        # Tugas gagal (FAILURE)
        error_info = getattr(task.info, 'exc_message', str(task.info))
        
        # Menggunakan HTML murni untuk error, atau render error_page.html jika Anda punya
        return make_response(f"Pemindaian Gagal. Detail: {error_info}", 500)
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

# app.py




