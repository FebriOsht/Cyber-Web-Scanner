from flask import Flask, render_template, request
from tasks import celery, run_full_scan_task
import sqlite3
import os
from datetime import datetime
from database import init_db, add_scan_result, get_all_scans

app = Flask(__name__)

# =======================
# HALAMAN UTAMA
# =======================
@app.route('/')
def index():
    return render_template('index.html')


# =======================
# JALANKAN PEMINDAIAN
# =======================
@app.route('/scan', methods=['POST'])
def scan():
    url_to_scan = request.form['url'].strip()

    # Validasi input
    if not url_to_scan:
        return render_template("results.html", results=None, error="URL tidak boleh kosong.")

    if not url_to_scan.startswith("http://") and not url_to_scan.startswith("https://"):
        url_to_scan = "https://" + url_to_scan

    if url_to_scan in ["https://", "http://"]:
        return render_template("results.html", results=None, error="URL tidak memiliki domain yang valid.")

    # Jalankan task Celery
    task = run_full_scan_task.delay(url_to_scan)
    return render_template('status.html', task_id=task.id)


# =======================
# TAMPILKAN HASIL PEMINDAIAN
# =======================
# app.py

@app.route('/result/<task_id>')
def get_result(task_id):
    task = celery.AsyncResult(task_id)

    if not task.ready():
        return render_template('status.html', task_id=task_id)

    if task.successful():
        result = task.result

        if isinstance(result, dict) and 'error' in result:
            error_message = result['error']
            return render_template("results.html", results=None, error=error_message)

        if result:
            # Ambil data dari hasil scanner
            url = result.get('target', 'Unknown')
            score = result.get('score_info', {}).get('score', 0)
            grade = result.get('score_info', {}).get('grade', 'N/A')

            # Simpan hasil ke database menggunakan helper dari database.py
            try:
                add_scan_result(url, score, grade, result)
            except Exception as e:
                print(f"[DB ERROR] {e}")

        return render_template("results.html", results=result, error=None)
    else:
        error_message = f"Pemindaian gagal di latar belakang. Info: {str(task.info)}"
        return render_template("results.html", results=None, error=error_message)


# Catatan: Tidak ada kode di bawah blok if/else ini, karena semua jalur mengakhiri dengan 'return'


# =======================
# HALAMAN RIWAYAT PEMINDAIAN
# =======================
@app.route('/history')
def history():
    scans = get_all_scans()
    # Konversi row ke dict agar template bisa baca
    scans_list = []
    for row in scans:
        scans_list.append({
            "id": row["id"],
            "url": row["url"],
            "scan_date": row["scan_date"],
            "score": row["score"],
            "grade": row["grade"]
        })
    return render_template("history.html", scans=scans_list)

@app.route('/docs')
def docs():
    return render_template('docs.html', datetime=datetime)


# =======================
# JALANKAN APP
# =======================
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
