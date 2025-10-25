from flask import Flask, render_template, request
import os
from datetime import datetime
from database import init_db, add_scan_result, get_all_scans

app = Flask(__name__)

print("TEMPLATE_FOLDER:", os.path.join(os.getcwd(), "templates"))

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
            score = result.get("score_info", {}).get("score", 0)
            grade = result.get("score_info", {}).get("grade", "N/A")
            add_scan_result(url, score, grade, result)
        except Exception as e:
            print(f"[DB ERROR] {e}")

        # Tampilkan hasil di halaman
        return render_template("result.html", results=result)

    except Exception as e:
        return render_template("error_page.html", error=str(e))

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

