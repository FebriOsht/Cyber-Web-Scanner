# database.py
import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.getcwd(), "scans.db")

def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    """Membuat tabel database jika belum ada."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scan_date TEXT,
            score INTEGER,
            grade TEXT,
            full_report TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_scan_result(url, score, grade, full_report):
    """Menambahkan hasil pemindaian baru ke database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    report_json = json.dumps(full_report, ensure_ascii=False)
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO scans (url, scan_date, score, grade, full_report) VALUES (?, ?, ?, ?, ?)",
        (url, scan_date, score, grade, report_json)
    )
    conn.commit()
    conn.close()

def get_all_scans():
    """Mengambil semua riwayat pemindaian dari database.""" 
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    scans = cursor.fetchall()
    conn.close()
    return scans

if __name__ == "__main__":
    init_db()
    print("Database inisialisasi selesai.")
