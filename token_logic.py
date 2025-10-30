import sqlite3

# Nama file database privat
DB_TOKENS = 'tokens.db'

def get_db_connection():
    """Membuat koneksi ke database tokens."""
    conn = sqlite3.connect(DB_TOKENS)
    conn.row_factory = sqlite3.Row
    return conn

def init_tokens_db():
    """Menginisialisasi tabel tokens dan menambahkan token uji."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Membuat tabel tokens untuk menyimpan kuota
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT UNIQUE NOT NULL,
            quota INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tambahkan token uji: Token ini memiliki kuota awal 50x scan
    TEST_TOKEN = 'SECURE-TOKEN-DEMO-123'
    INITIAL_QUOTA = 50
    try:
        cursor.execute("INSERT INTO tokens (token, quota) VALUES (?, ?)", (TEST_TOKEN, INITIAL_QUOTA))
        conn.commit()
        print(f"\n[INFO] Token Uji '{TEST_TOKEN}' ditambahkan ke tokens.db dengan kuota {INITIAL_QUOTA}.\n")
    except sqlite3.IntegrityError:
        # Token sudah ada, lewati
        pass
        
    conn.close()

def decrement_token_quota(token_key):
    """
    Memvalidasi token dan mengurangi kuota sebesar 1 secara atomik.
    Mengembalikan True jika kuota berhasil dikurangi, False jika kuota habis atau token tidak valid.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Cek dan Kurangi Kuota dalam satu query (Transaksi Atomik)
        # Query ini hanya akan berhasil jika token ada DAN kuota > 0
        cursor.execute("UPDATE tokens SET quota = quota - 1 WHERE token = ? AND quota > 0", (token_key,))
        
        # 2. Periksa apakah ada baris yang terpengaruh (kuota berkurang)
        success = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return success
    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"[TOKEN DB ERROR] Rollback: {e}")
        return False

def get_current_quota(token_key):
    """Mendapatkan sisa kuota saat ini dari suatu token."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT quota FROM tokens WHERE token = ?", (token_key,))
    result = cursor.fetchone()
    conn.close()
    return result['quota'] if result else -1 # Mengembalikan -1 jika token tidak ditemukan
