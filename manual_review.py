"""Lembar telaah manual: area yang tidak aman atau tidak mungkin diuji otomatis dari luar."""

CHECKLIST = (
    {'id': 'access-control', 'title': 'Kontrol akses antar-pengguna (IDOR)', 'track_label': 'Senior',
     'questions': ('Setiap endpoint yang menerima ID memeriksa bahwa objek itu milik pengguna yang login.',
                   'Pengguna biasa tidak bisa memanggil endpoint atau aksi milik admin.',
                   'Data milik tim atau organisasi lain tidak bisa dibaca dengan mengganti ID di URL atau body.'),
     'evidence': 'pengujian dengan dua akun uji milik sendiri, atau pemeriksaan kode untuk filter pemilik di setiap query.'},
    {'id': 'auth', 'title': 'Login, reset kata sandi, dan sesi', 'track_label': 'Pemula',
     'questions': ('Tautan reset kata sandi dibuat dari alamat situs yang tetap, bukan dari header Host permintaan.',
                   'Token reset hanya berlaku sekali dan kedaluwarsa dalam waktu singkat.',
                   'Sesi diganti (dirotasi) setelah login, dan logout benar-benar membatalkan sesi di server.',
                   'Cookie sesi memakai Secure, HttpOnly, dan SameSite, serta tidak berlaku untuk seluruh subdomain bila tidak perlu.'),
     'evidence': 'konfigurasi autentikasi dan hasil uji manual alur reset kata sandi.'},
    {'id': 'rate-limit', 'title': 'Pembatasan percobaan (rate limiting)', 'track_label': 'Pemula',
     'questions': ('Login, reset kata sandi, OTP, dan pendaftaran dibatasi jumlah percobaannya per akun dan per IP.',
                   'Ada penundaan atau CAPTCHA setelah beberapa kegagalan.',
                   'Endpoint mahal (AI, ekspor, kirim email) punya kuota per pengguna.'),
     'evidence': 'konfigurasi pembatas di server, gateway, atau layanan seperti Cloudflare/Vercel Firewall.'},
    {'id': 'webhooks', 'title': 'Webhook dan pembayaran', 'track_label': 'Senior',
     'questions': ('Setiap webhook (Midtrans, Xendit, PayPal, Stripe) memverifikasi tanda tangan sebelum diproses.',
                   'Status pembayaran dicek ulang ke penyedia, bukan hanya dipercaya dari data yang dikirim browser.',
                   'Webhook yang sama tidak diproses dua kali (idempoten).'),
     'evidence': 'kode handler webhook dan log pemrosesan.'},
    {'id': 'business-logic', 'title': 'Logika bisnis dan race condition', 'track_label': 'Senior',
     'questions': ('Kupon, saldo, kuota, dan stok tidak bisa dipakai ganda lewat permintaan paralel.',
                   'Langkah dalam alur (checkout, verifikasi, persetujuan) tidak bisa dilompati.',
                   'Harga dan jumlah dihitung ulang di server, bukan diambil dari browser.'),
     'evidence': 'transaksi atau kunci database pada operasi saldo dan stok, serta pengujian alur.'},
    {'id': 'ssrf', 'title': 'Fitur yang mengambil URL dari pengguna', 'track_label': 'Senior',
     'questions': ('Fitur impor URL, webhook keluar, atau proxy gambar menolak alamat privat, loopback, dan 169.254.169.254.',
                   'Jumlah redirect dan ukuran respons dibatasi.'),
     'evidence': 'kode validasi URL; lihat ssrf_guard.py di repositori ini sebagai contoh.'},
    {'id': 'data', 'title': 'Data pribadi, log, dan audit', 'track_label': 'Senior',
     'questions': ('Kata sandi, token, dan data pribadi tidak tercatat di log.',
                   'Aksi admin (hapus, ubah peran, ekspor data) tercatat di audit log.',
                   'Data pribadi dikumpulkan seperlunya dan ada kebijakan privasi sesuai UU PDP.'),
     'evidence': 'contoh baris log, tabel audit, dan kebijakan privasi.'},
    {'id': 'backup', 'title': 'Backup dan pemulihan', 'track_label': 'Pemula',
     'questions': ('Backup database berjalan otomatis dan disimpan di luar server utama.',
                   'Backup terenkripsi dan aksesnya dibatasi.',
                   'Pemulihan dari backup pernah benar-benar diuji.'),
     'evidence': 'jadwal backup, lokasi penyimpanan, dan catatan uji pemulihan terakhir.'},
    {'id': 'secrets', 'title': 'Pengelolaan rahasia dan akses', 'track_label': 'Pemula',
     'questions': ('Semua kunci API disimpan di variabel lingkungan atau secret manager, bukan di kode.',
                   'Akun admin dan layanan (hosting, database, domain, email) memakai autentikasi dua faktor.',
                   'Kunci yang pernah bocor sudah dicabut, dan akses mantan anggota tim sudah dicabut.'),
     'evidence': 'daftar variabel lingkungan (tanpa nilai) dan pengaturan 2FA tiap layanan.'},
)


def to_markdown():
    lines = ['# Lembar telaah manual (Cyber Web Scanner)', '',
             'Area berikut tidak aman atau tidak mungkin diuji otomatis dari luar. Jawab bersama tim, lalu centang yang sudah dipastikan.', '']
    for area in CHECKLIST:
        lines.append(f"## {area['title']} ({area['track_label']})")
        lines.append('')
        lines += [f'- [ ] {q}' for q in area['questions']]
        lines += ['', f"Bukti yang perlu ada: {area['evidence']}", '']
    return '\n'.join(lines)
