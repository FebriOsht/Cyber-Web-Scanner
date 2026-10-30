# Dibaca otomatis oleh gunicorn dari folder kerja.
timeout = 90
graceful_timeout = 30
worker_class = "gthread"
workers = 1
threads = 4