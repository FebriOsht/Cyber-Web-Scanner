#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt

# Inisialisasi database (idempotent)
python database.py || true

echo "Build complete."
