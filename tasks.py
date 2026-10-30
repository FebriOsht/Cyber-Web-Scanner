# tasks.py - worker Celery (opsional). Logika scan HANYA ada di scanner.py.
import os
from celery import Celery
from scanner import run_full_scan

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery = Celery('tasks', broker=redis_url, backend=redis_url)


@celery.task(bind=True)
def run_full_scan_task(self, url):
    try:
        return run_full_scan(url)
    except Exception as e:
        return {'error': f'{e.__class__.__name__}: {e}'}