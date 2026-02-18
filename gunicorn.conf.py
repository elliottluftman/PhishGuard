"""Gunicorn configuration for production deployment."""

from __future__ import annotations

import multiprocessing
import os

bind = f"{os.getenv('PHISHGUARD_HOST', '0.0.0.0')}:{os.getenv('PHISHGUARD_PORT', '5001')}"
workers = int(os.getenv("PHISHGUARD_WORKERS", str(max(2, multiprocessing.cpu_count() // 2))))
threads = int(os.getenv("PHISHGUARD_THREADS", "4"))
timeout = int(os.getenv("PHISHGUARD_TIMEOUT", "60"))
graceful_timeout = int(os.getenv("PHISHGUARD_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("PHISHGUARD_KEEPALIVE", "5"))
worker_class = "gthread"
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("PHISHGUARD_LOG_LEVEL", "info").lower()
