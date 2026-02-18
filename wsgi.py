"""WSGI entrypoint for production servers (e.g., Gunicorn)."""

from __future__ import annotations

from phishguard.bootstrap import ensure_model_artifacts
from web.app import create_app

ensure_model_artifacts()
app = create_app()
