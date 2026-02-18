"""Startup helpers for model artifact bootstrapping."""

from __future__ import annotations

import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "phishing_model.pkl"
VECTORIZER_PATH = PROJECT_ROOT / "models" / "tfidf_vectorizer.pkl"
LOCK_PATH = PROJECT_ROOT / "models" / ".training.lock"


def ensure_model_artifacts(timeout_seconds: int = 300) -> None:
    """Ensure model/vectorizer artifacts exist, training if missing."""
    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        return

    lock_handle = _acquire_lock(timeout_seconds=timeout_seconds)
    if lock_handle is None:
        raise RuntimeError("Timed out waiting for model training lock.")

    try:
        if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
            return

        print("[*] Model artifacts not found. Training model now...")
        from phishguard.train_model import train_and_save_model

        train_and_save_model()
    finally:
        try:
            os.close(lock_handle)
        except OSError:
            pass
        if LOCK_PATH.exists():
            try:
                LOCK_PATH.unlink()
            except OSError:
                pass


def _acquire_lock(timeout_seconds: int) -> int | None:
    """Acquire a cross-process lock file for one-time model training."""
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(1, timeout_seconds)

    while time.monotonic() < deadline:
        try:
            return os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            time.sleep(0.25)

    return None
