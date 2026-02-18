"""Flask web application for the PhishGuard dashboard and API."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

try:
    from flask_cors import CORS
except Exception:  # pragma: no cover
    CORS = None

from phishguard import __version__
from phishguard.bootstrap import MODEL_PATH, VECTORIZER_PATH, ensure_model_artifacts
from phishguard.config import AppConfig
from phishguard.email_analyzer import EmailAnalyzer
from phishguard.ml_classifier import PhishingClassifier
from phishguard.rate_limiter import InMemoryRateLimiter
from phishguard.scorer import ThreatScorer
from phishguard.url_analyzer import URLAnalyzer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_EMAIL_DIR = PROJECT_ROOT / "tests" / "sample_emails"


def create_app(config: AppConfig | None = None) -> Flask:
    """Factory for creating the PhishGuard Flask app."""
    runtime_config = config or AppConfig.from_env()
    ensure_model_artifacts()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=runtime_config.secret_key,
        MAX_CONTENT_LENGTH=runtime_config.max_content_length_bytes,
        JSON_SORT_KEYS=False,
    )

    if runtime_config.enable_cors and CORS is not None:
        CORS(
            app,
            resources={r"/api/*": {"origins": runtime_config.cors_origins.split(",")}},
        )

    _configure_logging(app, runtime_config.log_level)

    url_analyzer = URLAnalyzer()
    email_analyzer = EmailAnalyzer()
    scorer = ThreatScorer()
    classifier = PhishingClassifier()
    limiter = InMemoryRateLimiter(
        limit=runtime_config.rate_limit_requests,
        window_seconds=runtime_config.rate_limit_window_seconds,
    )

    app.config["PHISHGUARD_START_TIME"] = time.time()

    @app.before_request
    def _before_request():
        g.request_started_at = time.perf_counter()
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]

        if request.path.startswith("/api/"):
            client_ip = _resolve_client_ip()
            allowed, retry_after = limiter.is_allowed(client_ip)
            if not allowed:
                return _json_error(
                    "Rate limit exceeded. Please retry shortly.",
                    status_code=429,
                    retry_after=retry_after,
                )
        return None

    @app.after_request
    def _after_request(response):
        _apply_security_headers(response, is_secure=request.is_secure)

        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"

        request_id = getattr(g, "request_id", None)
        if request_id:
            response.headers["X-Request-ID"] = request_id

        started = getattr(g, "request_started_at", None)
        duration_ms = 0.0
        if started is not None:
            duration_ms = (time.perf_counter() - started) * 1000.0

        app.logger.info(
            "%s %s status=%s duration_ms=%.2f ip=%s",
            request.method,
            request.path,
            response.status_code,
            duration_ms,
            _resolve_client_ip(),
        )

        return response

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc: HTTPException):
        if request.path.startswith("/api/"):
            return _json_error(exc.description, status_code=exc.code or 500)
        return exc

    @app.errorhandler(Exception)
    def _handle_unexpected_exception(exc: Exception):
        app.logger.exception("Unhandled exception", exc_info=exc)
        if request.path.startswith("/api/"):
            return _json_error("Internal server error.", status_code=500)
        return render_template("index.html"), 500

    @app.get("/")
    def index() -> str:
        """Render dashboard page."""
        return render_template("index.html")

    @app.get("/healthz")
    def healthz():
        """Liveness endpoint for container/process health checks."""
        uptime_seconds = int(time.time() - app.config.get("PHISHGUARD_START_TIME", time.time()))
        return jsonify(
            {
                "status": "ok",
                "service": "phishguard",
                "version": __version__,
                "uptime_seconds": uptime_seconds,
            }
        )

    @app.get("/readyz")
    def readyz():
        """Readiness endpoint that verifies model artifacts are available."""
        ready = bool(MODEL_PATH.exists() and VECTORIZER_PATH.exists())
        status_code = 200 if ready else 503
        return (
            jsonify(
                {
                    "ready": ready,
                    "model_artifact": MODEL_PATH.name,
                    "vectorizer_artifact": VECTORIZER_PATH.name,
                }
            ),
            status_code,
        )

    @app.post("/api/analyze")
    def analyze_content():
        """Analyze URL or email content and return full scoring payload."""
        if not request.is_json:
            return _json_error("Request body must be JSON.", status_code=400)

        payload = request.get_json(silent=True)
        analysis_type, content, error_message = _validate_analysis_payload(payload, runtime_config)
        if error_message is not None:
            return _json_error(error_message, status_code=400)

        if analysis_type == "url":
            heuristic_result = url_analyzer.analyze(content)
            ml_result = classifier.predict(content)
        else:
            heuristic_result = email_analyzer.analyze(content)
            ml_input = heuristic_result.get("body") or content
            ml_result = classifier.predict(str(ml_input))

        score_result = scorer.calculate_score(heuristic_result, ml_result)

        return jsonify(
            {
                "type": analysis_type,
                "input": content,
                "heuristic": heuristic_result,
                "ml": ml_result,
                "score": score_result,
                "meta": {
                    "request_id": getattr(g, "request_id", None),
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                    "version": __version__,
                },
            }
        )

    @app.get("/api/samples")
    def get_samples():
        """Return sample URL and email payloads for instant demos."""
        phishing_email = _read_optional_text(SAMPLE_EMAIL_DIR / "phishing_example.txt")
        legitimate_email = _read_optional_text(SAMPLE_EMAIL_DIR / "legitimate_example.txt")

        return jsonify(
            {
                "phishing_url": "http://secure-paypa1-account.xyz/login/verify?session=281922",
                "safe_url": "https://www.amazon.com/gp/css/order-history",
                "phishing_email": phishing_email,
                "legitimate_email": legitimate_email,
            }
        )

    return app


def _configure_logging(app: Flask, level_name: str) -> None:
    """Configure structured console logging."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    root_logger = logging.getLogger()

    if not root_logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    root_logger.setLevel(level)
    app.logger.setLevel(level)


def _resolve_client_ip() -> str:
    """Resolve best-effort client IP from proxy headers or remote address."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return (request.remote_addr or "unknown").strip()


def _validate_analysis_payload(
    payload: Any,
    config: AppConfig,
) -> tuple[str, str, str | None]:
    """Validate and normalize API analyze payload."""
    if not isinstance(payload, dict):
        return "", "", "Request JSON must be an object."

    analysis_type = str(payload.get("type", "")).strip().lower()
    content = str(payload.get("content", "")).strip()

    if analysis_type not in {"url", "email"}:
        return "", "", "Invalid type. Use 'url' or 'email'."

    if not content:
        return "", "", "Content is required."

    if analysis_type == "url" and len(content) > config.max_url_length:
        return "", "", f"URL content exceeds {config.max_url_length} characters."

    if analysis_type == "email" and len(content) > config.max_email_length:
        return "", "", f"Email content exceeds {config.max_email_length} characters."

    return analysis_type, content, None


def _json_error(message: str, status_code: int, retry_after: int | None = None):
    """Build a consistent API JSON error response."""
    response = jsonify(
        {
            "error": message,
            "request_id": getattr(g, "request_id", None),
        }
    )
    response.status_code = status_code

    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)

    return response


def _apply_security_headers(response, is_secure: bool) -> None:
    """Attach baseline web-security headers."""
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';",
    )

    if is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


def _read_optional_text(file_path: Path) -> str:
    """Read UTF-8 text file if present, otherwise return empty string."""
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
