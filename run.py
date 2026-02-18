"""Entry point for running the PhishGuard dashboard."""

from __future__ import annotations

from phishguard.bootstrap import ensure_model_artifacts
from phishguard.config import AppConfig


def print_banner(port: int) -> None:
    """Print the startup banner for the dashboard."""
    banner = r"""
    ____  __    _      __    ______                     __
   / __ \/ /_  (_)____/ /_  / ____/_  ______ __________/ /
  / /_/ / __ \/ / ___/ __ \/ / __/ / / / __ `/ ___/ __  /
 / ____/ / / / (__  ) / / / /_/ / /_/ / /_/ / /  / /_/ /
/_/   /_/ /_/_/____/_/ /_/\____/\__,_/\__,_/_/   \__,_/
"""
    print(banner)
    print("[*] PhishGuard v1.1")
    print(f"[*] Dashboard: http://localhost:{port}")
    print("[*] Press Ctrl+C to stop")


def _serve_with_waitress(app, config: AppConfig) -> bool:
    """Serve using Waitress when available."""
    try:
        from waitress import serve  # type: ignore
    except Exception:
        return False

    serve(
        app,
        host=config.host,
        port=config.port,
        threads=config.waitress_threads,
        connection_limit=config.waitress_connection_limit,
    )
    return True


def main() -> None:
    """Run PhishGuard with production-friendly defaults."""
    config = AppConfig.from_env()
    ensure_model_artifacts()

    from web.app import create_app

    app = create_app(config=config)
    print_banner(config.port)

    if config.use_waitress and not config.debug:
        if _serve_with_waitress(app, config):
            return
        print("[!] Waitress is not installed. Falling back to Flask built-in server.")

    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
