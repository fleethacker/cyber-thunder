"""`cyberthunder serve`: run the API and the built UI from one offline process."""
from __future__ import annotations

import argparse
import os


def cmd_serve(a: argparse.Namespace) -> int:
    from cyberthunder.config import Settings

    settings = Settings.from_env(state_dir=a.state_dir)
    host = a.host or settings.host
    port = a.port or settings.port
    from cyberthunder.api.auth import validate_bind
    validate_bind(settings, host)
    if a.reload:
        if settings.auth_mode != "dev":
            raise ValueError("reload is available only with development authentication")
        # the reloader re-imports the app in a child process, so state comes through the environment
        import uvicorn

        os.environ["CT_STATE_DIR"] = str(settings.state_dir)
        uvicorn.run("cyberthunder.api.app:create_app", factory=True, reload=True, host=host, port=port,
                    log_level="info", ssl_certfile=settings.tls_cert, ssl_keyfile=settings.tls_key,
                    proxy_headers=False)
        return 0
    from cyberthunder.api.app import serve
    from cyberthunder.context import AppContext

    serve(host=host, port=port, ctx=AppContext(settings))
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("serve", help="run the HTTP API and the operator UI")
    p.add_argument("--host", help="bind address (default CT_HOST or 127.0.0.1)")
    p.add_argument("--port", type=int, help="port (default CT_PORT or 8000)")
    p.add_argument("--reload", action="store_true", help="restart on code changes (development only)")
    p.set_defaults(fn=cmd_serve)
