"""FastAPI application factory. Routers live in cyberthunder/api/routes/<name>.py and expose `router`.
The built UI (cyberthunder/ui/dist) is served from the same process so the whole thing runs offline."""
from __future__ import annotations

import importlib
import logging
import time
from pathlib import Path

from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from cyberthunder import PRODUCT, __version__
from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"
# Fixed list: a new feature area adds a module here and nowhere else.
ROUTE_MODULES = ("status", "targets", "scans", "findings", "proposals", "audit", "kill", "policy", "cluster",
                 "ingest", "reports", "demo", "discovery", "workflow", "finding_reviews", "vulnerabilities", "scap_results")


def create_app(ctx: AppContext | None = None) -> FastAPI:
    app = FastAPI(title=PRODUCT, version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.owns_context = ctx is None
    app.state.ctx = ctx if ctx is not None else AppContext()
    app.state.runtime_tasks = None
    def release(timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0, timeout)
        tasks = app.state.runtime_tasks
        if tasks is not None and not tasks.stop(max(0, deadline - time.monotonic())):
            log.warning("Runtime shutdown timed out; context remains open for retry")
            return False
        if app.state.owns_context and not app.state.ctx.close(max(0, deadline - time.monotonic())):
            log.warning("Context shutdown timed out; state remains open for retry")
            return False
        return True

    app.state.close = release

    @app.on_event("startup")
    def _startup_runtime_tasks() -> None:
        try:
            from cyberthunder.runtime import RuntimeTasks
            tasks = RuntimeTasks(app.state.ctx)
            app.state.runtime_tasks = tasks
            tasks.start()
        except BaseException:
            release()
            raise

    @app.on_event("shutdown")
    def _shutdown_runtime_tasks() -> None:
        release()

    try:
        _configure_app(app)
    except BaseException:
        release()
        raise
    return app


def _configure_app(app: FastAPI) -> None:
    from cyberthunder.api.errors import register_error_handlers
    register_error_handlers(app)

    for name in ROUTE_MODULES:
        try:
            mod = importlib.import_module(f"cyberthunder.api.routes.{name}")
        except ModuleNotFoundError as e:
            if e.name and e.name.endswith(name):
                log.debug("route module not present: %s", name)
                continue
            raise
        from cyberthunder.api.access import authorize_request
        app.include_router(mod.router, prefix=API_PREFIX, dependencies=[Depends(authorize_request)])

    from cyberthunder.api.auth import install_auth
    install_auth(app, app.state.ctx)

    dist = Path(app.state.ctx.settings.ui_dist)
    if (dist / "index.html").exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="ui")
    else:
        @app.get("/", response_class=HTMLResponse, include_in_schema=False)
        def _placeholder():
            return f"<h1>{PRODUCT} {__version__}</h1><p>UI not built. API docs at <a href='/api/docs'>/api/docs</a>.</p>"


def serve(host: str | None = None, port: int | None = None, ctx: AppContext | None = None) -> None:
    import uvicorn
    owned = ctx is None
    ctx = ctx if ctx is not None else AppContext()
    app = None
    try:
        from cyberthunder.api.auth import validate_bind
        bind = host or ctx.settings.host
        validate_bind(ctx.settings, bind)
        app = create_app(ctx)
        app.state.owns_context = owned
        uvicorn.run(app, host=bind, port=port or ctx.settings.port, log_level="info",
                    ssl_certfile=ctx.settings.tls_cert, ssl_keyfile=ctx.settings.tls_key, proxy_headers=False,
                    workers=1)
    finally:
        if app is not None:
            app.state.close()
        elif owned:
            ctx.close()
