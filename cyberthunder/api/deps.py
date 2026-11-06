"""FastAPI dependencies."""
from __future__ import annotations

from fastapi import Header, Request

from cyberthunder.context import AppContext


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_actor(x_actor: str | None = Header(default=None)) -> str:
    """Who is acting. Prototype identity: the X-Actor header set by the UI. Empty when absent, so routes
    that change state can refuse the request; read-only routes may fall back to 'operator' for their audit lines."""
    from cyberthunder.control.principal import current_principal
    principal = current_principal()
    return principal.actor if principal is not None and principal.verified else (x_actor or "").strip()
