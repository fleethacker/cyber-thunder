"""FastAPI dependencies."""
from __future__ import annotations

from fastapi import Header, Request

from cyberthunder.context import AppContext


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_actor(x_actor: str | None = Header(default=None)) -> str:
    """Who is acting. Prototype identity: the X-Actor header set by the UI. Never 'agent' for human edges."""
    actor = (x_actor or "").strip()
    return actor or "operator"
