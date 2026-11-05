"""GET /status: one call for the header bar (kill switch, audit head, model, link, outbox).
GET /whoami: the signed-in Keycloak user when the package is behind UDS Authservice."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.util import CtxDep

router = APIRouter(tags=["status"], route_class=MappedRoute)


@router.get("/status")
def get_status(ctx=CtxDep) -> dict:
    st = ctx.status()
    st["link"] = util.link_state(ctx)
    st["outbox"] = {"pending": util.outbox_pending(ctx)}
    return st


@router.get("/whoami")
def whoami(request: Request, ctx=CtxDep) -> dict:
    mode = ctx.settings.auth_mode.strip().lower()
    if mode != "mesh":
        return {"mode": "dev", "authenticated": False, "actor": None, "subject": None, "issuer": None, "username": None}
    from cyberthunder.api.auth import AuthError, authenticate
    try:
        principal = authenticate(request, ctx.settings)
        actor = util._human_actor(principal.actor)
    except AuthError as e:
        raise HTTPException(401, str(e)) from None
    return {
        "mode": "mesh",
        "authenticated": True,
        "actor": actor,
        "subject": principal.subject,
        "issuer": principal.issuer,
        "username": principal.username,
    }
