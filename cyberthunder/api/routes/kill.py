"""Kill switch: status, engage, release. Engaging blocks every apply and rollback until released.

Engaging is the one change that does not wait for a name: an operator on a fresh browser must be able to stop
the agent at once. The audit line then reads 'unidentified operator' with the client address. Machine
identities are still refused, and releasing always needs a named person."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.schemas import ReasonBody
from cyberthunder.api.util import ActorDep, CtxDep, require_actor

router = APIRouter(tags=["kill"], route_class=MappedRoute)


@router.get("/kill")
def kill_status(ctx=CtxDep) -> dict:
    return ctx.killswitch.status()


def engage_actor(request: Request, x_actor: str | None = Header(default=None)) -> str:
    from cyberthunder.control.principal import current_principal
    principal = current_principal()
    if principal is not None and principal.verified:
        return principal.actor
    if not (x_actor or "").strip():
        host = request.client.host if request.client else "unknown address"
        return f"unidentified operator ({host})"
    return require_actor(x_actor)


@router.post("/kill/engage")
def engage(body: ReasonBody | None = None, ctx=CtxDep, actor: str = Depends(engage_actor)) -> dict:
    ctx.killswitch.engage(actor, (body or ReasonBody()).reason or "")
    return ctx.killswitch.status()


@router.post("/kill/release")
def release(body: ReasonBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    ctx.killswitch.release(actor, (body or ReasonBody()).reason or "")
    return ctx.killswitch.status()
