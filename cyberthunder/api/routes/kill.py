"""Kill switch: status, engage, release. Engaging blocks every apply and rollback until released."""
from __future__ import annotations

from fastapi import APIRouter

from cyberthunder.api.errors import MappedRoute
from cyberthunder.api.schemas import ReasonBody
from cyberthunder.api.util import ActorDep, CtxDep

router = APIRouter(tags=["kill"], route_class=MappedRoute)


@router.get("/kill")
def kill_status(ctx=CtxDep) -> dict:
    return ctx.killswitch.status()


@router.post("/kill/engage")
def engage(body: ReasonBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    ctx.killswitch.engage(actor, (body or ReasonBody()).reason or "")
    return ctx.killswitch.status()


@router.post("/kill/release")
def release(body: ReasonBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    ctx.killswitch.release(actor, (body or ReasonBody()).reason or "")
    return ctx.killswitch.status()
