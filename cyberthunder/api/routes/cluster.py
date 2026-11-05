"""Cluster survey, Trivy baseline scans, and namespace risk profiles."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from cyberthunder.api.errors import MappedRoute, requires
from cyberthunder.api.util import ActorDep, CtxDep, to_plain

router = APIRouter(prefix="/cluster", tags=["cluster"], route_class=MappedRoute)


class BaselineBody(BaseModel):
    target_id: str | None = None
    use_openai: bool = False


def _svc(ctx):
    return requires(getattr(ctx, "cluster", None), "cluster baseline")


@router.get("/survey")
def survey(target_id: str | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return to_plain(_svc(ctx).survey(actor=actor, target_id=target_id))


@router.post("/baseline")
def baseline(body: BaselineBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or BaselineBody()
    return to_plain(_svc(ctx).scan(actor=actor, target_id=body.target_id, use_openai=body.use_openai))


@router.get("/risk")
def risk(ctx=CtxDep) -> dict:
    latest = _svc(ctx).latest()
    if latest is None:
        return {"generated_at": None, "namespaces": [], "errors": ["no cluster baseline has been generated"]}
    return {"id": latest.get("id"), "generated_at": latest.get("generated_at"),
            "requested_by": latest.get("requested_by"), "target": latest.get("target"),
            "namespaces": latest.get("namespaces") or [], "errors": latest.get("errors") or []}
