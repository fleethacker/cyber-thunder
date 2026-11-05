"""Cluster survey, Trivy baseline scans, and namespace risk profiles."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from cyberthunder.api.errors import MappedRoute, requires
from cyberthunder.api.util import ActorDep, CtxDep, to_plain

router = APIRouter(prefix="/cluster", tags=["cluster"], route_class=MappedRoute)


class BaselineBody(BaseModel):
    use_openai: bool = False


def _svc(ctx):
    return requires(getattr(ctx, "cluster", None), "cluster baseline")


@router.get("/survey")
def survey(ctx=CtxDep) -> dict:
    return to_plain(_svc(ctx).survey())


@router.post("/baseline")
def baseline(body: BaselineBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return to_plain(_svc(ctx).scan(use_openai=bool((body or BaselineBody()).use_openai)))


@router.get("/risk")
def risk(ctx=CtxDep) -> dict:
    latest = _svc(ctx).latest()
    if latest is None:
        return {"generated_at": None, "namespaces": [], "errors": ["no cluster baseline has been generated"]}
    return {"id": latest.get("id"), "generated_at": latest.get("generated_at"),
            "namespaces": latest.get("namespaces") or [], "errors": latest.get("errors") or []}
