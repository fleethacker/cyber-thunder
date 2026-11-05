"""Cluster survey, Trivy baseline scans, and namespace risk profiles."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from cyberthunder.adapters.kubernetes.known_good import KubernetesKnownGoodState
from cyberthunder.api.errors import MappedRoute, requires
from cyberthunder.api.schemas import KnownGoodBody, KnownGoodFromFindingBody
from cyberthunder.api.util import ActorDep, CtxDep, get_finding, to_plain

router = APIRouter(prefix="/cluster", tags=["cluster"], route_class=MappedRoute)


class BaselineBody(BaseModel):
    target_id: str | None = None
    use_openai: bool = False


def _svc(ctx):
    return requires(getattr(ctx, "cluster", None), "cluster baseline")


def _known_good(ctx) -> KubernetesKnownGoodState:
    return KubernetesKnownGoodState(ctx.store)


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


@router.get("/known-good")
def known_good(ctx=CtxDep) -> dict:
    return {"exceptions": [e.to_dict() for e in _known_good(ctx).list()]}


@router.post("/known-good/exceptions", status_code=201)
def add_known_good(body: KnownGoodBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    target = ctx.inventory.get(body.target_id)
    if target.asset_type != "kubernetes":
        raise ValueError(f"target {target.id!r} is a {target.asset_type} target, not kubernetes")
    item = _known_good(ctx).add(actor=actor, reason=body.reason, target_id=body.target_id, rule_id=body.rule_id,
                                rule_version=body.rule_version, group_id=body.group_id, object=body.object,
                                object_prefix=body.object_prefix, expires_at=body.expires_at)
    ctx.audit.append("known_good.add", actor, item.to_dict(), subject=item.id)
    return item.to_dict()


@router.post("/known-good/from-finding/{finding_id}", status_code=201)
def add_known_good_from_finding(finding_id: str, body: KnownGoodFromFindingBody, ctx=CtxDep,
                                actor: str = ActorDep) -> dict:
    finding = get_finding(ctx, finding_id)
    item = _known_good(ctx).add_from_finding(finding, actor=actor, reason=body.reason, scope=body.scope,
                                             expires_at=body.expires_at)
    ctx.audit.append("known_good.add", actor, item.to_dict(), subject=item.id)
    return item.to_dict()


@router.delete("/known-good/exceptions/{exception_id}", status_code=204)
def delete_known_good(exception_id: str, ctx=CtxDep, actor: str = ActorDep) -> None:
    if not _known_good(ctx).delete(exception_id):
        raise KeyError(f"unknown known-good exception {exception_id!r}")
    ctx.audit.append("known_good.delete", actor, {"id": exception_id}, subject=exception_id)
