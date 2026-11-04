"""Discovery API: scopes, sweeps, candidate assets, accept/ignore, findings and applicability.

Mutating routes need a named human actor (X-Actor); accept is the only way a discovered asset enters
the inventory. Errors map to: kill switch 423, bad input or machine actor at the edge 400, unknown id 404, refused actor
in the service 403.
"""
from __future__ import annotations

from typing import Callable, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from cyberthunder.api.util import require_actor
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.discovery.service import DiscoveryService, require_human, service_for

router = APIRouter(prefix="/discovery", tags=["discovery"])
T = TypeVar("T")


class ScopeIn(BaseModel):
    cidr: str
    allow_public: bool = False
    scanner_target: str | None = None


class ScopesIn(BaseModel):
    scopes: list[ScopeIn] = Field(default_factory=list)
    reason: str = ""


class SweepIn(BaseModel):
    scopes: list[str] | None = None
    mode: str = "quick"


class AcceptIn(BaseModel):
    name: str | None = None
    asset_type: str | None = None
    transport: str | None = None
    username: str | None = None
    credential_ref: str | None = None
    in_scope: bool
    reason: str = ""


class IgnoreIn(BaseModel):
    reason: str = ""


def _svc(request: Request) -> DiscoveryService:
    return service_for(request.app.state.ctx)


def _human(actor: str) -> str:
    """Same rule as the service (bare and prefixed machine identities), rejected here as 400."""
    try:
        return require_human(actor)
    except PermissionError:
        raise HTTPException(400, f"a named operator is required for this action (got {(actor or '').strip() or 'none'!r})") from None


def _call(fn: Callable[[], T]) -> T:
    try:
        return fn()
    except KillSwitchEngaged as e:
        raise HTTPException(423, str(e)) from None
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except KeyError as e:
        raise HTTPException(404, str(e.args[0]) if e.args else "not found") from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


@router.get("")
def overview(request: Request):
    svc = _svc(request)
    last = svc.last_run()
    return {"scopes": [s.to_dict() for s in svc.scopes()], "last_run": last.to_dict() if last else None,
            "counts": svc.counts()}


@router.put("/scopes")
def put_scopes(body: ScopesIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    svc = _svc(request)
    saved = _call(lambda: svc.set_scopes([s.model_dump() for s in body.scopes], actor, body.reason))
    return {"scopes": [s.to_dict() for s in saved]}


@router.post("/sweep", status_code=202)
def post_sweep(body: SweepIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    svc = _svc(request)
    return _call(lambda: svc.sweep(scopes=body.scopes, mode=body.mode, actor=actor, background=True)).to_dict()


@router.get("/runs")
def get_runs(request: Request):
    return [r.to_dict() for r in _svc(request).runs()]


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request):
    svc = _svc(request)
    return _call(lambda: dict(svc.get_run(run_id).to_dict(), assets=[a.to_dict() for a in svc.run_assets(run_id)]))


@router.get("/assets")
def get_assets(request: Request, status: str | None = Query(default=None)):
    if status is not None and status not in ("new", "known", "ignored", "missing"):
        raise HTTPException(400, f"unknown status {status!r}")
    return [a.to_dict() for a in _svc(request).list_assets(status)]


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, request: Request):
    svc = _svc(request)
    return _call(lambda: svc.get_asset(asset_id).to_dict())


@router.post("/assets/{asset_id}/accept")
def accept_asset(asset_id: str, body: AcceptIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    svc = _svc(request)
    return _call(lambda: svc.accept(asset_id, actor, name=body.name, asset_type=body.asset_type,
                                    transport=body.transport, username=body.username,
                                    credential_ref=body.credential_ref, in_scope=body.in_scope,
                                    reason=body.reason)).to_dict()


@router.post("/assets/{asset_id}/ignore")
def ignore_asset(asset_id: str, body: IgnoreIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    svc = _svc(request)
    return _call(lambda: svc.ignore(asset_id, actor, body.reason)).to_dict()


@router.get("/findings")
def get_findings(request: Request, run_id: str | None = Query(default=None)):
    svc = _svc(request)
    return [f.to_dict() for f in _call(lambda: svc.findings(run_id))]


@router.get("/applicable")
def get_applicable(request: Request, benchmark: str | None = Query(default=None),
                   title: str | None = Query(default=None), product: str | None = Query(default=None)):
    svc = _svc(request)
    return _call(lambda: svc.applicable(benchmark_id=benchmark, title=title, product=product))
