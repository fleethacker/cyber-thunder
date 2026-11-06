"""Discovery API: scopes, sweeps, candidate assets, accept/ignore, findings and applicability.

Configuration/acceptance routes require a human actor. Target-specific vSphere collection also
permits an authenticated analyst workload with explicit account access. Accept is the only way a
global discovered asset enters inventory; source snapshots never accept assets. Errors map to kill
switch 423, bad input 400, unknown id 404, authorization refusal 403 and source publication failure 503.
"""
from __future__ import annotations

from typing import Callable, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from cyberthunder.api.util import require_actor
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.discovery.service import DiscoveryService, require_human, service_for
from cyberthunder.discovery.recipes import ScopeRevisionConflict
from cyberthunder.discovery.vsphere_runs import VsphereRuns
from cyberthunder.discovery.sources.vsphere_client import VsphereError

router = APIRouter(prefix="/discovery", tags=["discovery"])
T = TypeVar("T")


class ScopeIn(BaseModel):
    cidr: str
    allow_public: bool = False
    scanner_target: str | None = None


class ScopesIn(BaseModel):
    scopes: list[ScopeIn] = Field(default_factory=list)
    reason: str = ""
    acknowledge_normalization: StrictBool = False


class ScopeRangesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include: list[str] = Field(max_length=128)
    exclude: list[str] = Field(default_factory=list, max_length=128)
    allow_public: StrictBool = False
    scanner_target: str | None = Field(default=None, max_length=64)
    acknowledge_normalization: StrictBool = False


class SaveScopeRangesIn(ScopeRangesIn):
    reason: str = Field(min_length=1, max_length=1000)


class ScopeRecipeIn(ScopeRangesIn):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=80)
    include: list[str] | None = Field(max_length=128)
    exclude: list[str] | None = Field(max_length=128)


class ScopeRecipesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: str = Field(min_length=1, max_length=64)
    recipes: list[ScopeRecipeIn] = Field(max_length=128)


class SaveScopeRecipesIn(ScopeRecipesIn):
    preview_fingerprint: str = Field(min_length=64, max_length=64)
    reason: str = Field(min_length=1, max_length=1000)


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
    except ScopeRevisionConflict as e:
        raise HTTPException(409, str(e)) from None
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
    saved = _call(lambda: svc.set_scopes([s.model_dump() for s in body.scopes], actor, body.reason,
                                       acknowledge_normalization=body.acknowledge_normalization))
    return {"scopes": [s.to_dict() for s in saved]}


@router.post("/scopes/preview")
def preview_scope_ranges(body: ScopeRangesIn):
    from cyberthunder.discovery.ranges import preview_ranges
    return _call(lambda: preview_ranges(**body.model_dump()))


@router.get("/scopes/recipes")
def get_scope_recipes(request: Request):
    return _call(lambda: _svc(request).scope_recipes())


@router.post("/scopes/recipes/preview")
def preview_scope_recipes(body: ScopeRecipesIn, request: Request):
    return _call(lambda: _svc(request).preview_scope_recipes([r.model_dump() for r in body.recipes], body.revision))


@router.put("/scopes/recipes")
def save_scope_recipes(body: SaveScopeRecipesIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    return _call(lambda: _svc(request).save_scope_recipes([r.model_dump() for r in body.recipes], body.revision,
                                                        body.preview_fingerprint, actor, body.reason))


@router.put("/scopes/ranges")
def save_scope_ranges(body: SaveScopeRangesIn, request: Request, actor: str = Depends(require_actor)):
    from cyberthunder.discovery.ranges import preview_ranges
    actor = _human(actor)
    data = body.model_dump(exclude={"reason"})
    preview = _call(lambda: preview_ranges(**data))
    if not preview["can_save"]:
        raise HTTPException(400, "; ".join(preview["blocking_reasons"]))
    svc = _svc(request)
    scopes = [{"cidr": cidr, "allow_public": body.allow_public, "scanner_target": body.scanner_target}
              for cidr in preview["networks"]]
    saved = _call(lambda: svc.set_scopes(scopes, actor, body.reason, range_input=data))
    return {"scopes": [s.to_dict() for s in saved], "preview": preview}


@router.post("/sweep", status_code=202)
def post_sweep(body: SweepIn, request: Request, actor: str = Depends(require_actor)):
    actor = _human(actor)
    svc = _svc(request)
    return _call(lambda: svc.sweep(scopes=body.scopes, mode=body.mode, actor=actor, background=True)).to_dict()


@router.get("/runs")
def get_runs(request: Request):
    return [r.to_dict() for r in _svc(request).runs()]


@router.post("/vsphere/{target_id}/collect")
def collect_vsphere(target_id: str, request: Request, actor: str = Depends(require_actor)):
    try:
        return _call(lambda: VsphereRuns(request.app.state.ctx).collect(target_id, actor))
    except VsphereError:
        raise HTTPException(503, "vsphere:publication_failed") from None


@router.get("/vsphere/{target_id}/runs")
def vsphere_runs(target_id: str, request: Request, limit: int = Query(default=20, ge=1, le=100)):
    return _call(lambda: VsphereRuns(request.app.state.ctx).runs(target_id, limit=limit))


@router.get("/vsphere/{target_id}/runs/{run_id}")
def vsphere_run(target_id: str, run_id: str, request: Request):
    return _call(lambda: VsphereRuns(request.app.state.ctx).get(target_id, run_id))


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
