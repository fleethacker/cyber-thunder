"""Scans: start a read-only scan in the background and poll it."""
from __future__ import annotations

from fastapi import APIRouter

from cyberthunder.adapters.base import MODULES
from cyberthunder.api.errors import MappedRoute, feature
from cyberthunder.api.schemas import SCAN_TRIGGERS, ScanRequest
from cyberthunder.api.util import ActorDep, CtxDep, scan_plus

router = APIRouter(tags=["scans"], route_class=MappedRoute)


def start_scan(ctx, actor: str, *, target_ids=None, modules=None, rule_filter=None, trigger: str = "manual") -> dict:
    """Validate a scan request and hand it to the Scanner. Shared with ingest (rescan after a STIG delta)."""
    if modules is not None:
        bad = [m for m in modules if m not in MODULES]
        if bad or not modules:
            raise ValueError(f"modules must be a non-empty subset of {list(MODULES)}; got {modules}")
    if trigger not in SCAN_TRIGGERS:
        raise ValueError(f"trigger must be one of {list(SCAN_TRIGGERS)}")
    if target_ids is not None:
        if not target_ids:
            raise ValueError("target_ids is empty; omit it to scan every in-scope target")
        for tid in target_ids:
            ctx.inventory.get(tid)                    # 404 for an unknown id
            ctx.inventory.assert_in_scope(tid)        # 403 for an out-of-scope one
    elif not any(t.in_scope for t in ctx.inventory.all()):
        raise ValueError("no in-scope targets in the inventory")
    with feature("scanner"):
        run = ctx.scanner.start(target_ids, modules=modules, rule_filter=rule_filter or None, trigger=trigger,
                                requested_by=actor, background=True)
    return scan_plus(run)


@router.post("/scans", status_code=202)
def post_scan(body: ScanRequest | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or ScanRequest()
    return start_scan(ctx, actor, target_ids=body.target_ids, modules=body.modules, rule_filter=body.rule_filter,
                      trigger=body.trigger or "manual")


@router.get("/scans")
def list_scans(ctx=CtxDep) -> dict:
    return {"scans": [scan_plus(r) for r in ctx.scanner.list()]}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, ctx=CtxDep) -> dict:
    run = ctx.scanner.get(scan_id)
    if run is None:
        raise KeyError(f"unknown scan {scan_id!r}")
    return scan_plus(run)
