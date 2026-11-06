"""Findings: list and filter the latest (or a named) scan, propose a library fix, explain."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute, feature
from cyberthunder.api.schemas import ExplainBatchBody, ExplainBody
from cyberthunder.api.util import ActorDep, CtxDep, finding_plus, proposal_plus, to_plain
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.security.resources import check_record, visible_record

router = APIRouter(tags=["findings"], route_class=MappedRoute)


def _check_history(ctx, scan_id: str) -> None:
    run = ctx.store.load_scan_run(scan_id)
    if run is None:
        if getattr(ctx.settings, "auth_mode", "dev") != "dev":
            raise PermissionError("scan is unavailable to this account")
        raise KeyError(f"unknown scan {scan_id!r}")
    check_record(ctx, run)


@router.get("/findings")
def list_findings(ctx=CtxDep, scan_id: str | None = None, host: str | None = None, status: str | None = None,
                  severity: str | None = None, source: str | None = None, asset_type: str | None = None,
                  category: str | None = None, benchmark: str | None = None, benchmark_release: str | None = None,
                  confidence: str | None = None, review: str | None = None,
                  sort_by: str = "default", sort_dir: str = "asc",
                  q: str | None = None, limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0)) -> dict:
    result = util.list_findings(ctx, scan_id=scan_id, limit=limit, offset=offset, host=host, status=status,
                              severity=severity, source=source, asset_type=asset_type, q=q, category=category,
                              benchmark=benchmark, benchmark_release=benchmark_release,
                              confidence=confidence, review=review,
                              sort_by=sort_by, sort_dir=sort_dir)
    if result["findings"]:
        reassessment = ReassessmentView(ctx, scan_id=scan_id)
        annotations = reassessment.assess_many(result["findings"])
        for finding, annotation in zip(result["findings"], annotations):
            finding["reassessment"] = annotation
        for finding in result["findings"]:
            check_record(ctx, finding)
    if scan_id:
        _check_history(ctx, scan_id)
    elif result["scan_id"] and not visible_record(ctx, ctx.store.load_scan_run(result["scan_id"]) or {}):
        result["scan_id"] = None
    return result


@router.post("/findings/explain")
def explain_many(body: ExplainBatchBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    """Queue background explanations. Default: every open finding of the latest scan."""
    body = body or ExplainBatchBody()
    if body.ids:
        findings = [util.get_finding(ctx, fid) for fid in body.ids]
    else:
        findings = [f for f in ctx.store.load_findings() if f.is_open]
    from cyberthunder.api.access import require_all
    from cyberthunder.security.resources import visible_record
    findings = [f for f in findings if visible_record(ctx, f)]
    require_all(ctx, [f.host for f in findings], "explain")
    with feature("explain"):
        n = ctx.explain.precompute(findings, background=True)
    return {"queued": int(n or 0)}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, ctx=CtxDep, scan_id: str | None = None) -> dict:
    if scan_id:
        # A named historical view has the same whole-run boundary as the list route.
        _check_history(ctx, scan_id)
    result = finding_plus(ctx, util.get_finding(ctx, finding_id, scan_id))
    result["reassessment"] = ReassessmentView(ctx, scan_id=scan_id).assess(result)
    check_record(ctx, result)
    if scan_id:
        _check_history(ctx, scan_id)
    return result


@router.post("/findings/{finding_id}/propose")
def propose(finding_id: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    finding = util.get_finding(ctx, finding_id)
    from cyberthunder.findings.review import ReviewService
    review = ReviewService(ctx).summary(finding)
    if review["remediation_held"]:
        raise HTTPException(409, "Risk acceptance holds remediation; revoke it or wait for expiry or reopened evidence")
    if review["suppressed"]:
        raise HTTPException(409, "This observation has an active review suppression; reopen its review before proposing a fix")
    fix = ctx.library.resolve(finding)
    if fix is None:
        raise KeyError(f"no library fix for finding {finding_id} ({finding.rule_version or finding.rule_id})")
    existing = util.proposal_for(ctx, finding_id)
    if existing is not None and existing.state.value in util.LIVE_STATES:
        raise HTTPException(409, f"finding {finding_id} already has a live proposal {existing.id} "
                                 f"({existing.state.value})")
    with feature("remediation engine"):
        p = ctx.engine.propose(finding, actor=actor, fix=fix)
    if p is None:
        raise KeyError(f"no library fix for finding {finding_id}")
    return proposal_plus(ctx, p)


@router.post("/findings/{finding_id}/explain")
def explain_one(finding_id: str, body: ExplainBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    body = body or ExplainBody()
    finding = util.get_finding(ctx, finding_id)
    with feature("explain"):
        e = ctx.explain.explain(finding, force=body.force)
    return to_plain(e)
