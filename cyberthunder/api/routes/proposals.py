"""Proposals: the decision queue. Approve, deny, cancel, apply (background), roll back, verify a hand-made
change, diff, bulk.

Apply and rollback check the kill switch before starting work so the Sailor gets a 423 at once; the gate
checks it again on the edge itself, so a kill engaged mid-flight still stops the change."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute, feature, status_for, unavailable
from cyberthunder.api.schemas import (ApplyBody, ApprovalBody, AssessmentReviewBody,
                                     BulkBody, ImpactBody, NoteBody)
from cyberthunder.api.util import ActorDep, CtxDep, proposal_plus
from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.security.step_up import StepUpRequired, ERROR as STEP_UP_ERROR

log = logging.getLogger(__name__)
router = APIRouter(tags=["proposals"], route_class=MappedRoute)

ROLLBACK_FROM = {ProposalState.APPLIED, ProposalState.VERIFIED, ProposalState.FAILED}


def _asset_type(d: dict) -> str | None:
    t = d.get("target") or {}
    return t.get("asset_type") or (d.get("fix") or {}).get("asset_type")


@router.get("/proposals")
def list_proposals(ctx=CtxDep, state: str | None = None, host: str | None = None,
                   asset_type: str | None = None) -> dict:
    states = {s.strip().lower() for s in (state or "").split(",") if s.strip()}
    for s in states:
        ProposalState(s)                            # ValueError -> 400 for an unknown state
    hosts = {h.strip() for h in (host or "").split(",") if h.strip()}
    types = {a.strip() for a in (asset_type or "").split(",") if a.strip()}
    items = sorted(ctx.gate.list(), key=lambda p: p.created_at)
    out = []
    for p in items:
        from cyberthunder.security.resources import visible_record
        if not visible_record(ctx, p):
            continue
        if states and p.state.value not in states:
            continue
        if hosts and p.host not in hosts:
            continue
        d = proposal_plus(ctx, p)
        if types and _asset_type(d) not in types:
            continue
        out.append(d)
    return {"proposals": out}


@router.get("/proposals/{pid}")
def get_proposal(pid: str, ctx=CtxDep) -> dict:
    return proposal_plus(ctx, util.get_proposal(ctx, pid))


def _decide(ctx, pid: str, action: str, actor: str, note: str | None):
    util.get_proposal(ctx, pid)
    fn = {"approve": ctx.gate.approve, "deny": ctx.gate.deny, "cancel": ctx.gate.cancel}[action]
    return fn(pid, actor, note)


@router.post("/proposals/bulk")
def bulk(body: BulkBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    results = []
    for pid in body.ids:
        try:
            p = _decide(ctx, pid, body.action, actor, body.note)
            results.append({"id": pid, "state": p.state.value})
        except Exception as e:  # noqa: BLE001  each id reports its own outcome
            if isinstance(e, StepUpRequired):
                results.append({"id": pid, "error": str(e), "status": 401,
                                "code": STEP_UP_ERROR, "step_up": e.challenge()})
                continue
            mapped = status_for(e)
            if mapped is None:
                log.exception("bulk %s failed on %s", body.action, pid)
                results.append({"id": pid, "error": str(e) or type(e).__name__, "status": 500})
            else:
                results.append({"id": pid, "error": mapped[1], "status": mapped[0]})
    return {"results": results}


@router.post("/proposals/{pid}/approve")
def approve(pid: str, body: ApprovalBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    util.get_proposal(ctx, pid)
    body = body or ApprovalBody()
    return proposal_plus(ctx, ctx.gate.approve(pid, actor, body.note,
                         assessment_id=body.assessment_id, assessment_note=body.assessment_note))


def _impact(ctx):
    service = getattr(ctx, "impact", None)
    if service is None:
        raise unavailable("dependency assessment")
    return service


@router.post("/proposals/{pid}/impact")
def assess_impact(pid: str, body: ImpactBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    util.get_proposal(ctx, pid)
    return _impact(ctx).assess(pid, actor=actor, live=(body or ImpactBody()).live)


@router.get("/proposals/{pid}/impact")
def latest_impact(pid: str, ctx=CtxDep) -> dict:
    util.get_proposal(ctx, pid)
    return {"assessment": _impact(ctx).latest(pid)}


@router.get("/change-assessments/{assessment_id}")
def get_impact(assessment_id: str, ctx=CtxDep) -> dict:
    receipt = _impact(ctx).get(assessment_id)
    if receipt is None:
        raise KeyError("unknown dependency assessment")
    return receipt


@router.post("/proposals/{pid}/review-impact")
def review_impact(pid: str, body: AssessmentReviewBody, ctx=CtxDep, actor: str = ActorDep) -> dict:
    util.get_proposal(ctx, pid)
    return proposal_plus(ctx, ctx.gate.review_assessment(pid, actor, body.assessment_id, body.note))


@router.post("/proposals/{pid}/deny")
def deny(pid: str, body: NoteBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return proposal_plus(ctx, _decide(ctx, pid, "deny", actor, (body or NoteBody()).note))


@router.post("/proposals/{pid}/cancel")
def cancel(pid: str, body: NoteBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return proposal_plus(ctx, _decide(ctx, pid, "cancel", actor, (body or NoteBody()).note))


def _demo_forces_failure(ctx) -> bool:
    demo = util.demo_module()
    fn = getattr(demo, "consume_simulate_verify_fail", None) if demo is not None else None
    if fn is None:
        return False
    try:
        return bool(fn(ctx))
    except Exception as e:  # noqa: BLE001  a demo toggle must never block a real apply
        log.warning("demo verify-fail toggle unreadable: %s", e)
        return False


@router.post("/proposals/{pid}/plan")
def plan(pid: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    fn = getattr(ctx.engine, "plan", None) if ctx.engine is not None else None
    if not callable(fn):
        raise unavailable("static remediation preview")
    with feature("static remediation preview"):
        return fn(pid, actor=actor)


@router.post("/proposals/{pid}/apply", status_code=202)
def apply(pid: str, body: ApplyBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    p = util.get_proposal(ctx, pid)
    if p.state != ProposalState.APPROVED:
        raise IllegalTransition(f"proposal {pid} is {p.state.value}; only an approved proposal can be applied")
    ctx.killswitch.guard(f"proposal.apply:{pid}", actor)
    from cyberthunder.control.assessment import guard_approved_assessment
    guard_approved_assessment(ctx, p)
    from cyberthunder.findings.review import ReviewService
    from cyberthunder.control.policy import assurance_block_reason
    finding = util.get_finding(ctx, p.finding_id)
    reason = None
    review = ReviewService(ctx).summary(finding)
    if review["remediation_held"]:
        reason = "Risk acceptance holds remediation; revoke it or wait for expiry or reopened evidence"
    elif review["suppressed"]:
        reason = "The finding has an active review suppression; reopen its review before applying"
    elif (p.decided_by or "").startswith("policy:"):
        reason = assurance_block_reason(ctx, finding)
    if reason:
        ctx.audit.append("finding.review_blocked", actor, {"action": "apply", "reason": reason},
                         subject=p.id, outcome="blocked")
        raise HTTPException(409, reason)
    body = body or ApplyBody()
    # The demo toggle is consumed only when the request does not ask for a forced failure itself.
    simulate = True if body.simulate_verify_fail else _demo_forces_failure(ctx)

    from_toggle = simulate and not body.simulate_verify_fail

    def work() -> None:
        with feature("remediation engine"):
            ctx.engine.execute(pid, actor=actor, simulate_verify_fail=simulate)

    try:
        util.run_background(work, f"apply-{pid}")
    except BaseException:
        if from_toggle:
            _rearm_demo_toggle(ctx)   # the apply never started, so the forced failure is still owed
        raise
    return {"proposal_id": pid, "state": "applying", "simulate_verify_fail": simulate}


def _rearm_demo_toggle(ctx) -> None:
    demo = util.demo_module()
    fn = getattr(demo, "set_simulate_verify_fail_next", None) if demo is not None else None
    if fn is None:
        return
    try:
        fn(ctx, True, "agent")
    except Exception as e:  # noqa: BLE001  the original error is what the caller needs to see
        log.warning("demo verify-fail toggle could not be re-armed: %s", e)


@router.post("/proposals/{pid}/rollback", status_code=202)
def rollback(pid: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    p = util.get_proposal(ctx, pid)
    if p.state not in ROLLBACK_FROM:
        raise IllegalTransition(f"proposal {pid} is {p.state.value}; only applied, verified or failed changes "
                                f"can be rolled back")
    ctx.killswitch.guard(f"proposal.rollback:{pid}", actor)

    def work() -> None:
        with feature("remediation engine"):
            ctx.engine.rollback(pid, actor=actor)

    util.run_background(work, f"rollback-{pid}")
    return {"proposal_id": pid, "state": "rolling_back"}


@router.post("/proposals/{pid}/verify")
def verify(pid: str, ctx=CtxDep, actor: str = ActorDep) -> dict:
    """Record verification of a change the operator carried out by hand (a runbook proposal). The engine
    owns the rescan and the state change; builds without engine.verify answer 501."""
    util.get_proposal(ctx, pid)
    fn = getattr(ctx.engine, "verify", None) if ctx.engine is not None else None
    if not callable(fn):
        raise unavailable("manual verification")
    with feature("manual verification"):
        p = fn(pid, actor=actor)
    return proposal_plus(ctx, p if hasattr(p, "state") else util.get_proposal(ctx, pid))


@router.get("/proposals/{pid}/diff")
def diff(pid: str, ctx=CtxDep) -> dict:
    util.get_proposal(ctx, pid)
    with feature("remediation engine"):
        d = ctx.engine.diff(pid)
    d = util.to_plain(d) or {}
    for k, default in (("before", {}), ("after", {}), ("verify", None), ("apply", None), ("files", [])):
        d.setdefault(k, default)
    return d
