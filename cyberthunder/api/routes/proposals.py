"""Proposals: the decision queue. Approve, deny, cancel, apply (background), roll back, diff, bulk.

Apply and rollback check the kill switch before starting work so the Sailor gets a 423 at once; the gate
checks it again on the edge itself, so a kill engaged mid-flight still stops the change."""
from __future__ import annotations

import logging

from fastapi import APIRouter

from cyberthunder.api import util
from cyberthunder.api.errors import MappedRoute, feature, status_for
from cyberthunder.api.schemas import ApplyBody, BulkBody, NoteBody
from cyberthunder.api.util import ActorDep, CtxDep, proposal_plus
from cyberthunder.control.approvals import IllegalTransition, ProposalState

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
            mapped = status_for(e)
            if mapped is None:
                log.exception("bulk %s failed on %s", body.action, pid)
                results.append({"id": pid, "error": str(e) or type(e).__name__, "status": 500})
            else:
                results.append({"id": pid, "error": mapped[1], "status": mapped[0]})
    return {"results": results}


@router.post("/proposals/{pid}/approve")
def approve(pid: str, body: NoteBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    return proposal_plus(ctx, _decide(ctx, pid, "approve", actor, (body or NoteBody()).note))


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


@router.post("/proposals/{pid}/apply", status_code=202)
def apply(pid: str, body: ApplyBody | None = None, ctx=CtxDep, actor: str = ActorDep) -> dict:
    p = util.get_proposal(ctx, pid)
    if p.state != ProposalState.APPROVED:
        raise IllegalTransition(f"proposal {pid} is {p.state.value}; only an approved proposal can be applied")
    ctx.killswitch.guard(f"proposal.apply:{pid}", actor)
    body = body or ApplyBody()
    # The demo toggle is consumed only when the request does not ask for a forced failure itself.
    simulate = True if body.simulate_verify_fail else _demo_forces_failure(ctx)

    def work() -> None:
        with feature("remediation engine"):
            ctx.engine.execute(pid, actor=actor, simulate_verify_fail=simulate)

    util.run_background(work, f"apply-{pid}")
    return {"proposal_id": pid, "state": "applying", "simulate_verify_fail": simulate}


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


@router.get("/proposals/{pid}/diff")
def diff(pid: str, ctx=CtxDep) -> dict:
    util.get_proposal(ctx, pid)
    with feature("remediation engine"):
        d = ctx.engine.diff(pid)
    d = util.to_plain(d) or {}
    for k, default in (("before", {}), ("after", {}), ("verify", None), ("apply", None), ("files", [])):
        d.setdefault(k, default)
    return d
