"""Static inspection of a proposal's vetted fix; no target or execution operations."""
from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import ProposalState
from cyberthunder.control.identity import require_human
from cyberthunder.control.policy import assurance_block_reason
from cyberthunder.findings.current import policy_block_reason
from cyberthunder.findings.review import ReviewService
from cyberthunder.findings.schema import utcnow
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.engine import EngineError, dynamic_ssg_fix, fix_digest

if TYPE_CHECKING:
    from cyberthunder.remediation.engine import RemediationEngine


LIMITATIONS = (
    "Static metadata only; this preview does not authorize execution or prove safety.",
    "Current host contents, access, applicability and lockout safety have not been tested.",
    "before_state files are declared capture paths, NOT an exhaustive list of touched files.",
    "Maintenance eligibility is checked again at execution; this preview does not reserve a window.",
    "Checks describe stored state at preview time; execution must enforce its own current guards.",
)


def _bound_fix(engine, proposal, current, target):
    """Match execution's library/saved/content precedence without its write side effects."""
    ctx = engine.ctx
    entry = ctx.library.get(proposal.fix_ref)
    if entry is None:
        # snapshot_dir() creates directories, including on a read. Build a confined path instead.
        root = ctx.store.snapshots_dir.resolve()
        path = (root / proposal.id).resolve()
        if path == root or not path.is_relative_to(root):
            raise EngineError("invalid proposal snapshot path")
        try:
            entry = snapshot.load_fix(path)
        except (OSError, ValueError, TypeError) as exc:
            raise EngineError("saved fix cannot be read; request a new proposal") from exc
        if entry is None and (path / "fix.json").exists():
            raise EngineError("saved fix is invalid; request a new proposal")
    if entry is None and target is not None and not target.simulated:
        # Historical content may reconstruct a bound SSG entry, but is NEVER readiness evidence.
        stored = current or ctx.store.get_finding(proposal.finding_id)
        if stored is not None and stored.host == proposal.host:
            entry = dynamic_ssg_fix(stored)
    if entry is None or entry.fix_ref != proposal.fix_ref:
        raise EngineError("proposal has no matching vetted fix; request a new proposal")
    entry = deepcopy(entry)
    digest = fix_digest(entry)
    approved_digest = engine._approved_digest(proposal)
    if entry.preview_text() != proposal.fix_preview or (approved_digest is not None and digest != approved_digest):
        raise EngineError("fix changed since it was proposed; propose and approve it again")
    return entry, digest, approved_digest


def static_plan(engine: RemediationEngine, proposal_id: str, *, actor: str) -> dict:
    """Return an audited metadata preview; only the audit record is written."""
    actor = require_human(actor)
    ctx = engine.ctx
    ctx.killswitch.guard(f"remediation.plan:{proposal_id}", actor)
    proposal = deepcopy(ctx.gate.get(proposal_id))
    try:
        target = deepcopy(ctx.inventory.get(proposal.host))
    except KeyError:
        target = None
    # get_finding() and engine._finding() both have historical fallbacks. Do not use them here.
    current = next((f for f in ctx.store.current_findings() if f.id == proposal.finding_id), None)
    entry, digest, approved_digest = _bound_fix(engine, proposal, current, target)
    checks = []

    def check(code, status, detail):
        checks.append({"code": code, "status": status, "detail": detail})

    if target is None:
        check("scope", "unknown", "Target is missing from current inventory; scope cannot be established.")
    elif not target.in_scope:
        check("scope", "blocked", "Target is marked out of scope.")
    else:
        check("scope", "pass", "Target is listed in scope in current inventory.")
    approved = proposal.state is ProposalState.APPROVED
    check("approval", "pass" if approved else "blocked",
          "Proposal is approved; this preview grants no execution authority." if approved else
          f"Proposal is {proposal.state.value}; execution requires an approved proposal.")
    check("fix_binding", "pass" if approved_digest is not None else "unknown",
          "Fix preview and all declared fields match the proposal's recorded digest." if approved_digest is not None else
          "Legacy proposal: preview matches, but no digest binds the remaining fix metadata.")

    usable = current is not None and current.host == proposal.host
    if current is None:
        check("current_finding", "unknown", "Finding is absent from the current view; historical observations are not readiness evidence.")
    elif not usable:
        check("current_finding", "blocked", "Current finding target differs from the proposal target.")
    else:
        check("current_finding", "pass" if current.is_open else "blocked",
              "An open finding is present in the current stored view; freshness is a separate policy evidence check."
              if current.is_open else "Current stored finding is not open.")
    if usable:
        review = ReviewService(ctx).summary(current)
        check("remediation_held", "blocked" if review["remediation_held"] else "pass",
              "Operator risk acceptance holds remediation; the scanner risk remains open." if review["remediation_held"] else
              "No active operator risk acceptance holds remediation.")
        check("suppression", "blocked" if review["suppressed"] else "pass",
              "Current finding has an active review suppression." if review["suppressed"] else
              "Current finding has no active review suppression.")
    else:
        check("remediation_held", "unknown", "Risk acceptance cannot be assessed without a matching current finding.")
        check("suppression", "unknown", "Active suppression cannot be assessed without a matching current finding.")

    if (proposal.decided_by or "").startswith("policy:"):
        if not usable or not current.is_open:
            check("policy_evidence", "blocked", "Standing approval requires a matching open current finding.")
        else:
            reason = policy_block_reason(ctx, current) or assurance_block_reason(ctx, current)
            check("policy_evidence", "blocked" if reason else "pass",
                  reason or "Current stored evidence and review meet the standing-approval evidence requirement; no approval is granted.")
    else:
        check("policy_evidence", "unknown", "Not assessed: this proposal has no standing-policy approval.")

    from cyberthunder.remediation.maintenance import MaintenanceService
    maintenance = MaintenanceService(ctx).summary(proposal)
    check("maintenance", "pass" if maintenance["allowed"] else "blocked", maintenance["reason"])
    result = {
        "version": 1, "mode": "static", "generated_at": utcnow(),
        "proposal_id": proposal.id, "proposal_state": proposal.state.value,
        "target": {"id": proposal.host, "name": target.name if target else None,
                   "asset_type": target.asset_type if target else None,
                   "simulated": target.simulated if target else None,
                   "in_scope": target.in_scope if target else None},
        "fix": entry.to_dict(), "fix_sha256": digest, "approved_fix_sha256": approved_digest,
        "checks": checks, "limitations": list(LIMITATIONS), "maintenance": maintenance,
    }
    ctx.audit.append("remediation.plan", actor,
                     {"proposal_id": proposal.id, "finding_id": proposal.finding_id,
                      "target_id": proposal.host, "fix_ref": entry.fix_ref,
                      "fix_sha256": digest, "approved_fix_sha256": approved_digest,
                      "checks": {c["code"]: c["status"] for c in checks}}, subject=proposal.id)
    return result
