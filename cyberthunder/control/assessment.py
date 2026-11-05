"""Bind a human's decision to an immutable advisory assessment receipt.

Unassessed decisions remain explicit for existing CLI/API clients and standing
policies. A reviewed receipt cannot silently expire or change before execution.
No receipt, model statement or risk rating grants execution authority.
"""
from __future__ import annotations

from cyberthunder.remediation.engine import EngineError


class AssessmentBlocked(EngineError):
    """The previously reviewed advisory no longer describes this pending change."""


def bind_assessment(ctx, proposal_id: str, assessment_id: str | None, note: str | None = None) -> dict:
    note = (note or "").strip()
    if len(note) > 2000:
        raise ValueError("assessment review note exceeds 2000 characters")
    if not assessment_id:
        return {"status": "not_assessed", "id": None,
                "note": note or "No dependency assessment was attached to this decision."}
    service = getattr(ctx, "impact", None)
    if service is None:
        raise EngineError("dependency assessment service unavailable")
    try:
        receipt = service.get(assessment_id)
        freshness = service.readiness(proposal_id, assessment_id)
    except Exception as exc:
        raise EngineError("assessment could not be read or validated; collect it again") from exc
    if receipt is None or receipt.get("proposal_id") != proposal_id:
        raise EngineError("assessment does not belong to this proposal")
    if freshness.get("stale", True):
        raise EngineError("assessment is stale or its bindings changed; assess and review the change again")
    assessment = receipt.get("assessment")
    model = receipt.get("model")
    if (not isinstance(assessment, dict) or not isinstance(model, dict)
            or not {"risk_level", "unknowns"} <= assessment.keys() or "used" not in model
            or not {"evidence_sha256", "fix_sha256", "target_binding_sha256", "valid_until"} <= receipt.keys()):
        raise EngineError("assessment receipt is incomplete; collect it again")
    has_unknowns = bool(assessment.get("unknowns") or freshness.get("unknowns"))
    if has_unknowns and len(note) < 10:
        raise EngineError("acknowledge the unresolved dependencies in an assessment review note")
    return {"status": "reviewed", "id": assessment_id,
            "evidence_sha256": receipt["evidence_sha256"],
            "fix_sha256": receipt["fix_sha256"],
            "target_binding_sha256": receipt["target_binding_sha256"],
            "valid_until": receipt["valid_until"],
            "risk_level": assessment["risk_level"], "has_unknowns": has_unknowns,
            "model_used": receipt["model"]["used"], "note": note}


def guard_approved_assessment(ctx, proposal) -> None:
    """Recheck local receipt bindings/time; this does not recollect live evidence."""
    binding = getattr(proposal, "assessment", None) or {}
    if binding.get("status") != "reviewed":
        return
    try:
        current = bind_assessment(ctx, proposal.id, binding.get("id"), binding.get("note"))
        if current != binding:
            raise EngineError("approved dependency assessment differs from its receipt; review it again")
    except Exception as exc:
        ctx.audit.append("impact.apply_blocked", "agent", {"assessment_id": binding.get("id"),
                         "reason": "assessment_requires_review"}, subject=proposal.id, outcome="blocked")
        raise AssessmentBlocked("approved assessment is unavailable, stale or changed; review it again") from exc
