"""Approval receipts bind real current state; all target/model operations stay offline."""
from copy import deepcopy
from datetime import datetime, timedelta
import socket

import pytest

from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.control.assessment import AssessmentBlocked, guard_approved_assessment
from cyberthunder.control.policy import AutomationPolicy, PolicyRule
from cyberthunder.findings.schema import Finding, utcnow
from cyberthunder.impact import service as impact_module
from cyberthunder.impact.service import ImpactService
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation import dependencies
from cyberthunder.remediation.engine import EngineError, RemediationEngine
from cyberthunder.remediation.library import FixEntry, FixLibrary

from . import fakes

ACTOR = "Joshua"
ACK = "I reviewed the unknown dependencies and will validate recovery with the owner."
HOST = "rhel-01"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("assessment gate tests must not contact the network")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def seed_assessment(ctx, *, host=HOST, with_receipt=True):
    """Real engine proposal + real stored-only receipt; no fake freshness decisions."""
    try:
        ctx.inventory.get(host)
    except KeyError:
        ctx.inventory.add(Target(host, "Assessment fixture", "linux", transport="fixture"))
    ctx.inventory.save()
    fix = FixEntry("assessment:ssh", "Review SSH change", "linux", [fakes.RULE_ROOT_LOGIN],
                   payload=fakes.CMD_ROOT_LOGIN, before_state={"files": [fakes.SSHD]},
                   restarts_services=["sshd"], verify={"rule_ids": [fakes.RULE_ROOT_LOGIN]})
    ctx.library = FixLibrary([fix])
    ctx.engine = RemediationEngine(ctx)
    ctx.impact = ImpactService(ctx)
    finding = Finding(host=host, source="openscap", rule_id=fakes.RULE_ROOT_LOGIN, title="Review SSH change",
                      severity="medium", status="open", asset_type="linux", fix_ref=fix.fix_ref,
                      evidence="PermitRootLogin yes", collected_at=utcnow())
    ctx.store.save_scan_run({"id": "assessment-scan", "started_at": utcnow(), "status": "done"})
    ctx.store.save_findings("assessment-scan", [finding])
    proposal = ctx.engine.propose(finding, actor=ACTOR)
    receipt = ctx.impact.assess(proposal.id, actor=ACTOR, live=False) if with_receipt else None
    return proposal, receipt, fix, finding


def block_external(ctx, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("approval/read path attempted model, transport, collection or execution")
    for obj, names in ((ctx, ("transport_for",)), (ctx.scanner, ("start", "run")),
                       (ctx.explain, ("explain", "precompute")),
                       (ctx.explain.backend, ("generate", "available"))):
        for name in names:
            monkeypatch.setattr(obj, name, forbidden)
    monkeypatch.setattr(impact_module, "collect_dependencies", forbidden)


def approve_reviewed(ctx, proposal, receipt):
    return ctx.gate.approve(proposal.id, ACTOR, assessment_id=receipt["id"], assessment_note=ACK)


def stored_receipt(ctx, receipt):
    return ctx.impact.directory / f"{receipt['id']}.json"


def test_real_receipt_and_review_binding_survive_context_restart(make_ctx, monkeypatch):
    ctx = make_ctx()
    proposal, receipt, _, _ = seed_assessment(ctx)
    block_external(ctx, monkeypatch)
    raw = ctx.store.read_json(stored_receipt(ctx, receipt))
    assert "freshness" not in raw
    approved = approve_reviewed(ctx, proposal, receipt)
    assert approved.assessment["status"] == "reviewed"
    assert approved.assessment["id"] == receipt["id"]
    assert approved.assessment["has_unknowns"] and approved.assessment["note"] == ACK
    for field in ("evidence_sha256", "fix_sha256", "target_binding_sha256", "valid_until"):
        assert approved.assessment[field] == receipt[field]
    assert ctx.store.read_json(stored_receipt(ctx, receipt)) == raw
    other = make_ctx()
    other.library = ctx.library
    assert other.gate.get(proposal.id).assessment == approved.assessment
    assert other.impact.get(receipt["id"])["assessment"] == receipt["assessment"]
    assert other.store.read_json(stored_receipt(other, receipt)) == raw
    if ctx.store.backend_name == "sqlite":
        assert ctx.store.docs.get(f"change_assessments/{receipt['id']}.json") == raw
        assert not stored_receipt(ctx, receipt).exists()
    else:
        assert stored_receipt(ctx, receipt).exists()
    assert ctx.audit.verify().ok and other.audit.verify().ok


@pytest.mark.parametrize("note", [None, "Owner chose a manual dependency review."])
def test_legacy_approval_is_explicitly_not_assessed(ctx, monkeypatch, note):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    block_external(ctx, monkeypatch)
    approved = ctx.gate.approve(proposal.id, ACTOR, assessment_note=note)
    assert approved.assessment["status"] == "not_assessed" and approved.assessment["id"] is None
    assert approved.assessment["note"]
    if note:
        assert approved.assessment["note"] == note
    record = next(r for r in reversed(list(ctx.audit.records())) if r["action"] == "proposal.approved")
    assert record["details"]["assessment"] == approved.assessment
    guard_approved_assessment(ctx, approved)  # explicit unassessed is permitted, not an invented receipt


def test_standing_policy_approval_also_records_not_assessed(ctx, monkeypatch):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    policy = AutomationPolicy(rules=[PolicyRule("assessment-test")])
    policy.sign(ACTOR, "Fixture standing approval")
    ctx.save_policy(policy, ACTOR)
    block_external(ctx, monkeypatch)
    approved = ctx.gate.approve_by_policy(proposal.id, policy)
    assert approved.state is ProposalState.APPROVED
    assert isinstance(approved.assessment, dict), "standing approval must explicitly record not_assessed"
    assert approved.assessment["status"] == "not_assessed"
    record = next(r for r in reversed(list(ctx.audit.records())) if r["action"] == "proposal.approved")
    assert record["details"]["assessment"]["status"] == "not_assessed"


@pytest.mark.parametrize("actor", ["", "agent", "policy:Joshua"])
@pytest.mark.parametrize("action", ["approve", "review"])
def test_gate_checks_human_before_reading_reviewed_receipt(ctx, monkeypatch, actor, action):
    proposal, receipt, _, _ = seed_assessment(ctx)
    if action == "review":
        ctx.gate.approve(proposal.id, ACTOR)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    monkeypatch.setattr(ctx.impact, "get", lambda *a: pytest.fail("invalid actor read receipt"))
    with pytest.raises(PermissionError):
        if action == "approve":
            ctx.gate.approve(proposal.id, actor, assessment_id=receipt["id"], assessment_note=ACK)
        else:
            ctx.gate.review_assessment(proposal.id, actor, receipt["id"], ACK)
    assert proposal.to_dict() == before


@pytest.mark.parametrize("actor", ["agent", " AGENT:planner ", "policy:Unsigned", ""])
@pytest.mark.parametrize("with_assessment", [False, True])
def test_invalid_actor_approval_preserves_rejection_audit(ctx, monkeypatch, actor, with_assessment):
    proposal, _, _, _ = seed_assessment(ctx, with_receipt=False)
    before = deepcopy(proposal.to_dict())
    persisted = ctx.store.proposals.read_bytes()
    audit_count = len(ctx.audit)
    block_external(ctx, monkeypatch)

    def forbidden(*args, **kwargs):
        pytest.fail("invalid approval actor reached assessment validation or proposal persistence")

    monkeypatch.setattr(ctx.gate, "assessment_validator", forbidden)
    monkeypatch.setattr(ctx.gate, "_save", forbidden)
    aid = "00000000-0000-4000-8000-000000000001" if with_assessment else None
    with pytest.raises(PermissionError):
        ctx.gate.approve(proposal.id, actor, assessment_id=aid, assessment_note=ACK)
    assert ctx.gate.get(proposal.id).to_dict() == before
    assert ctx.store.proposals.read_bytes() == persisted
    records = list(ctx.audit.records())[audit_count:]
    assert len(records) == 1, "a rejected approval must retain the gate's rejection audit"
    record = records[0]
    assert record["action"] == "proposal.approved" and record["outcome"] == "rejected"
    assert record["subject"] == proposal.id
    assert record["details"]["from"] == "proposed" and record["details"]["reason"]
    if actor.strip():
        assert record["actor"] == actor.strip()


@pytest.mark.parametrize("problem", ["wrong_proposal", "target_config", "fix_metadata", "current_finding", "expired", "evidence_tampered", "missing_receipt", "missing_inventory"])
def test_approval_rejects_mismatched_or_stale_real_receipt(ctx, monkeypatch, problem):
    proposal, receipt, fix, finding = seed_assessment(ctx)
    if problem == "wrong_proposal":
        proposal = ctx.gate.propose(actor=ACTOR, finding_id=finding.id, host=HOST, title="Other decision",
                                    fix_ref=fix.fix_ref, fix_preview=fix.preview_text(), rollback_plan="Restore", risk="Unknown")
    elif problem == "target_config":
        ctx.inventory.get(HOST).address = "192.0.2.77"
        ctx.inventory.save()
    elif problem == "fix_metadata":
        fix.before_state["files"].append("/etc/changed")
    elif problem == "current_finding":
        finding.evidence = "Different current observation"
        ctx.store.save_findings("assessment-scan", [finding])
    elif problem == "expired":
        later = datetime.fromisoformat(receipt["valid_until"]) + timedelta(seconds=1)
        monkeypatch.setattr(impact_module, "_now", lambda: later)
    elif problem == "evidence_tampered":
        raw = ctx.store.read_json(stored_receipt(ctx, receipt))
        raw["evidence_packet"]["unknowns"].append("Unbound added evidence")
        ctx.store.write_json(stored_receipt(ctx, receipt), raw)
    elif problem == "missing_receipt":
        ctx.store.delete_json(stored_receipt(ctx, receipt))
    elif problem == "missing_inventory":
        ctx.store.targets.unlink()
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    with pytest.raises(EngineError):
        approve_reviewed(ctx, proposal, receipt)
    assert ctx.gate.get(proposal.id).to_dict() == before
    assert not any(r["action"] == "proposal.approved" and r.get("outcome") == "ok" for r in ctx.audit.records())


@pytest.mark.parametrize("note", [None, "", "   ", "reviewed", " " * 30])
@pytest.mark.parametrize("freshness_only", [False, True])
def test_unknowns_need_substantive_acknowledgement(ctx, monkeypatch, note, freshness_only):
    proposal, receipt, _, _ = seed_assessment(ctx)
    if freshness_only:
        raw = ctx.store.read_json(stored_receipt(ctx, receipt))
        raw["assessment"]["unknowns"] = []
        ctx.store.write_json(stored_receipt(ctx, receipt), raw)
    block_external(ctx, monkeypatch)
    with pytest.raises(EngineError, match="acknowledge"):
        ctx.gate.approve(proposal.id, ACTOR, assessment_id=receipt["id"], assessment_note=note)
    assert proposal.state is ProposalState.PROPOSED
    assert approve_reviewed(ctx, proposal, receipt).assessment["has_unknowns"] is True


@pytest.mark.parametrize("field,value", [("evidence_sha256", "0" * 64), ("fix_sha256", "1" * 64),
                                       ("target_binding_sha256", "2" * 64), ("valid_until", "2100-01-01T00:00:00+00:00"),
                                       ("risk_level", "low"), ("model_used", True)])
def test_execution_refuses_changed_approval_receipt_binding_before_target_io(ctx, monkeypatch, field, value):
    proposal, receipt, _, _ = seed_assessment(ctx)
    approve_reviewed(ctx, proposal, receipt)
    proposal.assessment[field] = value
    ctx.gate._save()
    before = deepcopy(fakes.HOSTS[HOST])
    block_external(ctx, monkeypatch)
    with pytest.raises(AssessmentBlocked):
        ctx.engine.execute(proposal.id, actor=ACTOR)
    assert proposal.state is ProposalState.APPROVED and fakes.HOSTS[HOST] == before
    assert any(r["action"] == "impact.apply_blocked" for r in ctx.audit.records())


def move_to(ctx, proposal, state):
    if state == "proposed":
        return
    if state == "denied":
        ctx.gate.deny(proposal.id, ACTOR)
        return
    if state == "cancelled":
        ctx.gate.cancel(proposal.id, ACTOR)
        return
    ctx.gate.approve(proposal.id, ACTOR)
    if state == "approved":
        return
    ctx.gate.start_apply(proposal.id, ACTOR)
    if state == "applying":
        return
    if state == "failed":
        ctx.gate.failed(proposal.id, ACTOR)
        return
    ctx.gate.applied(proposal.id, ACTOR)
    if state == "applied":
        return
    ctx.gate.verified(proposal.id, ACTOR)
    if state == "rolled_back":
        ctx.gate.rolled_back(proposal.id, ACTOR)


@pytest.mark.parametrize("state", [s.value for s in ProposalState])
def test_rereview_only_changes_an_approved_not_started_decision(ctx, monkeypatch, state):
    proposal, receipt, _, _ = seed_assessment(ctx)
    move_to(ctx, proposal, state)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    if state != "approved":
        with pytest.raises(IllegalTransition):
            ctx.gate.review_assessment(proposal.id, ACTOR, receipt["id"], ACK)
        assert ctx.gate.get(proposal.id).to_dict() == before
    else:
        reviewed = ctx.gate.review_assessment(proposal.id, ACTOR, receipt["id"], ACK)
        assert reviewed.state is ProposalState.APPROVED
        assert reviewed.assessment["id"] == receipt["id"]
        assert reviewed.decided_at == before["decided_at"]
        assert reviewed.history[-1]["assessment_id"] == receipt["id"]


def test_rereview_cannot_silently_clear_a_reviewed_receipt(ctx, monkeypatch):
    proposal, receipt, _, _ = seed_assessment(ctx)
    approve_reviewed(ctx, proposal, receipt)
    before = deepcopy(proposal.to_dict())
    block_external(ctx, monkeypatch)
    with pytest.raises((EngineError, ValueError, IllegalTransition)):
        ctx.gate.review_assessment(proposal.id, ACTOR, "", ACK)
    assert ctx.gate.get(proposal.id).to_dict() == before


@pytest.mark.parametrize("problem", ["expired", "service_unavailable", "malformed_receipt", "missing_inventory"])
def test_assessment_failure_after_capture_never_mutates_or_rolls_back_host(ctx, fake_adapter, monkeypatch, problem):
    proposal, receipt, _, _ = seed_assessment(ctx)
    approve_reviewed(ctx, proposal, receipt)
    before = deepcopy(fakes.HOSTS[HOST])
    capture = fake_adapter.capture_before_state
    operations = []

    def capture_then_invalidate(*args, **kwargs):
        result = capture(*args, **kwargs)
        operations.append("capture")
        if problem == "expired":
            later = datetime.fromisoformat(receipt["valid_until"]) + timedelta(seconds=1)
            monkeypatch.setattr(impact_module, "_now", lambda: later)
        elif problem == "service_unavailable":
            ctx.impact = None
        elif problem == "missing_inventory":
            ctx.store.targets.unlink()
        else:
            raw = ctx.store.read_json(stored_receipt(ctx, receipt))
            raw.pop("assessment")
            ctx.store.write_json(stored_receipt(ctx, receipt), raw)
        return result

    apply, rollback = fake_adapter.apply, fake_adapter.rollback

    def track_apply(*args, **kwargs):
        operations.append("apply")
        return apply(*args, **kwargs)

    def track_rollback(*args, **kwargs):
        operations.append("rollback")
        return rollback(*args, **kwargs)

    monkeypatch.setattr(fake_adapter, "capture_before_state", capture_then_invalidate)
    monkeypatch.setattr(fake_adapter, "apply", track_apply)
    monkeypatch.setattr(fake_adapter, "rollback", track_rollback)
    try:
        ctx.engine.execute(proposal.id, actor=ACTOR)
    except AssessmentBlocked:
        pass
    assert operations == ["capture"], "an assessment failure before apply must not execute apply or rollback"
    assert fakes.HOSTS[HOST] == before
    assert fake_adapter.transports_made[-1].closed
    assert ctx.gate.get(proposal.id).state is ProposalState.FAILED
    assert any(r["action"] == "impact.apply_blocked" for r in ctx.audit.records())


def test_refreshed_receipt_can_be_rereviewed_then_execute(ctx, fake_adapter, monkeypatch):
    proposal, old, _, _ = seed_assessment(ctx)
    approve_reviewed(ctx, proposal, old)
    later = datetime.fromisoformat(old["valid_until"]) + timedelta(seconds=1)
    monkeypatch.setattr(impact_module, "_now", lambda: later)
    with pytest.raises(AssessmentBlocked):
        ctx.engine.execute(proposal.id, actor=ACTOR)
    assert not fake_adapter.transports_made
    # Fresh collection happens after the first receipt expired; do not move the clock back.
    monkeypatch.setattr(dependencies, "utcnow", lambda: later.isoformat())
    fresh = ctx.impact.assess(proposal.id, actor=ACTOR, live=False)
    assert fresh["id"] != old["id"]
    assert ctx.impact.readiness(proposal.id, old["id"])["stale"]
    assert not ctx.impact.readiness(proposal.id, fresh["id"])["stale"]
    ctx.gate.review_assessment(proposal.id, ACTOR, fresh["id"], ACK)
    result = ctx.engine.execute(proposal.id, actor=ACTOR)
    assert result.state is ProposalState.VERIFIED
    assert "PermitRootLogin no" in fakes.HOSTS[HOST]["files"][fakes.SSHD]
