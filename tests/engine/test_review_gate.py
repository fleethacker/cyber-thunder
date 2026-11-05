"""Reviews can stop remediation, but can never grant approval or rewrite observations."""
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.findings.review import ReviewConflict, ReviewService
from cyberthunder.remediation.engine import PolicyEvidenceBlocked, ReviewSuppressed
from . import fakes
from .conftest import HOST
from .test_engine import SAILOR, _policy, scan


def decide(ctx, finding, disposition="false_positive"):
    service = ReviewService(ctx)
    current = service.summary(finding)
    return service.save(finding, actor=SAILOR, disposition=disposition,
                        reason="Validated against the fixture baseline", supporting_evidence="Fixture observation",
                        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
                        if disposition in ("false_positive", "not_applicable") else None,
                        expected_revision=current["revision"], evidence_fingerprint=current["evidence_fingerprint"])


def test_review_blocks_proposals_without_changing_scanner_result(make_ctx):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    decide(ctx, finding)
    assert ctx.engine.propose(finding) is None
    assert ctx.engine.auto_propose([finding]) == []
    assert ctx.store.get_finding(finding.id).status.value == "open"
    assert ctx.gate.list() == []
    decide(ctx, finding, "unreviewed")
    assert ctx.engine.propose(finding).state is ProposalState.PROPOSED


def test_review_blocks_existing_approved_fix_before_transport(make_ctx, fake_adapter):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    decide(ctx, finding)
    transports = len(fake_adapter.transports_made)
    with pytest.raises(ReviewSuppressed):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert len(fake_adapter.transports_made) == transports
    assert fakes.HOSTS[HOST] == fakes.seed_state()
    assert ctx.gate.get(proposal.id).state is ProposalState.APPROVED


def test_investigation_blocks_standing_approval_but_not_manual_approval(make_ctx):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx, fix_allowlist=["fake:sshd_disable_root_login"])
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    decide(ctx, finding, "needs_investigation")
    proposal = ctx.engine.auto_propose([finding])[0]
    assert ctx.gate.get(proposal.id).state is ProposalState.PROPOSED
    ctx.gate.approve(proposal.id, SAILOR)
    assert ctx.engine.execute(proposal.id, actor=SAILOR).state is ProposalState.VERIFIED


def test_new_investigation_stops_existing_policy_approval(make_ctx, fake_adapter):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx, fix_allowlist=["fake:sshd_disable_root_login"])
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.auto_propose([finding])[0]
    assert ctx.gate.get(proposal.id).state is ProposalState.APPROVED
    decide(ctx, finding, "needs_investigation")
    count = len(fake_adapter.transports_made)
    with pytest.raises(PolicyEvidenceBlocked):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert len(fake_adapter.transports_made) == count
    assert ctx.gate.get(proposal.id).state is ProposalState.APPROVED


def test_review_during_capture_stops_apply_without_rollback(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    capture = fake_adapter.capture_before_state
    def capture_and_review(*args, **kwargs):
        result = capture(*args, **kwargs)
        decide(ctx, finding)
        return result
    monkeypatch.setattr(fake_adapter, "capture_before_state", capture_and_review)
    monkeypatch.setattr(fake_adapter, "apply", lambda *a, **k: pytest.fail("suppressed apply ran"))
    monkeypatch.setattr(fake_adapter, "rollback", lambda *a, **k: pytest.fail("unnecessary rollback ran"))
    with pytest.raises(ReviewSuppressed):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert ctx.gate.get(proposal.id).state is ProposalState.FAILED
    assert fakes.HOSTS[HOST] == fakes.seed_state()


def test_low_confidence_withholds_policy_without_granting_manual_approval(make_ctx):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx, fix_allowlist=["fake:sshd_disable_root_login"])
    findings = list(scan(ctx).values())
    finding = next(f for f in findings if f.rule_id == fakes.RULE_ROOT_LOGIN)
    finding.collection_provenance = {"simulated": True}
    ctx.store.save_findings(finding.scan_id, findings)
    proposal = ctx.engine.auto_propose([finding])[0]
    assert ctx.gate.get(proposal.id).state is ProposalState.PROPOSED
    assert any("low confidence" in str(r["details"]) for r in ctx.audit.records())


def test_review_cannot_commit_between_final_check_and_apply(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    guard = ctx.killswitch.guard
    rejected = []
    def competing_review(action, actor):
        if action.startswith("remediation.apply:"):
            with pytest.raises(ReviewConflict):
                decide(ctx, finding)
            rejected.append(True)
        return guard(action, actor)
    monkeypatch.setattr(ctx.killswitch, "guard", competing_review)
    assert ctx.engine.execute(proposal.id, actor=SAILOR).state is ProposalState.VERIFIED
    assert rejected and not ReviewService(ctx).summary(finding)["suppressed"]


def test_busy_review_lock_stops_before_apply_without_rollback(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    monkeypatch.setattr(fake_adapter, "apply", lambda *a, **k: pytest.fail("busy apply ran"))
    monkeypatch.setattr(fake_adapter, "rollback", lambda *a, **k: pytest.fail("busy rollback ran"))
    with ReviewService(ctx).remediation_guard(finding):
        with pytest.raises(ReviewConflict):
            ctx.engine.execute(proposal.id, actor=SAILOR)
    assert ctx.gate.get(proposal.id).state is ProposalState.FAILED
