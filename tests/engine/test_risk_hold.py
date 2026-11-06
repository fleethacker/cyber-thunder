"""Risk holds stop proposal, policy and final apply paths without implying remediation."""
import pytest

from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.control.policy import assurance_block_reason
from cyberthunder.findings.review import ReviewConflict, ReviewService
from cyberthunder.remediation.engine import RemediationHeld
from tests.findings.test_risk_acceptance import accept, revoke
from . import fakes
from .conftest import HOST
from .test_engine import SAILOR, _policy, scan


def test_active_risk_holds_manual_automatic_proposals_and_standing_approval(make_ctx):
    ctx = make_ctx(auto_propose=False)
    _policy(ctx, fix_allowlist=["fake:sshd_disable_root_login"])
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    service = ReviewService(ctx)
    accept(service, finding)
    assert ctx.engine.propose(finding, actor=SAILOR) is None
    assert ctx.engine.auto_propose([finding]) == []
    assert "risk acceptance" in assurance_block_reason(ctx, finding)
    assert ctx.gate.list() == [] and ctx.store.get_finding(finding.id).is_open
    revoke(service, finding)
    proposal = ctx.engine.propose(finding, actor=SAILOR)
    assert proposal.state is ProposalState.PROPOSED
    with pytest.raises(IllegalTransition):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert fakes.HOSTS[HOST] == fakes.seed_state()


def test_existing_human_approval_does_not_override_risk_hold(make_ctx, fake_adapter):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    accept(ReviewService(ctx), finding)
    plan = ctx.engine.plan(proposal.id, actor=SAILOR)
    assert next(c for c in plan["checks"] if c["code"] == "remediation_held")["status"] == "blocked"
    count = len(fake_adapter.transports_made)
    with pytest.raises(RemediationHeld):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert len(fake_adapter.transports_made) == count
    assert ctx.gate.get(proposal.id).state is ProposalState.APPROVED
    assert ctx.store.get_finding(finding.id).is_open and fakes.HOSTS[HOST] == fakes.seed_state()


def test_acceptance_during_capture_stops_apply_without_rollback(make_ctx, fake_adapter, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    capture = fake_adapter.capture_before_state
    def capture_then_accept(*args, **kwargs):
        before = capture(*args, **kwargs)
        accept(ReviewService(ctx), finding)
        return before
    monkeypatch.setattr(fake_adapter, "capture_before_state", capture_then_accept)
    monkeypatch.setattr(fake_adapter, "apply", lambda *a, **k: pytest.fail("held apply ran"))
    monkeypatch.setattr(fake_adapter, "rollback", lambda *a, **k: pytest.fail("capture-only stop rolled back"))
    with pytest.raises(RemediationHeld):
        ctx.engine.execute(proposal.id, actor=SAILOR)
    assert ctx.gate.get(proposal.id).state is ProposalState.FAILED
    assert fakes.HOSTS[HOST] == fakes.seed_state()


def test_acceptance_cannot_commit_between_final_check_and_apply(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    proposal = ctx.engine.propose(finding)
    ctx.gate.approve(proposal.id, SAILOR)
    guard = ctx.killswitch.guard
    blocked = []
    def guard_with_accept(action, actor):
        if action.startswith("remediation.apply:"):
            with pytest.raises(ReviewConflict):
                accept(ReviewService(ctx), finding)
            blocked.append(True)
        return guard(action, actor)
    monkeypatch.setattr(ctx.killswitch, "guard", guard_with_accept)
    assert ctx.engine.execute(proposal.id, actor=SAILOR).state is ProposalState.VERIFIED
    assert blocked and ReviewService(ctx).summary(finding)["history_count"] == 0


def test_acceptance_serializes_with_proposal_creation(make_ctx, monkeypatch):
    ctx = make_ctx(auto_propose=False)
    finding = scan(ctx)[fakes.RULE_ROOT_LOGIN]
    propose = ctx.gate.propose
    def propose_with_accept(*args, **kwargs):
        with pytest.raises(ReviewConflict):
            accept(ReviewService(ctx), finding)
        return propose(*args, **kwargs)
    monkeypatch.setattr(ctx.gate, "propose", propose_with_accept)
    assert ctx.engine.propose(finding).state is ProposalState.PROPOSED
