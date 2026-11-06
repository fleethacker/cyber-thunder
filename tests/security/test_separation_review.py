"""Adversarial lifecycle replay and final mutation-boundary checks; no target IO."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.schema import Severity
from cyberthunder.remediation.models import BeforeState
from tests.security.test_separation_of_duties import (
    approve, edit_proposal, offline, person, propose, setup,
)


@pytest.mark.parametrize("edge", ["cancelled", "denied", "applied"])
def test_old_proposal_snapshot_cannot_replay_a_later_audited_lifecycle(setup, edge):
    ctx, make, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    if edge != "denied":
        approve(ctx, p.id, "carol")
    snapshot = deepcopy(p.to_dict())
    who = person("carol")
    with principal_scope(who):
        if edge == "cancelled":
            ctx.gate.cancel(p.id, who.actor)
        elif edge == "denied":
            ctx.gate.deny(p.id, who.actor)
        else:
            ctx.gate.start_apply(p.id, who.actor)
            ctx.gate.applied(p.id, who.actor)
    edit_proposal(ctx, p.id, lambda row: (row.clear(), row.update(snapshot)))
    restarted = make()
    with principal_scope(who), pytest.raises(PermissionError):
        if edge == "denied":
            restarted.gate.approve(p.id, who.actor)
        else:
            restarted.gate.start_apply(p.id, who.actor)
    assert ctx.audit.verify().ok


def test_apply_authority_revoked_during_receipt_validation_is_rechecked(setup):
    ctx, _, _, policy_path = setup
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    validate = ctx.gate.assessment_validator

    def revoke(*args):
        result = validate(*args)
        policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        return result

    ctx.gate.assessment_validator = revoke
    who = person("carol")
    with principal_scope(who), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, who.actor)
    assert ctx.gate.get(p.id).state == ProposalState.APPROVED


def test_approval_authority_is_checked_after_the_final_source_read(setup):
    ctx, _, _, policy_path = setup
    p = propose(setup)
    source = ctx.gate.separation_source
    calls = 0

    def revoke(proposal):
        nonlocal calls
        result = source(proposal)
        calls += 1
        if calls == 2:
            policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        return result

    ctx.gate.separation_source = revoke
    with pytest.raises(PermissionError):
        approve(ctx, p.id)
    assert not ctx.gate.get(p.id).approvals


@pytest.mark.parametrize("change", ["finding", "receipt", "fix"])
@pytest.mark.parametrize("kind", ["script", "runbook"])
def test_capture_cannot_invalidate_approved_evidence_then_reach_mutation(setup, monkeypatch, change, kind):
    ctx, _, finding, _ = setup
    finding.severity = Severity.MEDIUM
    ctx.store.save_findings("sod-scan", [finding])
    ctx.library.get("fixture:separation").kind = kind
    p = propose(setup)
    approve(ctx, p.id)
    assert p.required_approvals == 1 and p.state == ProposalState.APPROVED
    mutations = []

    def capture(*args):
        if change == "finding":
            finding.severity = Severity.HIGH
            ctx.store.save_findings("sod-scan", [finding])
        elif change == "receipt":
            edit_proposal(ctx, p.id, lambda row: row["approvals"][0]["principal"].update(sub="forged"))
        else:
            ctx.library.get(p.fix_ref).payload = "substituted payload"
        return BeforeState(target_id=p.host, fix_ref=p.fix_ref, dir=str(args[-1]), files=[])

    def apply(*args):
        mutations.append(True)
        raise PermissionError("inert adapter mutation boundary reached")

    adapter = SimpleNamespace(capture_before_state=capture, apply=apply)
    monkeypatch.setattr(ctx.engine, "_adapter", lambda target: adapter)
    monkeypatch.setattr(ctx, "transport_for", lambda target: SimpleNamespace(close=lambda: None))
    who = person("bob")
    with principal_scope(who), pytest.raises(PermissionError):
        ctx.engine.execute(p.id, actor=who.actor)
    assert mutations == [], "invalidated approvals reached adapter.apply"


@pytest.mark.parametrize("field", ["decided_by", "decided_principal"])
def test_final_decision_cannot_be_relabelled_after_quorum(setup, field):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    edit_proposal(ctx, p.id, lambda row: row.update({field: None}))
    who = person("carol")
    with principal_scope(who), pytest.raises(PermissionError, match="audited approval"):
        ctx.gate.start_apply(p.id, who.actor)


def test_partial_vote_cannot_be_removed_from_persisted_history(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    edit_proposal(ctx, p.id, lambda row: row.update(approvals=[]))
    with pytest.raises(PermissionError, match="audited lifecycle"):
        approve(ctx, p.id, "carol")


def test_failed_vote_persistence_requires_cancellation_and_new_proposal(setup, monkeypatch):
    ctx, make, _, _ = setup
    p = propose(setup)

    def unavailable(*args):
        raise OSError("fixture persistence failure")

    monkeypatch.setattr(ctx.gate, "_save", unavailable)
    with pytest.raises(OSError):
        approve(ctx, p.id)
    restarted = make()
    with pytest.raises(PermissionError, match="audited lifecycle"):
        approve(restarted, p.id, "carol")
    who = person("carol")
    with principal_scope(who):
        restarted.gate.cancel(p.id, who.actor)
    new = propose((restarted, *setup[1:]))
    assert new.id != p.id and not new.approvals
    approve(restarted, new.id)
    assert approve(restarted, new.id, "carol").state == ProposalState.APPROVED


@pytest.mark.parametrize("operation", ["approve", "apply"])
def test_source_changed_during_assessment_cannot_be_approved_or_started(setup, operation):
    ctx, _, finding, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    if operation == "apply":
        approve(ctx, p.id, "carol")
    original = ctx.gate.assessment_validator

    def changed(*args):
        result = original(*args)
        finding.severity = Severity.LOW
        ctx.store.save_findings("sod-scan", [finding])
        return result

    ctx.gate.assessment_validator = changed
    who = person("carol")
    with principal_scope(who), pytest.raises(PermissionError):
        if operation == "apply":
            ctx.gate.start_apply(p.id, who.actor)
        else:
            ctx.gate.approve(p.id, who.actor)
    assert p.state == (ProposalState.APPROVED if operation == "apply" else ProposalState.PROPOSED)


def test_unchanged_protected_runbook_can_be_issued_after_final_validation(setup, monkeypatch):
    ctx, _, _, _ = setup
    ctx.library.get("fixture:separation").kind = "runbook"
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    adapter = SimpleNamespace(capture_before_state=lambda *args:
        BeforeState(target_id=p.host, fix_ref=p.fix_ref, dir=str(args[-1]), files=[]))
    monkeypatch.setattr(ctx.engine, "_adapter", lambda target: adapter)
    monkeypatch.setattr(ctx, "transport_for", lambda target: SimpleNamespace(close=lambda: None))
    who = person("carol")
    with principal_scope(who):
        result = ctx.engine.execute(p.id, actor=who.actor)
    assert result.state == ProposalState.APPLIED
    assert len(result.approvals) == 2 and ctx.audit.verify().ok


@pytest.mark.parametrize("kind", ["script", "runbook"])
@pytest.mark.parametrize("change", ["kill", "scope"])
def test_kill_and_scope_are_checked_after_final_quorum_validation(setup, monkeypatch, kind, change):
    ctx, _, _, _ = setup
    ctx.library.get("fixture:separation").kind = kind
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    validate = ctx.gate.validate_apply

    def changed(*args):
        validate(*args)
        if change == "kill":
            monkeypatch.setenv("CT_KILL", "1")
        else:
            ctx.inventory.get("alpha").environment = "moved"
            ctx.inventory.save()

    def forbidden(*args):
        pytest.fail("a revoked operation reached apply/runbook issuance")

    adapter = SimpleNamespace(capture_before_state=lambda *args:
        BeforeState(target_id=p.host, fix_ref=p.fix_ref, dir=str(args[-1]), files=[]), apply=forbidden)
    monkeypatch.setattr(ctx.engine, "_adapter", lambda target: adapter)
    monkeypatch.setattr(ctx.engine, "_issue_runbook", forbidden)
    monkeypatch.setattr(ctx, "transport_for", lambda target: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(ctx.gate, "validate_apply", changed)
    who = person("carol")
    with principal_scope(who), pytest.raises((PermissionError, KillSwitchEngaged)):
        ctx.engine.execute(p.id, actor=who.actor)
