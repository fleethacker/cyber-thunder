"""Operator risk decisions retain scanner evidence and share the review lifecycle ledger."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings import review
from cyberthunder.findings.review import ReviewConflict, ReviewService
from tests.findings.test_reviews import context, decision, env, persist


def accept(service, finding, **changes):
    summary = service.summary(finding)
    args = dict(actor="ITC Rivera", reason="Temporary operational constraint",
                supporting_evidence="Owner's maintenance-window record",
                expires_at=(datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
                expected_revision=summary["revision"], evidence_fingerprint=summary["evidence_fingerprint"])
    return service.accept_risk(finding, **(args | changes))


def revoke(service, finding, **changes):
    summary = service.summary(finding)
    return service.revoke_risk(finding, **(dict(actor="ITC Rivera", reason="Maintenance window available",
        expected_revision=summary["revision"], evidence_fingerprint=summary["evidence_fingerprint"]) | changes))


def test_accept_revoke_restart_retains_scanner_and_exact_decision(env):
    ctx, service, finding = env
    raw = ctx.store.read_json(ctx.store.scans_dir / finding.scan_id / "findings.json")
    accepted = accept(service, finding)
    assert accepted["remediation_held"] and not accepted["suppressed"]
    assert accepted["disposition"] == "risk_accepted" and accepted["risk_acceptance_status"] == "active"
    assert accepted["current"]["identity_verified"] is False
    other = context(ctx.store.root, ctx.store.backend_name)
    try:
        assert ReviewService(other).history(finding) == accepted
    finally:
        other.store.close()
    reversed_view = revoke(service, finding)
    assert reversed_view["risk_acceptance_status"] == "revoked"
    assert not reversed_view["active"] and not reversed_view["remediation_held"]
    assert reversed_view["disposition"] == "unreviewed"
    assert reversed_view["history"][0] == accepted["current"]
    assert ctx.store.read_json(ctx.store.scans_dir / finding.scan_id / "findings.json") == raw
    pending = [r for r in ctx.audit.records() if r["outcome"] == "pending"]
    assert [r["details"]["event"] for r in pending] == reversed_view["history"]
    assert all(r["action"] == "finding.risk_acceptance" for r in pending)


@pytest.mark.parametrize("change", [dict(reason=" "), dict(supporting_evidence=" "), dict(expires_at=None),
    dict(expires_at="2099-01-01T00:00:00Z"), dict(expires_at="2020-01-01T00:00:00Z"),
    dict(expires_at="2026-12-01"), dict(expires_at="2026-12-01T00:00:00"), dict(actor="agent")])
def test_invalid_or_unbounded_acceptance_leaves_no_decision(env, change):
    ctx, service, finding = env
    with pytest.raises((ValueError, PermissionError)):
        accept(service, finding, **change)
    assert service.history(finding)["revision"] == 0
    assert not list(ctx.audit.records())


@pytest.mark.parametrize("status", ["not_a_finding", "not_applicable", "not_reviewed", "error"])
def test_only_open_scanner_observations_can_have_risk_accepted(env, status):
    ctx, service, finding = env
    finding = replace(finding, status=status)
    persist(ctx, finding)
    with pytest.raises(ValueError, match="open scanner"):
        accept(service, finding)


@pytest.mark.parametrize("disposition", sorted(review.DISPOSITIONS | review.RISK_DECISIONS))
def test_generic_save_cannot_create_revoke_or_replace_active_acceptance(env, disposition):
    _, service, finding = env
    original = accept(service, finding)
    with pytest.raises((ReviewConflict, ValueError)):
        decision(service, finding, disposition=disposition)
    assert service.history(finding) == original


def test_exact_cap_and_expiry_boundary_then_ordinary_review(env, monkeypatch):
    _, service, finding = env
    now = datetime.now(timezone.utc)
    original_now = review._now
    monkeypatch.setattr(review, "_now", lambda value=None: original_now(value) if value else now)
    expiry = now + timedelta(days=30)
    original = accept(service, finding, expires_at=expiry.isoformat())
    assert service.summary(finding, now=expiry - timedelta(microseconds=1))["remediation_held"]
    expired = service.summary(finding, now=expiry)
    assert expired["risk_acceptance_status"] == "expired" and not expired["remediation_held"]
    assert expired["current"] == original["current"]
    now = expiry
    changed = decision(service, finding, disposition="confirmed", expires_at=None)
    assert changed["risk_acceptance_status"] == "expired" and changed["history"][0] == original["current"]


def test_relevant_change_and_recurrence_durably_reopen_acceptance(env):
    ctx, service, finding = env
    original = accept(service, finding)
    changed = replace(finding, status="not_a_finding", scan_id="scan-2")
    persist(ctx, changed, "scan-2", "2026-11-05T11:00:00Z")
    persist(ctx, replace(finding, scan_id="scan-3"), "scan-3", "2026-11-05T12:00:00Z")
    reopened = service.history(finding)
    assert reopened["risk_acceptance_status"] == "reopened" and not reopened["remediation_held"]
    assert reopened["history"] == [original["current"]]
    assert reopened["revision"] == 2 and reopened["reopened_reason"]
    assert service.summary(changed)["risk_acceptance_status"] == "reopened"


@pytest.mark.parametrize("part", ["environment", "authorization_id"])
def test_reassignment_does_not_disclose_or_carry_acceptance_to_new_owner(env, part):
    ctx, service, finding = env
    finding.authorization_scope = dict(version=1, target_id=finding.host, environment="A", authorization_id="first")
    persist(ctx, finding)
    accepted = accept(service, finding)
    moved = replace(finding, authorization_scope=finding.authorization_scope | {part: "new"})
    persist(ctx, moved, "scan-2", "2026-11-05T11:00:00Z")
    view = service.history(moved)
    assert not view["remediation_held"] and view["risk_acceptance_status"] == "none"
    assert view["history"] == [] and view["current"] is None
    assert ctx.store.read_json(service._path(finding))["history"] == [accepted["current"]]
    persist(ctx, finding, "scan-3", "2026-11-05T12:00:00Z")
    assert service.summary(finding)["risk_acceptance_status"] == "reopened"


def test_decision_race_has_exactly_one_winner(env):
    _, service, finding = env
    def attempt(_):
        try:
            return accept(service, finding, expected_revision=0)
        except ReviewConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sum(result is not None for result in results) == 1
    assert service.history(finding)["history_count"] == 1


@pytest.mark.parametrize("operation", ["accept", "revoke"])
def test_audit_failure_kill_and_apply_lock_prevent_decision(env, monkeypatch, operation):
    ctx, service, finding = env
    if operation == "revoke":
        accept(service, finding)
    act = accept if operation == "accept" else revoke
    before = service.history(finding)
    with service.remediation_guard(finding), pytest.raises(ReviewConflict):
        act(service, finding)
    ctx.killswitch.engage("ITC Rivera", "test stop")
    with pytest.raises(KillSwitchEngaged):
        act(service, finding)
    ctx.killswitch.release("ITC Rivera", "test release")
    def fail(*args, **kwargs):
        raise OSError("audit unavailable")
    monkeypatch.setattr(ctx.audit, "append", fail)
    with pytest.raises(OSError):
        act(service, finding)
    assert service.history(finding) == before


def test_history_reserves_a_slot_for_authorized_revocation(env, monkeypatch):
    _, service, finding = env
    monkeypatch.setattr(review, "MAX_HISTORY_EVENTS", 2)
    accept(service, finding)
    with pytest.raises(ReviewConflict):
        accept(service, finding)
    assert revoke(service, finding)["revision"] == 2
