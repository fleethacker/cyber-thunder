"""Decision provenance uses server identity and survives both persistence backends."""
from copy import deepcopy
from dataclasses import replace
import time

import pytest

from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.findings.review import ReviewService, evidence_fingerprint
from tests.findings.test_reviews import context, decision, observation, persist


def reviewer(**changes):
    return Principal(**{"issuer": "https://identity.example", "subject": "rivera-123", "display_name": "ITC Rivera",
                        "kind": "human", "roles": ("approver",), "expires_at": time.time() + 3600, **changes})


@pytest.fixture
def identity_env(state_dir):
    ctx = context(state_dir)
    finding = observation()
    persist(ctx, finding)
    yield ctx, ReviewService(ctx), finding
    assert ctx.audit.verify().ok
    ctx.store.close()


def test_verified_review_roundtrip_and_audit_binding(identity_env):
    ctx, service, finding = identity_env
    principal = reviewer()
    with principal_scope(principal):
        result = decision(service, finding, actor=principal.actor)
    assert result["identity_verified"] is True
    event = result["current"]
    assert event["reviewed_by"] == principal.actor
    assert event["reviewed_principal"] == principal.evidence()
    audit = list(ctx.audit.records())[0]
    assert audit["actor"] == principal.actor
    assert audit["details"]["event"] == event
    reopened = context(ctx.store.root, ctx.store.backend_name)
    try:
        assert ReviewService(reopened).history(finding) == result
    finally:
        reopened.store.close()
    # Verification records the past login; it does not require a live session to read.
    assert service.history(finding)["identity_verified"] is True


@pytest.mark.parametrize("case", ["wrong_actor", "workload", "expired", "wrong_role", "revoked"])
def test_invalid_identity_cannot_create_a_review(identity_env, case):
    ctx, service, finding = identity_env
    principal = reviewer()
    actor = principal.actor
    validity = None
    if case == "wrong_actor":
        actor = "Someone Else"
    if case == "workload":
        principal = replace(principal, kind="workload")
        actor = principal.actor
    if case == "expired":
        principal = replace(principal, expires_at=time.time() - 1)
    if case == "wrong_role":
        principal = replace(principal, roles=("viewer",))
    if case == "revoked":
        def validity():
            raise PermissionError("session revoked")
    with principal_scope(principal, validity=validity), pytest.raises(PermissionError):
        decision(service, finding, actor=actor)
    assert service.history(finding)["revision"] == 0
    assert not list(ctx.audit.records())


def test_revocation_after_pending_audit_prevents_persistence(identity_env, monkeypatch):
    ctx, service, finding = identity_env
    principal = reviewer()
    revoked = False
    append = ctx.audit.append

    def audit(*args, **kwargs):
        nonlocal revoked
        result = append(*args, **kwargs)
        revoked = True
        return result

    def validity():
        if revoked:
            raise PermissionError("revoked during write")

    monkeypatch.setattr(ctx.audit, "append", audit)
    with principal_scope(principal, validity=validity), pytest.raises(PermissionError):
        decision(service, finding, actor=principal.actor)
    assert service.history(finding)["history_count"] == 0
    assert list(ctx.audit.records())[0]["outcome"] == "pending"


def test_verified_history_survives_scan_invalidation_and_legacy_reversal(identity_env):
    ctx, service, finding = identity_env
    principal = reviewer()
    with principal_scope(principal):
        original = decision(service, finding, actor=principal.actor)
    changed = replace(finding, evidence="different scanner evidence", scan_id="scan-2")
    persist(ctx, changed, scan_id="scan-2", started_at="2026-11-05T11:00:00Z")
    reopened = service.history(changed)
    assert reopened["identity_verified"] is True and not reopened["active"]
    assert reopened["current"] == original["current"]
    assert reopened["reopened_reason"]
    legacy = decision(service, changed, disposition="unreviewed", expires_at=None)
    assert legacy["identity_verified"] is False
    assert legacy["history"][0]["reviewed_principal"] == principal.evidence()


@pytest.mark.parametrize("new_owner", [None,
    {"version": 1, "target_id": "range-01", "environment": "B", "authorization_id": "generation-1"},
    {"version": 1, "target_id": "range-01", "environment": "A", "authorization_id": "generation-2"},
])
def test_changed_ownership_cannot_read_or_inherit_a_review(identity_env, monkeypatch, new_owner):
    ctx, service, finding = identity_env
    owner = {"version": 1, "target_id": "range-01", "environment": "A", "authorization_id": "generation-1"}
    finding.authorization_scope = owner
    current = [finding]
    monkeypatch.setattr(ctx.store, "current_findings", lambda: current)
    principal = reviewer()
    with principal_scope(principal):
        original = decision(service, finding, actor=principal.actor, reason="A-only decision")
    path = service._path(finding)
    persisted = ctx.store.read_json(path)
    changed = replace(finding)
    changed.authorization_scope = new_owner
    current[:] = [changed]
    assert evidence_fingerprint(changed) != evidence_fingerprint(finding)
    view = service.history(changed)
    assert view["history"] == [] and view["history_count"] == 0
    assert view["current"] is None and view["identity_verified"] is False
    assert view["disposition"] == "unreviewed" and not view["suppressed"]
    assert ctx.store.read_json(path) == persisted
    replacement = decision(service, changed, reason="New owner's decision")
    assert replacement["history_count"] == 1 and len(replacement["history"]) == 1
    assert replacement["current"]["identity_verified"] is False
    assert "A-only" not in str(replacement)
    assert ctx.store.read_json(path)["history"][0] == original["current"]


def test_new_owned_finding_does_not_retroverify_legacy_review(identity_env):
    _, service, finding = identity_env
    legacy = decision(service, finding)
    owned = replace(finding)
    owned.authorization_scope = {"version": 1, "target_id": "range-01", "environment": "A",
                                 "authorization_id": "new-generation"}
    view = service.history(owned)
    assert view["history"] == [] and view["current"] is None
    assert view["identity_verified"] is False and not view["suppressed"]
    assert service.history(finding) == legacy


@pytest.mark.parametrize("dev", [False, True])
def test_legacy_and_dev_labels_never_gain_verification(identity_env, dev):
    ctx, service, finding = identity_env
    principal = Principal("local", "ITC Rivera", "ITC Rivera", kind="dev", via="dev") if dev else None
    with principal_scope(principal):
        result = decision(service, finding)
    assert result["identity_verified"] is False
    assert result["current"].get("reviewed_principal") is None
    assert service.history(finding) == result


@pytest.mark.parametrize("tamper", ["flag_only", "actor", "subject", "issuer", "kind", "source", "bool",
                                    "extra_secret", "false_with_principal", "bad_name"])
def test_forged_stored_identity_is_rejected_without_overwriting_history(identity_env, tamper):
    ctx, service, finding = identity_env
    principal = reviewer()
    with principal_scope(principal):
        decision(service, finding, actor=principal.actor)
    path = service._path(finding)
    doc = ctx.store.read_json(path)
    event = doc["history"][0]
    if tamper == "flag_only":
        del event["reviewed_principal"]
    elif tamper == "actor":
        event["reviewed_by"] = "typed-label"
    elif tamper == "false_with_principal":
        event["identity_verified"] = False
    else:
        field, value = {"subject": ("sub", "different"), "issuer": ("iss", "https://other.example"),
                        "kind": ("kind", "workload"), "source": ("via", "dev"),
                        "bool": ("verified", 1), "extra_secret": ("access_token", "must not persist"),
                        "bad_name": ("name", "line\nbreak")}[tamper]
        event["reviewed_principal"][field] = value
    ctx.store.write_json(path, doc)
    before = deepcopy(doc)
    with pytest.raises((ValueError, TypeError)):
        service.history(finding)
    assert ctx.store.read_json(path) == before
