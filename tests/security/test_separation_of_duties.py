"""Separation of duties through the real gate, persisted findings and API boundary."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import json
import socket
from threading import Barrier, local
import time

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.approvals import IllegalTransition, ProposalState
from cyberthunder.control.policy import AutomationPolicy, PolicyRule, save_policy
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.control.separation import RESERVED_FIELDS
from cyberthunder.findings.schema import Finding, Severity, Status
from cyberthunder.inventory.targets import Target
from cyberthunder.remediation.library import FixEntry, FixLibrary
from cyberthunder.security.resources import target_scope

ISSUER = "https://identity.example.test"
ACK = "Reviewed the unresolved dependencies and the recovery procedure with the owner."


def person(subject, *, issuer=ISSUER, roles=("analyst", "approver"), kind="human", **kw):
    return Principal(issuer, subject, "Operator", kind=kind, roles=roles, expires_at=time.time() + 600, **kw)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("separation tests must not contact a target or external service")
    original_pair, original_connect = socket.socketpair, socket.socket.connect
    creating_pair = local()

    def socketpair(*args, **kwargs):
        # Windows implements the event loop's internal wake-up socket using an
        # ephemeral loopback pair. Only that construction may connect.
        creating_pair.active = True
        try:
            return original_pair(*args, **kwargs)
        finally:
            creating_pair.active = False

    def connect(sock, address):
        if getattr(creating_pair, "active", False) and address[0] in {"127.0.0.1", "::1"}:
            return original_connect(sock, address)
        forbidden()

    monkeypatch.setattr(socket, "socketpair", socketpair)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(AppContext, "transport_for", forbidden)


@pytest.fixture
def setup(state_dir):
    contexts = []
    fix = FixEntry("fixture:separation", "Change a setting", "linux", ["fixture-rule"],
                   payload="reviewed fixture payload", before_state={"files": ["/etc/fixture"]})

    def make(*, mode="oidc"):
        ctx = AppContext(Settings(state_dir=state_dir, auth_mode=mode, security_mode="range",
                                  llm_backend="template", auto_propose=False, explain_precompute=False))
        ctx.library = FixLibrary([deepcopy(fix)])
        contexts.append(ctx)
        return ctx

    ctx = make()
    for tid in ("alpha", "beta"):
        ctx.inventory.add(Target(tid, tid, "linux", "simulated", simulated=True, environment=tid))
    ctx.inventory.save()
    folder = state_dir / "auth"
    folder.mkdir(mode=0o700)
    entries = [{"issuer": issuer, "subject": subject, "node_actions": [],
                "grants": [{"target_ids": [target], "actions": ["read", "propose", "approve", "deny", "cancel",
                                                                "apply", "review", "plan"]}]}
               for issuer, subject, target in ((ISSUER, "alice", "alpha"), (ISSUER, "bob", "alpha"),
                                               (ISSUER, "carol", "alpha"), (ISSUER, "mallory", "beta"),
                                               (ISSUER, "admin", "alpha"), (ISSUER, "service", "alpha"),
                                               (ISSUER + "/second", "bob", "alpha"))]
    path = folder / "access.json"
    path.write_text(json.dumps({"version": 1, "entries": entries}), encoding="utf-8")
    path.chmod(0o600)
    ctx.store.save_scan_run({"id": "sod-scan", "targets": ["alpha"], "status": "done"})
    finding = Finding(host="alpha", source="fixture", rule_id="fixture-rule", title="Fixture finding",
                      severity=Severity.HIGH, status=Status.OPEN, asset_type="linux", evidence="fixture evidence")
    finding.authorization_scope = target_scope(ctx.inventory.get("alpha"))
    ctx.store.save_findings("sod-scan", [finding])
    yield ctx, make, finding, path
    for context in contexts:
        context.store.close()


def propose(setup, *, subject="alice", actor=None):
    ctx, _, finding, _ = setup
    who = person(subject)
    with principal_scope(who):
        return ctx.engine.propose(deepcopy(finding), actor=who.actor if actor is None else actor)


def approve(ctx, pid, subject="bob", **kwargs):
    who = person(subject)
    with principal_scope(who):
        return ctx.gate.approve(pid, who.actor, **kwargs)


def edit_proposal(ctx, pid, change):
    rows = json.loads(ctx.gate.store.read_text(encoding="utf-8"))
    change(next(row for row in rows if row["id"] == pid))
    ctx.gate.store.write_text(json.dumps(rows), encoding="utf-8")


def test_cat_i_requires_two_other_people_and_partial_decision_survives_restart(setup):
    ctx, make, _, _ = setup
    p = propose(setup)
    assert p.proposed_by == person("alice").actor
    assert p.proposed_principal["sub"] == "alice" and p.required_approvals == 2
    first = approve(ctx, p.id)
    assert first.state == ProposalState.PROPOSED and first.decided_by is None
    assert len(first.approvals) == 1
    other = make()
    reloaded = other.gate.get(p.id)
    assert reloaded.approvals == first.approvals
    with principal_scope(person("carol")):
        with pytest.raises(IllegalTransition):
            other.gate.start_apply(p.id, person("carol").actor)
    complete = approve(other, p.id, "carol")
    assert complete.state == ProposalState.APPROVED and len(complete.approvals) == 2
    assert ctx.gate.get(p.id).approvals == complete.approvals
    with principal_scope(person("carol")):
        assert other.gate.start_apply(p.id, person("carol").actor).state == ProposalState.APPLYING
    assert ctx.audit.verify().ok


@pytest.mark.parametrize("service_label", [False, True])
def test_proposer_is_stable_and_cannot_self_approve_even_after_renaming(setup, service_label):
    ctx, _, _, _ = setup
    p = propose(setup, actor="agent:planner" if service_label else None)
    renamed = replace(person("alice"), display_name="Renamed operator", roles=("approver",), groups=("new-group",))
    with principal_scope(renamed), pytest.raises(PermissionError, match="proposer"):
        ctx.gate.approve(p.id, renamed.actor)
    assert p.proposed_principal["name"] == "Operator" and not p.approvals
    assert any(r["outcome"] == "rejected" and "proposer" in r["details"].get("reason", "")
               for r in ctx.audit.records())


def test_duplicate_is_same_issuer_and_subject_despite_new_session_or_display_name(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    changed = replace(person("bob"), display_name="Different name", session_id="new-session")
    with principal_scope(changed), pytest.raises(PermissionError, match="already approved"):
        ctx.gate.approve(p.id, changed.actor)
    assert len(p.approvals) == 1 and p.state == ProposalState.PROPOSED


def test_same_subject_from_another_explicitly_authorized_issuer_is_distinct(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    other = person("bob", issuer=ISSUER + "/second")
    with principal_scope(other):
        assert ctx.gate.approve(p.id, other.actor).state == ProposalState.APPROVED


@pytest.mark.parametrize("who", [person("mallory"), person("admin", roles=("admin",)),
                                  person("bob", roles=("analyst",)), person("service", kind="workload"),
                                  replace(person("bob"), expires_at=1)])
def test_each_approval_requires_current_human_role_session_and_target_permission(setup, who):
    ctx, _, _, _ = setup
    p = propose(setup)
    with principal_scope(who), pytest.raises(PermissionError):
        ctx.gate.approve(p.id, who.actor)
    assert not p.approvals
    assert any(r["outcome"] == "rejected" for r in ctx.audit.records())


@pytest.mark.parametrize("operation", ["propose", "approve"])
def test_direct_actor_spoof_is_refused(setup, operation):
    ctx, _, finding, _ = setup
    p = propose(setup)
    with principal_scope(person("bob")), pytest.raises(PermissionError):
        if operation == "approve":
            ctx.gate.approve(p.id, person("carol").actor)
        else:
            ctx.engine.propose(finding, actor=person("alice").actor)
    assert not p.approvals


def test_workload_to_human_role_change_cannot_hide_the_original_proposer(setup):
    ctx, _, finding, _ = setup
    with principal_scope(person("service", kind="workload", roles=("analyst",))):
        p = ctx.engine.propose(finding, actor="agent:planner")
    who = person("service", kind="human", roles=("approver",))
    with principal_scope(who), pytest.raises(PermissionError, match="proposer"):
        ctx.gate.approve(p.id, who.actor)


def test_live_proposal_reuse_cannot_disclose_a_different_targets_record(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    with principal_scope(person("mallory")), pytest.raises(PermissionError):
        ctx.gate.propose(actor=person("mallory").actor, finding_id=p.finding_id, host="beta",
                         one_live_per_finding=True)


def test_revoked_session_and_target_grant_stop_the_next_approval(setup):
    ctx, _, _, path = setup
    p = propose(setup)
    approve(ctx, p.id)

    def expired():
        raise PermissionError("session ended")

    with principal_scope(person("carol"), validity=expired), pytest.raises(PermissionError):
        ctx.gate.approve(p.id, person("carol").actor)
    doc = json.loads(path.read_text())
    doc["entries"] = [e for e in doc["entries"] if e["subject"] != "carol"]
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(PermissionError):
        approve(ctx, p.id, "carol")
    assert len(p.approvals) == 1 and p.state == ProposalState.PROPOSED


def test_revocation_during_assessment_validation_stops_before_recording_a_vote(setup):
    ctx, _, _, path = setup
    p = propose(setup)
    original = ctx.gate.assessment_validator

    def revoked(*args):
        result = original(*args)
        path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        return result

    ctx.gate.assessment_validator = revoked
    with pytest.raises(PermissionError):
        approve(ctx, p.id)
    assert not p.approvals
    assert not any("approval" in r["details"] for r in ctx.audit.records())


@pytest.mark.parametrize("severity,count", [("high", 2), ("medium", 1), ("low", 1), ("info", 1), ("unknown", 2)])
def test_requirement_is_from_persisted_severity_not_call_metadata(setup, severity, count):
    ctx, _, finding, _ = setup
    finding.severity = Severity(severity)
    ctx.store.save_findings("sod-scan", [finding])
    fix = ctx.library.get("fixture:separation")
    with principal_scope(person("alice")):
        p = ctx.gate.propose(actor=person("alice").actor, finding_id=finding.id, host=finding.host,
                             title=finding.title, fix_ref=fix.fix_ref, fix_preview=fix.preview_text(),
                             rollback_plan="restore", risk="fixture", meta={"severity": "low", "fix_sha256": "fake"})
    assert p.required_approvals == count
    assert p.history[0]["meta"]["severity"] == severity
    assert p.history[0]["meta"]["fix_sha256"] != "fake"
    first = approve(ctx, p.id)
    assert first.state == (ProposalState.APPROVED if count == 1 else ProposalState.PROPOSED)


@pytest.mark.parametrize("field", sorted(RESERVED_FIELDS))
def test_callers_cannot_supply_managed_requirement_or_identity_fields(setup, field):
    ctx, _, _, _ = setup
    with principal_scope(person("alice")), pytest.raises(PermissionError, match="server-managed"):
        ctx.gate.propose(actor=person("alice").actor, **{field: 1})
    assert ctx.gate.list() == []


@pytest.mark.parametrize("field,value", [("required_approvals", 1), ("required_approvals", True),
                                         ("fix_preview", "different payload"), ("proposed_by", "someone else"),
                                         ("approval_requirements", None)])
def test_persisted_requirement_and_payload_tampering_cannot_lower_the_bar(setup, field, value):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    edit_proposal(ctx, p.id, lambda row: row.update({field: value}))
    with pytest.raises(PermissionError):
        approve(ctx, p.id, "carol")


def test_fully_recomputed_lower_requirement_still_disagrees_with_creation_audit(setup):
    ctx, _, _, _ = setup
    p = propose(setup)

    def lower(row):
        row["required_approvals"] = 1
        row["approval_requirements"]["required_approvals"] = 1
        row["approval_requirements"]["source"]["severity"] = "low"

    edit_proposal(ctx, p.id, lower)
    with pytest.raises(PermissionError, match="creation record"):
        approve(ctx, p.id)


@pytest.mark.parametrize("change", ["lower_severity", "higher_severity", "fix", "target_generation", "missing_finding"])
def test_fresh_server_facts_cannot_change_under_pending_approvals(setup, change):
    ctx, _, finding, _ = setup
    if change == "higher_severity":
        finding.severity = Severity.MEDIUM
        ctx.store.save_findings("sod-scan", [finding])
    p = propose(setup)
    if change in {"lower_severity", "higher_severity"}:
        finding.severity = Severity.LOW if change == "lower_severity" else Severity.HIGH
        ctx.store.save_findings("sod-scan", [finding])
    elif change == "fix":
        ctx.library.get(p.fix_ref).payload = "changed payload"
    elif change == "target_generation":
        ctx.inventory.get("alpha").environment = "changed"
        ctx.inventory.save()
    else:
        ctx.store.save_findings("sod-scan", [])
    with pytest.raises(PermissionError):
        approve(ctx, p.id)


def test_forged_persisted_vote_does_not_satisfy_start_apply(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)

    def forge(row):
        fake = deepcopy(row["approvals"][0])
        fake.update(id="forged-vote", actor=person("carol").actor, principal=person("carol").evidence())
        row["approvals"].append(fake)
        row["state"] = "approved"

    edit_proposal(ctx, p.id, forge)
    with principal_scope(person("carol")), pytest.raises(PermissionError, match="audited"):
        ctx.gate.start_apply(p.id, person("carol").actor)


def test_approval_audit_carries_exact_immutable_identity_payload_and_assessment(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    first = deepcopy(p.approvals[0])
    approve(ctx, p.id, "carol")
    events = [r for r in ctx.audit.records() if "approval" in r["details"]]
    assert len(events) == 2 and events[0]["details"]["state"] == "proposed"
    for vote, event in zip(p.approvals, events):
        assert event["details"]["approval"] == vote
        assert event["principal"] == vote["principal"]
        assert vote["payload_sha256"] == p.approval_requirements["payload_sha256"]
        assert vote["assessment"]["status"] == "not_assessed"
    assert p.approvals[0] == first and ctx.audit.verify().ok


def test_missing_creation_audit_blocks_verified_approval(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    ctx.audit.path.write_text("", encoding="utf-8")
    with pytest.raises(PermissionError, match="audit integrity"):
        approve(ctx, p.id)
    assert not p.approvals


@pytest.mark.parametrize("subjects", [("bob", "carol"), ("bob", "bob")])
def test_concurrent_gate_instances_preserve_distinct_partial_approvals(setup, subjects):
    ctx, make, _, _ = setup
    p = propose(setup)
    gates = [make(), make()]
    barrier = Barrier(2)

    def decide(i):
        who = person(subjects[i])
        with principal_scope(who):
            barrier.wait(timeout=10)
            try:
                gates[i].gate.approve(p.id, who.actor)
                return True
            except PermissionError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, range(2)))
    saved = make().gate.get(p.id)
    assert sum(results) == len(set(subjects)) == len(saved.approvals)
    assert saved.state == (ProposalState.APPROVED if len(set(subjects)) == 2 else ProposalState.PROPOSED)
    assert ctx.audit.verify().ok


def test_different_assessment_receipts_cannot_be_combined_and_single_rereview_cannot_replace_quorum(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    with principal_scope(person("bob")):
        first = ctx.impact.assess(p.id, actor=person("bob").actor, live=False)
    approve(ctx, p.id, assessment_id=first["id"], assessment_note=ACK)
    with principal_scope(person("carol")):
        second = ctx.impact.assess(p.id, actor=person("carol").actor, live=False)
    with pytest.raises(PermissionError, match="same assessment"):
        approve(ctx, p.id, "carol", assessment_id=second["id"], assessment_note=ACK)
    approve(ctx, p.id, "carol", assessment_id=first["id"], assessment_note="I reviewed the same dependency receipt.")
    with principal_scope(person("carol")), pytest.raises(PermissionError, match="fresh approvals"):
        ctx.gate.review_assessment(p.id, person("carol").actor, second["id"], ACK)
    assert p.state == ProposalState.APPROVED and p.assessment["id"] == first["id"]
    assert {vote["assessment"]["id"] for vote in p.approvals} == {first["id"]}


def test_assessment_change_after_quorum_blocks_start_apply(setup):
    ctx, _, _, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    edit_proposal(ctx, p.id, lambda row: row.update(assessment={"status": "reviewed", "id": "forged"}))
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, person("carol").actor)


@pytest.mark.parametrize("change", ["finding", "separation_source", "authorizer"])
def test_apply_revalidates_current_server_facts_and_cannot_drop_verified_wiring(setup, change):
    ctx, _, finding, _ = setup
    p = propose(setup)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    if change == "finding":
        finding.severity = Severity.LOW
        ctx.store.save_findings("sod-scan", [finding])
    else:
        setattr(ctx.gate, change, None)
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.engine.execute(p.id, actor=person("carol").actor)
    assert ctx.gate.get(p.id).state == ProposalState.APPROVED


@pytest.mark.parametrize("approved", [False, True])
def test_legacy_decisions_remain_readable_but_cannot_be_upgraded_in_verified_mode(setup, approved):
    ctx, make, finding, _ = setup
    dev = make(mode="dev")
    p = dev.engine.propose(finding, actor="Local proposer")
    if approved:
        dev.gate.approve(p.id, "Local approver")
    raw = json.loads(dev.gate.store.read_text())
    for row in raw:
        for key in RESERVED_FIELDS:
            row.pop(key, None)
    dev.gate.store.write_text(json.dumps(raw))
    loaded = ctx.gate.get(p.id)
    assert loaded.approval_requirements is None and loaded.approvals == []
    before = dev.gate.store.read_bytes()
    with principal_scope(person("bob")), pytest.raises(PermissionError, match="legacy"):
        if approved:
            ctx.gate.start_apply(p.id, person("bob").actor)
        else:
            ctx.gate.approve(p.id, person("bob").actor)
    assert dev.gate.store.read_bytes() == before


def test_explicit_unverified_development_mode_enforces_rule_without_claiming_verified_people(setup):
    _, make, finding, _ = setup
    ctx = make(mode="dev")
    ctx.gate.unverified_separation = True
    p = ctx.engine.propose(finding, actor="Alice")
    assert p.approval_requirements["mode"] == "unverified_dev"
    assert p.proposed_principal["verified"] is False
    with pytest.raises(PermissionError, match="proposer"):
        ctx.gate.approve(p.id, "ALICE")
    ctx.gate.approve(p.id, "Bob")
    with pytest.raises(PermissionError, match="already approved"):
        ctx.gate.approve(p.id, "BOB")
    ctx.gate.unverified_separation = False  # Persisted requirements cannot be turned off later.
    assert ctx.gate.approve(p.id, "Carol").state == ProposalState.APPROVED
    assert all(v["principal"]["verified"] is False for v in p.approvals)


@pytest.mark.parametrize("method", ["policy", "approve", "move"])
@pytest.mark.parametrize("partial", [False, True])
def test_no_policy_or_internal_transition_can_satisfy_cat_i(setup, method, partial):
    _, make, finding, _ = setup
    ctx = make(mode="dev")
    ctx.gate.unverified_separation = True
    p = ctx.engine.propose(finding, actor="Alice")
    policy = AutomationPolicy(rules=[PolicyRule("test", max_severity=None)])
    policy.sign("Signer", "test policy")
    save_policy(ctx.store.policy, policy)
    if partial:
        ctx.gate.approve(p.id, "Bob")
    with pytest.raises(PermissionError):
        if method == "policy":
            ctx.gate.approve_by_policy(p.id, policy)
        elif method == "approve":
            ctx.gate.approve(p.id, "policy:Signer")
        else:
            ctx.gate._move(p.id, ProposalState.APPROVED, "Bob")
    assert p.state == ProposalState.PROPOSED and len(p.approvals) == int(partial)


@pytest.fixture
def api(setup, monkeypatch):
    ctx, _, _, _ = setup
    tokens = {}

    class Validator:
        def validate(self, token):
            p = tokens[token]
            return {"iss": p.issuer, "sub": p.subject, "name": p.display_name, "ct_kind": p.kind,
                    "ct_roles": list(p.roles), "exp": p.expires_at}

    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *_: Validator())

    def headers(subject, **kw):
        token = f"fixture-{len(tokens)}"
        tokens[token] = person(subject, **kw)
        return {"Authorization": "Bearer " + token, "X-Actor": "forged operator"}

    with TestClient(create_app(ctx)) as client:
        yield client, headers


def test_api_proposal_and_two_approvals_ignore_client_thresholds_and_actor_spoofing(setup, api):
    ctx, _, finding, _ = setup
    client, headers = api
    response = client.post(f"/api/v1/findings/{finding.id}/propose", headers=headers("alice"),
                           json={"severity": "low", "required_approvals": 1, "proposed_by": "someone else"})
    assert response.status_code == 200, response.text
    p = response.json()
    assert p["required_approvals"] == 2 and p["proposed_principal"]["sub"] == "alice"
    path = f"/api/v1/proposals/{p['id']}/approve"
    assert client.post(path, headers=headers("alice"), json={}).status_code == 403
    for subject, kw in [("mallory", {}), ("admin", {"roles": ("admin",)}), ("service", {"kind": "workload"})]:
        assert client.post(path, headers=headers(subject, **kw), json={}).status_code == 403
    first = client.post(path, headers=headers("bob"), json={"required_approvals": 1, "severity": "low"})
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "proposed" and len(first.json()["approvals"]) == 1
    assert client.post(path, headers=headers("bob"), json={}).status_code == 403
    last = client.post(path, headers=headers("carol"), json={})
    assert last.status_code == 200, last.text
    assert last.json()["state"] == "approved" and len(last.json()["approvals"]) == 2
    assert "forged operator" not in ctx.audit.path.read_text()


def test_api_bulk_preserves_partial_state_and_rejects_duplicate_vote(setup, api):
    p = propose(setup)
    client, headers = api
    body = {"action": "approve", "ids": [p.id, p.id]}
    response = client.post("/api/v1/proposals/bulk", headers=headers("bob"), json=body)
    assert response.status_code == 200, response.text
    results = response.json()["results"]
    assert results[0]["state"] == "proposed" and results[1]["status"] == 403


def test_api_can_read_legacy_proposal_without_upgrading_its_authority(setup, api):
    ctx, make, finding, _ = setup
    dev = make(mode="dev")
    p = dev.engine.propose(finding, actor="Local proposer")
    client, headers = api
    path = f"/api/v1/proposals/{p.id}"
    response = client.get(path, headers=headers("bob"))
    assert response.status_code == 200, response.text
    assert response.json()["approval_requirements"] is None
    before = ctx.gate.store.read_bytes()
    refused = client.post(path + "/approve", headers=headers("bob"), json={})
    assert refused.status_code == 403 and "legacy" in refused.json()["detail"]
    assert ctx.gate.store.read_bytes() == before
