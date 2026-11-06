"""Protected person quorums preserve each acting account's independent authority."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from cyberthunder.control import separation
from cyberthunder.control.access import AccessDenied
from cyberthunder.control.approvals import ProposalState
from cyberthunder.control.principal import principal_scope
from tests.security.test_separation_of_duties import (
    ISSUER, api, approve, edit_proposal, offline, person, propose, setup,
)


def write_policy(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")


@pytest.fixture
def mapped(setup):
    ctx, _, _, path = setup
    document = json.loads(path.read_text())
    document.update(version=2, approval_identity={"mode": "person", "version": 1,
                                                 "namespace": "operators", "revision": 1})
    for i, entry in enumerate(document["entries"]):
        entry["person_id"] = f"p-{i}"
    for subject in ("alice", "bob"):
        alias = deepcopy(next(e for e in document["entries"] if e.get("subject") == subject))
        alias["subject"] += "-admin"
        document["entries"].append(alias)
    write_policy(path, document)
    return setup


def mutate(path, change):
    doc = json.loads(path.read_text())
    if change == "missing_file":
        path.unlink()
        return
    if change == "whitespace":
        path.write_text(path.read_text() + "\n")
        return
    if change == "revoked":
        doc["entries"][1].pop("person_id")
    elif change == "relinked":
        doc["entries"][1]["person_id"] = "p-other"
    elif change == "revision":
        doc["approval_identity"]["revision"] += 1
    elif change == "namespace":
        doc["approval_identity"]["namespace"] = "replacement"
    elif change == "unknown_version":
        doc["approval_identity"]["version"] = 2
    elif change == "unrelated_grant":
        doc["entries"][-1]["node_actions"] = ["read"]
    elif change == "downgrade":
        doc["version"] = 1
        doc.pop("approval_identity")
        for entry in doc["entries"]:
            entry.pop("person_id", None)
    write_policy(path, doc)


def test_other_account_of_proposer_and_second_vote_of_same_person_are_refused(mapped):
    ctx, _, _, path = mapped
    p = propose(mapped)
    with pytest.raises(PermissionError, match="proposer"):
        approve(ctx, p.id, "alice-admin")
    approve(ctx, p.id, "bob")
    with pytest.raises(PermissionError, match="already approved"):
        approve(ctx, p.id, "bob-admin")
    assert p.state == ProposalState.PROPOSED and len(p.approvals) == 1
    vote = p.approvals[0]
    assert vote["principal"]["sub"] == "bob"
    assert vote["person_association"]["person_id"] == "p-1"
    assert vote["person_association"]["source"]["policy_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert p.history[-1]["person_association"] == vote["person_association"]
    assert p.proposed_principal["sub"] == "alice" and p.approval_requirements["version"] == 2
    rejected = [r for r in ctx.audit.records() if r["outcome"] == "rejected"]
    assert {r["principal"]["sub"] for r in rejected} == {"alice-admin", "bob-admin"}
    approve(ctx, p.id, "carol")
    assert p.state == ProposalState.APPROVED
    assert ctx.audit.verify().ok


@pytest.mark.parametrize("severity,count", [("high", 2), ("unknown", 2), ("medium", 1), ("low", 1), ("info", 1)])
def test_distinct_mapped_people_complete_quorum_and_survive_restart(mapped, severity, count):
    from cyberthunder.findings.schema import Severity
    ctx, make, finding, _ = mapped
    finding.severity = Severity(severity)
    ctx.store.save_findings("sod-scan", [finding])
    p = propose(mapped, actor="agent:planner")
    approve(ctx, p.id)
    restarted = make()
    if count == 2:
        approve(restarted, p.id, "carol")
    with principal_scope(person("carol")):
        restarted.gate.start_apply(p.id, person("carol").actor)
        restarted.gate.validate_apply(p.id, person("carol").actor)
    assert len(restarted.gate.get(p.id).approvals) == count


@pytest.mark.parametrize("same_person", [False, True])
def test_different_issuers_only_correlate_by_explicit_mapping(mapped, same_person):
    ctx, _, _, path = mapped
    if same_person:
        doc = json.loads(path.read_text())
        doc["entries"][6]["person_id"] = doc["entries"][1]["person_id"]
        write_policy(path, doc)
    p = propose(mapped)
    approve(ctx, p.id)
    other = person("bob", issuer=ISSUER + "/second")
    with principal_scope(other):
        if same_person:
            with pytest.raises(PermissionError, match="already approved"):
                ctx.gate.approve(p.id, other.actor)
        else:
            ctx.gate.approve(p.id, other.actor)
            assert p.state == ProposalState.APPROVED


@pytest.mark.parametrize("stage", ["approve", "start_apply", "validate_apply"])
@pytest.mark.parametrize("change", ["revoked", "relinked", "revision", "namespace", "unknown_version",
                                    "unrelated_grant", "whitespace", "downgrade", "missing_file"])
def test_policy_changes_fail_closed_at_each_operation_boundary(mapped, stage, change):
    ctx, make, _, path = mapped
    p = propose(mapped)
    approve(ctx, p.id)
    if stage != "approve":
        approve(ctx, p.id, "carol")
    with principal_scope(person("carol")):
        if stage == "validate_apply":
            ctx.gate.start_apply(p.id, person("carol").actor)
        before = deepcopy(p.to_dict())
        mutate(path, change)
        restarted = make()
        with pytest.raises(PermissionError):
            getattr(restarted.gate, stage)(p.id, person("carol").actor)
        assert restarted.gate.get(p.id).to_dict() == before
    # Historical validation has no dependency on the current file, callback, or login.
    restarted.gate.separation_policy = None
    assert separation.validate_history(restarted.gate, restarted.gate.get(p.id)) == p.approval_requirements


@pytest.mark.parametrize("stage", ["propose", "approve", "start_apply", "validate_apply"])
def test_missing_core_hook_never_selects_legacy_mode(mapped, stage):
    ctx = mapped[0]
    if stage == "propose":
        ctx.gate.separation_policy = None
        with pytest.raises(PermissionError, match="wiring"):
            propose(mapped)
        return
    p = propose(mapped)
    if stage != "approve":
        approve(ctx, p.id)
        approve(ctx, p.id, "carol")
    with principal_scope(person("carol")):
        if stage == "validate_apply":
            ctx.gate.start_apply(p.id, person("carol").actor)
        ctx.gate.separation_policy = None
        with pytest.raises(PermissionError, match="wiring"):
            getattr(ctx.gate, stage)(p.id, person("carol").actor)


@pytest.mark.parametrize("stage,final_call", [("propose", 2), ("approve", 2), ("start_apply", 3), ("validate_apply", 3)])
def test_policy_changed_by_final_authorization_callback_is_rechecked(mapped, stage, final_call):
    ctx, _, _, path = mapped
    p = propose(mapped) if stage != "propose" else None
    if stage not in {"approve", "propose"}:
        approve(ctx, p.id)
        approve(ctx, p.id, "carol")
    with principal_scope(person("carol")):
        if stage == "validate_apply":
            ctx.gate.start_apply(p.id, person("carol").actor)
        original, calls = ctx.gate.authorizer, 0

        def revoke(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == final_call:
                mutate(path, "whitespace")
            return result

        ctx.gate.authorizer = revoke
        with pytest.raises(PermissionError, match="policy changed"):
            if stage == "propose":
                propose(mapped)
            else:
                getattr(ctx.gate, stage)(p.id, person("carol").actor)
        assert calls == final_call


@pytest.mark.parametrize("subject", ["alice", "bob"])
def test_missing_mapping_and_group_grants_cannot_supply_person_identity(mapped, subject):
    ctx, _, _, path = mapped
    doc = json.loads(path.read_text())
    row = next(e for e in doc["entries"] if e.get("subject") == subject)
    row.pop("person_id")
    group = deepcopy(row)
    group["group"] = group.pop("subject")
    doc["entries"].append(group)
    write_policy(path, doc)
    if subject == "alice":
        with pytest.raises(PermissionError, match="association"):
            propose(mapped)
        rejected = [r for r in ctx.audit.records() if r["action"] == "proposal.create" and r["outcome"] == "rejected"]
        assert rejected[-1]["principal"]["sub"] == "alice"
    else:
        p = propose(mapped)
        who = person(subject, groups=(subject,))
        with principal_scope(who), pytest.raises(PermissionError, match="association"):
            ctx.gate.approve(p.id, who.actor)


@pytest.mark.parametrize("kind,via", [("workload", "oidc"), ("dev", "dev")])
def test_nonhuman_cannot_propose_or_vote_even_with_mapping(mapped, kind, via):
    ctx, _, finding, _ = mapped
    p = propose(mapped)
    who = person("service", kind=kind, via=via)
    with principal_scope(who):
        with pytest.raises(PermissionError):
            ctx.gate.propose(actor=who.actor, finding_id=finding.id, host="alpha", title="Other",
                             fix_ref=p.fix_ref, fix_preview=p.fix_preview, rollback_plan="restore", risk="fixture")
        with pytest.raises(PermissionError):
            ctx.gate.approve(p.id, who.actor)


@pytest.mark.parametrize("votes", [0, 1, 2])
def test_opt_in_never_upgrades_existing_account_votes(setup, votes):
    ctx, _, _, path = setup
    p = propose(setup)
    for subject in ["bob", "carol"][:votes]:
        approve(ctx, p.id, subject)
    before = deepcopy(p.to_dict())
    doc = json.loads(path.read_text())
    doc.update(version=2, approval_identity={"mode": "person", "version": 1, "namespace": "operators", "revision": 1})
    for i, row in enumerate(doc["entries"]):
        row["person_id"] = f"p-{i}"
    write_policy(path, doc)
    with principal_scope(person("carol")), pytest.raises(PermissionError, match="account-only"):
        if votes < 2:
            ctx.gate.approve(p.id, person("carol").actor)
        else:
            ctx.gate.start_apply(p.id, person("carol").actor)
    assert p.to_dict() == before
    assert separation.validate_history(ctx.gate, p)["version"] == 1


@pytest.mark.parametrize("tamper", ["person", "account", "source", "source_type", "source_version_type",
                                  "proposer", "removed_vote"])
def test_association_and_receipt_tampering_is_refused_by_history_and_gate(mapped, tamper):
    ctx = mapped[0]
    p = propose(mapped)
    approve(ctx, p.id)

    def edit(row):
        if tamper == "removed_vote":
            row["approvals"] = []
        elif tamper == "proposer":
            row["approval_requirements"]["proposer_association"]["person_id"] = "fake"
        else:
            a = row["approvals"][0]["person_association"]
            if tamper == "person":
                a["person_id"] = "fake"
            elif tamper == "account":
                a["subject"] = "bob-admin"
            elif tamper == "source_type":
                a["source"]["revision"] = True  # Python equality alone treats True as 1.
            elif tamper == "source_version_type":
                a["source"]["policy_version"] = 2.0
            else:
                a["source"]["revision"] += 1

    edit_proposal(ctx, p.id, edit)
    with pytest.raises(PermissionError):
        separation.validate_history(ctx.gate, ctx.gate.get(p.id))
    with pytest.raises(PermissionError):
        approve(ctx, p.id, "carol")


def test_old_snapshot_cannot_revive_cancelled_person_quorum(mapped):
    ctx, make, _, _ = mapped
    p = propose(mapped)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    old = deepcopy(p.to_dict())
    with principal_scope(person("carol")):
        ctx.gate.cancel(p.id, person("carol").actor)
    edit_proposal(ctx, p.id, lambda row: (row.clear(), row.update(old)))
    with principal_scope(person("carol")), pytest.raises(PermissionError, match="lifecycle"):
        make().gate.start_apply(p.id, person("carol").actor)


def test_concurrent_alias_votes_count_once(mapped):
    ctx, make, _, _ = mapped
    p = propose(mapped)
    other = make()
    barrier = Barrier(2)

    def vote(context, subject):
        barrier.wait(timeout=10)
        try:
            approve(context, p.id, subject)
            return True
        except PermissionError:
            return False

    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(vote, ctx, "bob"), pool.submit(vote, other, "bob-admin")]
        assert sorted(f.result(timeout=20) for f in futures) == [False, True]
    assert len(ctx.gate.get(p.id).approvals) == 1 and ctx.audit.verify().ok


def test_api_consumes_v2_without_accepting_client_associations(mapped, api):
    p = propose(mapped)
    client, headers = api
    url = f"/api/v1/proposals/{p.id}/approve"
    response = client.post(url, headers=headers("bob"), json={"person_association": {"person_id": "fake"}})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["approval_requirements"]["version"] == 2
    assert body["approval_requirements"]["identity_basis"]["mode"] == "person"
    assert body["approvals"][0]["person_association"]["person_id"] == "p-1"
    assert body["approvals"] == mapped[0].gate.get(p.id).approvals
    assert client.post(url, headers=headers("bob-admin"), json={}).status_code == 403
    assert client.post(url, headers=headers("carol"), json={}).status_code == 200
    saved = client.get(f"/api/v1/proposals/{p.id}", headers=headers("carol")).json()
    assert saved["state"] == "approved"
    assert [v["person_association"]["person_id"] for v in saved["approvals"]] == ["p-1", "p-2"]


def test_source_snapshot_is_immutable_and_mappings_do_not_union_permissions(mapped):
    ctx, _, _, path = mapped
    doc = json.loads(path.read_text())
    normal, privileged = doc["entries"][0], doc["entries"][-2]
    normal["grants"] = [{"target_ids": ["alpha"], "actions": ["read", "scan"],
                         "credential": {"username": "scan_only", "credential_ref": "SCAN_ONLY", "sudo": False, "options": {}}}]
    privileged["grants"] = [{"target_ids": ["beta"], "actions": ["read", "apply"],
                             "credential": {"username": "apply_only", "credential_ref": "APPLY_ONLY", "sudo": True, "options": {}}}]
    write_policy(path, doc)
    snapshot = ctx.access.approval_identity_source()
    with pytest.raises(FrozenInstanceError):
        snapshot.revision = 2
    snapshot.basis["revision"] = 2
    assert snapshot.basis["revision"] == 1
    assert snapshot.association(ISSUER, "alice")["person_id"] == snapshot.association(ISSUER, "alice-admin")["person_id"]
    a = replace(ctx.inventory.get("alpha"), transport="ssh", simulated=False)
    b = replace(ctx.inventory.get("beta"), transport="ssh", simulated=False)
    scan_binding = ctx.access.credential(person("alice"), "scan", a)
    apply_binding = ctx.access.credential(person("alice-admin"), "apply", b)
    assert (scan_binding.username, scan_binding.provenance.subject) == ("scan_only", "alice")
    assert (apply_binding.username, apply_binding.provenance.subject) == ("apply_only", "alice-admin")
    assert scan_binding.provenance.policy_sha256 == apply_binding.provenance.policy_sha256 == snapshot.policy_sha256
    for subject, action, target in [("alice", "apply", b), ("alice-admin", "scan", a), ("alice", "apply", a)]:
        with pytest.raises(AccessDenied):
            ctx.access.credential(person(subject), action, target)
    assert [t.id for t in ctx.access.visible_targets(person("alice"), [a, b])] == ["alpha"]
    assert [t.id for t in ctx.access.visible_targets(person("alice-admin"), [a, b])] == ["beta"]
    with principal_scope(person("alice", roles=("viewer",))), pytest.raises(PermissionError):
        ctx.authorize("scan", actor=person("alice").actor, target="alpha")


@pytest.mark.parametrize("kind", ["script", "runbook"])
def test_mapping_changed_during_capture_never_reaches_mutation_or_runbook(mapped, monkeypatch, kind):
    from cyberthunder.remediation.models import BeforeState
    ctx, _, _, path = mapped
    ctx.library.get("fixture:separation").kind = kind
    p = propose(mapped)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    calls = []

    def capture(*args):
        mutate(path, "relinked")
        return BeforeState(target_id=p.host, fix_ref=p.fix_ref, dir=str(args[-1]), files=[])

    def forbidden(*args):
        calls.append(True)
        raise AssertionError("changed person mapping reached mutation/runbook issuance")

    monkeypatch.setattr(ctx.engine, "_adapter", lambda target: SimpleNamespace(capture_before_state=capture, apply=forbidden))
    monkeypatch.setattr(ctx.engine, "_issue_runbook", forbidden)
    monkeypatch.setattr(ctx, "transport_for", lambda target: SimpleNamespace(close=lambda: None))
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.engine.execute(p.id, actor=person("carol").actor)
    assert calls == []
