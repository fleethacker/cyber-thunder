"""Historical person associations remain attributable after current policy changes."""
from copy import deepcopy
import json
import time

import pytest

from cyberthunder.control import separation
from cyberthunder.control.principal import principal_scope
from cyberthunder.report import approvals, poam
from cyberthunder.report.service import ReportService
from tests.security.test_person_association import mapped, mutate, write_policy
from tests.security.test_separation_of_duties import approve, edit_proposal, offline, person, propose, setup


@pytest.fixture
def exported(mapped):
    ctx, _, _, path = mapped
    d = json.loads(path.read_text())
    d["entries"][0]["node_actions"] = ["export", "audit"]
    d["entries"][0]["grants"][0]["actions"].append("export")
    write_policy(path, d)
    p = propose(mapped)
    approve(ctx, p.id)
    approve(ctx, p.id, "carol")
    return ctx, p, path


@pytest.mark.parametrize("change", ["revoked", "relinked", "revision", "whitespace", "downgrade", "hook"])
def test_report_keeps_history_separate_from_current_association_validity(exported, change):
    ctx, p, path = exported
    before = deepcopy(p.to_dict())
    if change == "hook":
        ctx.gate.separation_policy = None
    else:
        mutate(path, change)
    with principal_scope(person("alice", roles=("auditor",))):
        result = approvals.evidence(ctx, p)
        output = json.loads(ReportService(ctx).commander("sod-scan", "json"))["proposal_approvals"][0]
        row = poam.poam_rows(ctx, "sod-scan")[0]
    for evidence in (result, output):
        assert evidence["identity_basis"] == "mapped_person"
        assert evidence["historical_validation"]["status"] == "checked"
        assert evidence["historical_quorum_evidence_checked"]
        assert evidence["validation"]["status"] == "not_established"
        assert not evidence["quorum_evidence_checked"]
        assert evidence["current_apply_authorization"] == "not_established_by_report"
        assert evidence["approvals"] == before["approvals"]
        assert all(v["identity"]["verified"] for v in evidence["approval_identities"])
        assert "Recorded person association: operators/p-1" in evidence["text"]
    assert "person_association" in row["Approval Evidence"]
    assert p.to_dict() == before
    with principal_scope(person("carol")), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, person("carol").actor)


@pytest.mark.parametrize("fmt", ["html", "md", "json"])
def test_exports_render_recorded_person_basis_and_actual_account(exported, fmt):
    ctx, p, path = exported
    mutate(path, "relinked")
    with principal_scope(person("alice", roles=("auditor",))):
        text = ReportService(ctx).commander("sod-scan", fmt)
    for value in ("Mapped-person quorum", "operators", "p-1", "bob", "Historical audit-bound",
                  p.approvals[0]["person_association"]["source"]["policy_sha256"]):
        assert value in text
    assert "Current permission to apply" in text


def test_disputed_person_receipts_are_not_certified_historically(exported):
    ctx, p, _ = exported
    edit_proposal(ctx, p.id, lambda d: d["approvals"][0]["person_association"].update(person_id="fake"))
    with principal_scope(person("alice", roles=("auditor",))):
        result = approvals.evidence(ctx, ctx.gate.get(p.id))
    assert result["historical_validation"]["status"] == "not_established"
    assert not result["historical_quorum_evidence_checked"]
    assert not result["approval_identities"][0]["identity"]["verified"]
    assert result["approvals"][0]["person_association"]["person_id"] == "fake"


def test_numerically_equal_principal_tampering_is_disputed(exported):
    ctx, p, _ = exported

    def edit(row):
        principal = row["approvals"][0]["principal"]
        principal["auth_time"] = float(principal["auth_time"])

    edit_proposal(ctx, p.id, edit)
    with principal_scope(person("alice", roles=("auditor",))):
        result = approvals.evidence(ctx, ctx.gate.get(p.id))
    assert result["historical_validation"]["status"] == "not_established"
    assert not result["historical_quorum_evidence_checked"]
    assert not result["quorum_evidence_checked"]
    assert not result["approval_identities"][0]["identity"]["verified"]
    assert result["current_apply_authorization"] == "not_established_by_report"


def test_malformed_requirements_are_retained_as_disputed_history(exported):
    ctx, p, _ = exported
    edit_proposal(ctx, p.id, lambda d: d.update(approval_requirements=["invalid"]))
    with principal_scope(person("alice", roles=("auditor",))):
        result = approvals.evidence(ctx, ctx.gate.get(p.id))
    assert result["approval_requirements"] == ["invalid"]
    assert result["historical_validation"]["status"] == "not_established"
    assert result["identity_basis"] == "unavailable"


def test_expired_historical_logins_do_not_become_current_sessions(exported, monkeypatch):
    ctx, p, _ = exported
    later = time.time() + 1000
    monkeypatch.setattr(time, "time", lambda: later)
    with principal_scope(person("alice", roles=("auditor",))):
        result = approvals.evidence(ctx, p)
    assert all(v["principal"]["expires_at"] < later for v in result["approvals"])
    assert result["historical_validation"]["status"] == "checked"
    assert result["current_apply_authorization"] == "not_established_by_report"


@pytest.mark.parametrize("validator", ["validate_history", "validate"])
def test_person_report_retains_final_export_and_audit_revocation_checks(exported, monkeypatch, validator):
    ctx, p, path = exported
    original = getattr(separation, validator)

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        d = json.loads(path.read_text())
        d["entries"][0]["node_actions"] = [a for a in d["entries"][0]["node_actions"] if a != "audit"]
        write_policy(path, d)
        return result

    monkeypatch.setattr(separation, validator, changed)
    with principal_scope(person("alice", roles=("auditor",))), pytest.raises(PermissionError):
        ReportService(ctx).commander("sod-scan", "json")
