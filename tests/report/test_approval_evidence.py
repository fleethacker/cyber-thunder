"""Export complete gate receipts without turning historical evidence into present authority."""
from copy import deepcopy
import csv
from dataclasses import replace
import io
import json
import time

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.report import approvals, checklist, history, onepager, poam
from cyberthunder.report.service import ReportService
from tests.report.conftest import SCAN
from tests.security.test_separation_of_duties import (ISSUER, api, approve, edit_proposal, offline, person, propose, setup)


@pytest.fixture
def account(setup):
    ctx, _, _, path = setup
    policy = json.loads(path.read_text())
    policy["entries"][0]["node_actions"] = ["export", "audit"]
    policy["entries"][0]["grants"][0]["actions"].append("export")
    policy["entries"][2]["grants"][0]["actions"] += ["verify", "rollback"]
    path.write_text(json.dumps(policy))
    return ctx, person("alice", roles=("analyst", "auditor"))


def complete(setup):
    ctx = setup[0]
    p = propose(setup)
    approve(ctx, p.id, "bob", note="First independent review; retained evidence")
    return approve(ctx, p.id, "carol", note="Second independent review; same display name")


def test_commander_api_json_preserves_receipts_and_exact_saved_document(account, setup, api):
    ctx, _ = account
    proposal = complete(setup)
    client, headers = api
    response = client.get("/api/v1/reports/commander?format=json&scan_id=sod-scan",
                          headers=headers("alice", roles=("analyst", "auditor")))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/json"
    document = response.json()
    assert isinstance(document, dict)
    assert document["proposal_approvals"][0]["approvals"] == proposal.to_dict()["approvals"]
    with principal_scope(account[1]):
        saved = history.search(ctx)["reports"][0]
        assert history.get(ctx, saved["id"])["content"] == response.text


@pytest.mark.parametrize("denial", ["role", "target", "generation"])
def test_commander_api_json_keeps_export_and_original_owner_boundary(account, setup, api, denial):
    ctx, _ = account
    proposal = complete(setup)
    client, headers = api
    roles = ("analyst",) if denial == "role" else ("analyst", "auditor")
    if denial == "target":
        path = setup[3]
        policy = json.loads(path.read_text())
        policy["entries"][0]["grants"][0]["actions"].remove("export")
        path.write_text(json.dumps(policy))
    elif denial == "generation":
        ctx.inventory.get("alpha").authorization_id = "replacement-generation"
        ctx.inventory.save()
    response = client.get("/api/v1/reports/commander?format=json&scan_id=sod-scan",
                          headers=headers("alice", roles=roles))
    assert response.status_code == 403, response.text
    assert proposal.approvals[0]["note"] not in response.text


@pytest.mark.parametrize("fmt", ["json", "html", "md"])
def test_commander_keeps_every_receipt_proposer_and_snapshot(account, setup, fmt):
    ctx, exporter = account
    p = complete(setup)
    original = deepcopy(p.to_dict())
    before = ctx.gate.store.read_bytes()
    with principal_scope(exporter):
        text = ReportService(ctx).commander("sod-scan", fmt)
        data = json.loads(text) if fmt == "json" else onepager.build_commander(ctx, "sod-scan", fmt)
        evidence = data["proposal_approvals"][0]
        assert evidence["approvals"] == original["approvals"]
        assert evidence["proposed_principal"] == original["proposed_principal"]
        assert evidence["approval_requirements"] == original["approval_requirements"]
        assert evidence["required_approvals"] == evidence["recorded_count"] == 2
        assert evidence["quorum_evidence_checked"] is True
        assert evidence["validation"]["status"] == "checked"
        assert evidence["current_apply_authorization"] == "not_established_by_report"
        for vote in original["approvals"]:
            for value in (vote["id"], vote["actor"], vote["note"], vote["approved_at"], vote["assessment_sha256"]):
                assert value in text
        assert original["proposed_by"] in text
        assert [row["identity"]["subject"] for row in evidence["approval_identities"]] == ["bob", "carol"]
        assert {row["identity"]["display_name"] for row in evidence["approval_identities"]} == {"Operator"}
        saved = history.search(ctx)["reports"][0]
        assert history.get(ctx, saved["id"])["content"] == text
    assert ctx.gate.store.read_bytes() == before


@pytest.mark.parametrize("phase,count,state", [("empty", 0, "proposed"), ("partial", 1, "proposed"),
    ("denied", 1, "denied"), ("cancelled", 1, "cancelled"), ("full_cancelled", 2, "cancelled"),
    ("verified", 2, "verified"), ("rolled_back", 2, "rolled_back")])
def test_partial_and_terminal_states_are_historical_not_apply_authority(account, setup, phase, count, state):
    ctx, exporter = account
    p = propose(setup)
    if count:
        approve(ctx, p.id, "bob")
    if count == 2:
        approve(ctx, p.id, "carol")
    operator = person("carol")
    with principal_scope(operator):
        if phase == "denied":
            ctx.gate.deny(p.id, operator.actor, "Change declined")
        elif phase in {"cancelled", "full_cancelled"}:
            ctx.gate.cancel(p.id, operator.actor, "Change withdrawn")
        elif phase in {"verified", "rolled_back"}:
            ctx.gate.start_apply(p.id, operator.actor)
            ctx.gate.applied(p.id, operator.actor)
            ctx.gate.verified(p.id, operator.actor)
            if phase == "rolled_back":
                ctx.gate.rolled_back(p.id, operator.actor)
    with principal_scope(exporter):
        data = json.loads(ReportService(ctx).commander("sod-scan", "json"))
        result = data["proposal_approvals"][0]
        row = poam.poam_rows(ctx, "sod-scan")[0]
        assert result["state"] == state and result["recorded_count"] == count
        assert f"recorded state: {state}" in result["summary"]
        assert result["current_apply_authorization"] == "not_established_by_report"
        assert row["Proposal State"] == state
        if count < 2:
            assert result["quorum_status"] == "partial"
            assert not result["quorum_evidence_checked"]
        if phase in {"denied", "cancelled", "full_cancelled"}:
            assert data["decisions"]["approved"] == 0
            assert "Apply" not in row["Milestone"]


@pytest.mark.parametrize("change", ["finding", "fix", "duplicate", "receipt", "audit", "source_unavailable"])
def test_changed_or_unverifiable_evidence_is_not_claimed_valid(account, setup, change, monkeypatch):
    ctx, exporter = account
    p = complete(setup)
    if change == "finding":
        finding = ctx.store.get_finding(p.finding_id)
        finding.evidence = "New observation after approval"
        ctx.store.save_findings("sod-scan", [finding])
    elif change == "fix":
        ctx.library.get(p.fix_ref).payload = "changed vetted payload"
    elif change == "duplicate":
        edit_proposal(ctx, p.id, lambda row: row["approvals"].__setitem__(1, deepcopy(row["approvals"][0])))
    elif change == "receipt":
        edit_proposal(ctx, p.id, lambda row: row["approvals"][0].update(note="altered receipt"))
    elif change == "audit":
        ctx.audit.path.write_text(ctx.audit.path.read_text().replace("First independent", "Altered independent"))
    else:
        def unavailable(_proposal):
            raise OSError("private path and credentials must not enter an export")
        monkeypatch.setattr(ctx.gate, "separation_source", unavailable)
    with principal_scope(exporter):
        result = approvals.evidence(ctx, ctx.gate.get(p.id))
    assert result["validation"]["status"] == "not_established"
    assert not result["quorum_evidence_checked"]
    assert result["current_apply_authorization"] == "not_established_by_report"
    assert "private path and credentials" not in json.dumps(result)
    assert len(result["approvals"]) == 2  # Retain the disputed evidence rather than silently omitting it.


def test_same_subject_from_distinct_issuers_remains_distinct(account, setup):
    ctx, exporter = account
    p = propose(setup)
    approve(ctx, p.id, "bob")
    other = person("bob", issuer=ISSUER + "/second")
    with principal_scope(other):
        ctx.gate.approve(p.id, other.actor)
    with principal_scope(exporter):
        result = approvals.evidence(ctx, ctx.gate.get(p.id))
    identities = [row["identity"] for row in result["approval_identities"]]
    assert [row["subject"] for row in identities] == ["bob", "bob"]
    assert len({row["issuer"] for row in identities}) == len({row["actor"] for row in identities}) == 2
    assert result["quorum_evidence_checked"]


@pytest.mark.parametrize("existing", [False, True])
def test_poam_and_cklb_preserve_all_receipts_and_original_checklist_text(account, setup, existing):
    ctx, exporter = account
    p = complete(setup)
    original_file = None
    with principal_scope(exporter):
        if existing:
            base = checklist.build_checklist(ctx, "sod-scan", "alpha")
            base["stigs"][0]["rules"][0]["comments"] = "Original reviewer comment"
            original_file = ctx.store.scans_dir / "sod-scan" / "raw" / "alpha" / "original.cklb"
            original_file.parent.mkdir(parents=True, exist_ok=True)
            original_file.write_text(json.dumps(base))
            before = original_file.read_bytes()
        doc = ReportService(ctx).checklist_cklb("sod-scan", "alpha")
        row = list(csv.DictReader(io.StringIO(ReportService(ctx).poam_csv("sod-scan"))))[0]
        event = [r for r in ctx.audit.records() if r["action"] == "report.render" and
                 r["details"].get("kind") == "poam"][-1]
        assert event["details"]["rows"] == 1  # Quoted multiline approval notes are still one CSV row.
        records = json.loads(row["Approval Evidence"])
        assert records[0]["approvals"] == p.approvals
        assert records[0]["proposed_principal"] == p.proposed_principal
        rule = doc["stigs"][0]["rules"][0]
        assert rule["status"] == "open"  # Approval alone cannot close a scanner observation.
        for vote in p.approvals:
            for value in (vote["actor"], vote["id"], vote["approved_at"], vote["assessment_sha256"]):
                assert value in rule["comments"] and value in row["Approval Evidence"]
        assert p.proposed_by in rule["comments"]
        assert "Current permission to apply is not established" in rule["comments"]
    if original_file:
        assert "Original reviewer comment" in rule["comments"]
        assert original_file.read_bytes() == before


def test_prior_cancelled_proposal_receipt_survives_a_new_proposal(account, setup):
    ctx, exporter = account
    first = propose(setup)
    approve(ctx, first.id, "bob", note="Earlier independent review")
    who = person("carol")
    with principal_scope(who):
        ctx.gate.cancel(first.id, who.actor)
    second = propose(setup)
    approve(ctx, second.id, "carol", note="New independent review")
    assert first.id != second.id
    with principal_scope(exporter):
        row = poam.poam_rows(ctx, "sod-scan")[0]
        doc = checklist.build_checklist(ctx, "sod-scan", "alpha")
    records = json.loads(row["Approval Evidence"])
    assert {record["proposal_id"] for record in records} == {first.id, second.id}
    comment = doc["stigs"][0]["rules"][0]["comments"]
    for text in ("Earlier independent review", "New independent review", first.id, second.id):
        assert text in row["Comments"] and text in comment


def test_unverified_separation_never_becomes_verified_identity(setup):
    _, make, finding, _ = setup
    ctx = make(mode="dev")
    ctx.gate.unverified_separation = True
    p = ctx.engine.propose(finding, actor="Alice")
    ctx.gate.approve(p.id, "Bob")
    ctx.gate.approve(p.id, "Carol")
    result = approvals.evidence(ctx, p)
    assert result["validation"]["status"] == "checked"
    assert result["approval_requirements"]["mode"] == "unverified_dev"
    assert not result["proposer_identity"]["verified"]
    assert all(not row["identity"]["verified"] for row in result["approval_identities"])
    assert "Verified at decision" not in result["text"]


def test_legacy_json_retains_last_decision_without_inventing_a_quorum(node):
    result = json.loads(ReportService(node).commander(SCAN, "json"))
    evidence = next(item for item in result["proposal_approvals"] if item["state"] == "verified")
    assert evidence["decided_by"] == "sailor1"
    assert evidence["approvals"] == [] and evidence["required_approvals"] is None
    assert evidence["quorum_status"] == "not_recorded"
    assert evidence["validation"]["status"] == "legacy_unavailable"
    assert not evidence["quorum_evidence_checked"]


def test_commander_cli_exports_json_without_changing_legacy_fields(node, tmp_path):
    from cyberthunder.cli import main
    output = tmp_path / "commander.json"
    assert main(["--state-dir", str(node.store.root), "report", "commander", "--format", "json",
                 "--scan-id", SCAN, "--out", str(output)]) == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["verified"][0]["decided_by"] == "sailor1"
    assert data["proposal_approvals"] and data["scan_id"] == SCAN


def test_checked_historical_quorum_is_not_current_apply_authorization(account, setup):
    ctx, exporter = account
    p = complete(setup)
    path = setup[3]
    policy = json.loads(path.read_text())
    policy["entries"][2]["grants"][0]["actions"].remove("apply")
    path.write_text(json.dumps(policy))
    with principal_scope(exporter):
        result = approvals.evidence(ctx, p)
    assert result["quorum_evidence_checked"]
    assert result["current_apply_authorization"] == "not_established_by_report"
    operator = person("carol")
    with principal_scope(operator), pytest.raises(PermissionError):
        ctx.gate.start_apply(p.id, operator.actor)


def test_expired_reviewer_login_does_not_erase_recorded_attribution(account, setup, monkeypatch):
    ctx, exporter = account
    p = complete(setup)
    future = time.time() + 1000
    monkeypatch.setattr("cyberthunder.control.principal.time.time", lambda: future)
    exporter = replace(exporter, expires_at=future + 600)
    with principal_scope(exporter):
        result = approvals.evidence(ctx, p)
    assert result["quorum_evidence_checked"]
    assert all(row["identity"]["verified"] for row in result["approval_identities"])
    assert all(vote["principal"]["expires_at"] < future for vote in result["approvals"])
    assert result["current_apply_authorization"] == "not_established_by_report"


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_approval_notes_and_display_names_are_literal_in_page_exports(account, setup, fmt):
    ctx, exporter = account
    p = propose(setup)
    who = replace(person("bob"), display_name='<script>name</script>|[click](https://invalid.example)')
    note = '</pre><script>note</script>\n| [link](https://invalid.example)\n```'
    with principal_scope(who):
        ctx.gate.approve(p.id, who.actor, note=note)
    with principal_scope(exporter):
        text = ReportService(ctx).commander("sod-scan", fmt)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert '</pre><script>' not in text
    if fmt == "md":
        assert r"\|\[click\]" in text and r"\| \[link\]" in text
        assert "\n```" not in text


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-cmd", "@SUM(A1)", " \t=cmd", "\n=cmd", "\ufeff=cmd"])
def test_exported_csv_neutralizes_formula_cells(account, setup, value):
    ctx, exporter = account
    finding = setup[2]
    finding.title = value
    ctx.store.save_findings("sod-scan", [finding])
    with principal_scope(exporter):
        row = list(csv.DictReader(io.StringIO(poam.poam_csv(ctx, "sod-scan"))))[0]
    assert row["Title"] == "'" + value


@pytest.mark.parametrize("report", ["commander", "poam", "checklist", "evidence"])
def test_approval_evidence_never_reassigns_original_target_ownership(account, setup, report):
    ctx, exporter = account
    p = complete(setup)
    ctx.inventory.get("alpha").environment = "replacement"
    ctx.inventory.save()
    with principal_scope(exporter), pytest.raises(PermissionError):
        if report == "commander":
            ReportService(ctx).commander("sod-scan", "json")
        elif report == "poam":
            ReportService(ctx).poam_csv("sod-scan")
        elif report == "checklist":
            ReportService(ctx).checklist_cklb("sod-scan", "alpha")
        else:
            approvals.evidence(ctx, p)
