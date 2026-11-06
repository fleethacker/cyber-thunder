"""Adversarial receipt, publication and representation checks on both state stores."""
from contextlib import contextmanager
from copy import deepcopy
import csv
from dataclasses import replace
import io
import json

import pytest

from cyberthunder.control import separation
from cyberthunder.control.principal import principal_scope
from cyberthunder.report import approvals
from cyberthunder.report.service import ReportService
from tests.report.test_approval_evidence import account, complete
from tests.security.test_separation_of_duties import approve, edit_proposal, offline, person, propose, setup


def revoke(setup, change):
    ctx, _, _, path = setup
    if change == "ownership":
        ctx.inventory.get("alpha").environment = "moved"
        ctx.inventory.save()
        return
    policy = json.loads(path.read_text())
    entry = policy["entries"][0]
    if change == "target_export":
        entry["grants"][0]["actions"].remove("export")
    else:
        entry["node_actions"].remove(change)
    path.write_text(json.dumps(policy))


@pytest.mark.parametrize("change", ["ownership", "audit"])
def test_receipt_validation_cannot_swallow_lost_ownership_or_audit_access(account, setup, monkeypatch, change):
    ctx, exporter = account
    proposal = complete(setup)
    validate = separation.validate

    def changed(*args, **kwargs):
        validate(*args, **kwargs)
        revoke(setup, change)
        raise PermissionError("source changed; private validator diagnostics")

    monkeypatch.setattr(separation, "validate", changed)
    with principal_scope(exporter), pytest.raises(PermissionError):
        approvals.evidence(ctx, proposal)


@pytest.mark.parametrize("change", ["ownership", "audit", "export", "target_export"])
def test_history_rechecks_authority_after_waiting_for_publication_lock(account, setup, monkeypatch, change):
    ctx, exporter = account
    complete(setup)
    lock = ctx.store.files.lock

    @contextmanager
    def changed(name):
        with lock(name):
            if name == "report-history":
                revoke(setup, change)
            yield

    monkeypatch.setattr(ctx.store.files, "lock", changed)
    with principal_scope(exporter), pytest.raises(PermissionError):
        ReportService(ctx).commander("sod-scan", "json")
    assert not list((ctx.store.root / "reports" / "history").glob("*.json"))


def test_return_boundary_rechecks_audit_after_report_audit_append(account, setup, monkeypatch):
    ctx, exporter = account
    complete(setup)
    service = ReportService(ctx)
    audited = service._audited

    def changed(*args, **kwargs):
        audited(*args, **kwargs)
        revoke(setup, "audit")

    monkeypatch.setattr(service, "_audited", changed)
    with principal_scope(exporter), pytest.raises(PermissionError):
        service.commander("sod-scan", "json")


@pytest.mark.parametrize("change", ["duplicate", "self", "note", "source"])
def test_disputed_receipts_never_become_validated_identity_from_metadata(account, setup, change):
    ctx, exporter = account
    original = complete(setup)
    if change == "duplicate":
        edit_proposal(ctx, original.id, lambda p: p["approvals"].__setitem__(1, deepcopy(p["approvals"][0])))
    elif change == "self":
        edit_proposal(ctx, original.id, lambda p: p["approvals"][0].update(
            actor=p["proposed_by"], principal=deepcopy(p["proposed_principal"])))
    elif change == "note":
        edit_proposal(ctx, original.id, lambda p: p["approvals"][0].update(note="Altered claim"))
    else:
        ctx.library.get(original.fix_ref).payload = "Changed fix"
    proposal = ctx.gate.get(original.id)
    with principal_scope(exporter):
        result = approvals.evidence(ctx, proposal)
    assert result["approvals"] == proposal.approvals
    assert result["validation"]["status"] == "not_established"
    assert not result["quorum_evidence_checked"]
    assert not result["proposer_identity"]["verified"]
    assert all(not vote["identity"]["verified"] for vote in result["approval_identities"])
    assert "Verified at decision" not in result["text"]
    assert "identity claim" in result["text"]


def test_markdown_escapes_proposal_title_everywhere_it_is_repeated(account, setup):
    ctx, exporter = account
    finding = setup[2]
    finding.title = '<script>title</script> __claim__ ~~approved~~ | [click](https://invalid.example)'
    ctx.store.save_findings("sod-scan", [finding])
    propose(setup)
    with principal_scope(exporter):
        text = ReportService(ctx).commander("sod-scan", "md")
    assert "<script>" not in text
    # The recorded JSON block is HTML escaped; ordinary Markdown cells must also escape emphasis.
    outside_json = text.split("<pre>")[0] + "".join(part.split("</pre>", 1)[-1] for part in text.split("<pre>")[1:])
    assert "__claim__" not in outside_json and "~~approved~~" not in outside_json
    assert "[click](https://invalid.example)" not in outside_json
    assert r"\_\_claim\_\_" in text and r"\~\~approved\~\~" in text


def test_json_cklb_and_csv_retain_literal_receipts_without_inventing_fields(account, setup):
    ctx, exporter = account
    proposer = replace(person("alice"), display_name='=FORMULA("name")')
    note = '=FORMULA("vote")\r\n</pre><script>literal</script>|"status":"approved"'
    with principal_scope(proposer):
        p = ctx.engine.propose(deepcopy(setup[2]), actor=proposer.actor)
    approve(ctx, p.id, "bob", note=note)
    original = ctx.gate.get(p.id).to_dict()
    with principal_scope(exporter):
        service = ReportService(ctx)
        commander = json.loads(service.commander("sod-scan", "json"))
        csv_text = service.poam_csv("sod-scan")
        cklb_text = json.dumps(service.checklist_cklb("sod-scan", "alpha"))
    evidence = commander["proposal_approvals"][0]
    assert evidence["approvals"] == original["approvals"]
    assert evidence["state"] == "proposed" and not evidence["quorum_evidence_checked"]
    row, = csv.DictReader(io.StringIO(csv_text))
    assert row["Proposer Identity"].startswith("'=FORMULA")
    assert json.loads(row["Approval Evidence"])[0]["approvals"] == original["approvals"]
    rule = json.loads(cklb_text)["stigs"][0]["rules"][0]
    assert rule["status"] == "open"
    assert original["approvals"][0]["note"] in rule["comments"]
    assert ctx.gate.get(p.id).to_dict() == original


def test_verified_checklist_cannot_adopt_another_targets_raw_file_by_display_metadata(account, setup):
    ctx, exporter = account
    complete(setup)
    run = ctx.store.load_scan_run("sod-scan")
    run["targets"] = ["alpha", "beta"]
    from cyberthunder.security.resources import target_scope
    run["authorization_scopes"].append(target_scope(ctx.inventory.get("beta")))
    ctx.store.save_scan_run(run)
    raw = ctx.store.scans_dir / "sod-scan" / "raw" / "beta" / "original.cklb"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"target_data": {"host_name": "alpha"}, "stigs": [{"rules": [
        {"rule_id": setup[2].rule_id, "comments": "Other target private approval text", "status": "open"}]}]}))
    before = raw.read_bytes()
    with principal_scope(exporter):
        doc = ReportService(ctx).checklist_cklb("sod-scan", "alpha")
    assert "Other target private approval text" not in json.dumps(doc)
    assert doc["target_data"]["host_name"] == "alpha"
    assert raw.read_bytes() == before


def test_verified_checklist_refuses_raw_directory_aliases_in_original_scan(account, setup):
    from cyberthunder.inventory.targets import Target
    from cyberthunder.security.resources import target_scope
    ctx, exporter = account
    alias = Target("ALPHA", "Other target", "linux", "simulated", simulated=True, environment="other")
    ctx.inventory.add(alias)
    ctx.inventory.save()
    run = ctx.store.load_scan_run("sod-scan")
    run["targets"].append(alias.id)
    run["authorization_scopes"].append(target_scope(alias))
    ctx.store.save_scan_run(run)
    raw = ctx.store.scans_dir / "sod-scan" / "raw" / "alpha" / "original.cklb"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"target_data": {"host_name": "alpha"}, "stigs": [{"rules": [
        {"rule_id": setup[2].rule_id, "comments": "Ambiguous path receipt", "status": "open"}]}]}))
    with principal_scope(exporter), pytest.raises(PermissionError):
        ReportService(ctx).checklist_cklb("sod-scan", "alpha")


def test_additive_session_fingerprint_survives_all_reports_as_recorded_evidence(account, setup, monkeypatch):
    from tests.security import test_separation_of_duties as fixtures
    ctx, exporter = account
    original = fixtures.person
    raw_session = "fixture-private-issuer-session"

    def with_session(*args, **kwargs):
        return original(*args, session_id=raw_session, **kwargs)

    monkeypatch.setattr(fixtures, "person", with_session)
    proposal = complete(setup)
    expected = [proposal.proposed_principal, *(vote["principal"] for vote in proposal.approvals)]
    with principal_scope(exporter):
        service = ReportService(ctx)
        texts = [service.commander("sod-scan", fmt) for fmt in ("json", "html", "md")]
        texts += [service.poam_csv("sod-scan"), json.dumps(service.checklist_cklb("sod-scan", "alpha"))]
    recorded = json.loads(texts[0])["proposal_approvals"][0]
    assert recorded["quorum_evidence_checked"]
    assert recorded["proposer_identity"]["verified"]
    assert all(row["identity"]["verified"] for row in recorded["approval_identities"])
    assert recorded["proposed_principal"] == expected[0]
    assert [vote["principal"] for vote in recorded["approvals"]] == expected[1:]
    for principal in expected:
        assert principal["session_id"] is None
        assert all(principal["session_fingerprint"] in text for text in texts)
    assert all(raw_session not in text for text in texts)
