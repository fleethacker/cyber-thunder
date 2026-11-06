"""Report assurance keeps raw scanner evidence and scoped review decisions separate."""
import csv
import io
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.confidence import assess_for_context
from cyberthunder.findings.review import ReviewService
from cyberthunder.findings.schema import Finding, Status
from cyberthunder.inventory.targets import Target
from cyberthunder.report import assurance, checklist, history, onepager
from cyberthunder.report.closure import verified_closure
from cyberthunder.report.poam import poam_csv, poam_rows
from cyberthunder.report.service import ReportService

from .conftest import SCAN


def decide(node, finding, disposition="false_positive", **changes):
    service = ReviewService(node)
    summary = service.summary(finding)
    args = {
        "actor": "ITC Rivera", "disposition": disposition, "reason": "Owner checked the local configuration",
        "supporting_evidence": "Local configuration export", "expected_revision": summary["revision"],
        "evidence_fingerprint": summary["evidence_fingerprint"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
        **changes,
    }
    return service.save(finding, **args)


def evidence_rows(node, scan_id=SCAN):
    data = onepager.build_commander(node, scan_id, "md")
    return data, {f["id"]: f for f in data["assurance"]["findings"]}


def persist_new_scan(node, findings):
    node.store.save_scan_run({"id": "new-scan", "targets": ["rhel-01", "sw-01"], "status": "done",
                             "started_at": datetime.now(timezone.utc).isoformat(), "trigger": "manual"})
    node.store.save_findings("new-scan", findings)


def test_review_counts_do_not_rewrite_raw_findings_or_count_suppression_as_remediation(node):
    before = node.store.read_json(node.store.scans_dir / SCAN / "findings.json")
    decide(node, node.findings["empty"], "confirmed")
    decide(node, node.findings["cron"])
    decide(node, node.findings["accts"], "not_applicable")
    decide(node, node.findings["world"], "needs_investigation")
    data, rows = evidence_rows(node)
    assert data["assurance"]["counts"] == {
        "total": 8, "raw_open": 7, "confirmed": 1, "unreviewed": 3, "suppressed": 2,
        "needs_investigation": 1, "risk_accepted": 0, "scanner_pass": 1, "scanner_not_applicable": 0,
        "scanner_not_reviewed": 0, "scanner_error": 0,
    }
    assert data["decisions"]["verified"] == 1
    assert len(data["verified"]) == 1
    assert sum(r["total"] for r in data["by_host"]) == 4
    assert rows[node.findings["cron"].id]["status"] == "open"
    assert rows[node.findings["shadow"].id]["review"]["disposition"] == "unreviewed"
    assert not rows[node.findings["shadow"].id]["review"]["active"]
    assert node.store.read_json(node.store.scans_dir / SCAN / "findings.json") == before


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_commander_retains_suppressed_evidence_confidence_and_review_details(node, fmt):
    f = node.findings["empty"]
    decision = decide(node, f)
    rendered, data = onepager.render_commander(node, SCAN, fmt)
    assessed = next(row for row in data["assurance"]["findings"] if row["id"] == f.id)
    for text in (f.title, f.evidence, "SUPPRESSED BY REVIEW - NOT REMEDIATED", "false_positive",
                 "ITC Rivera", "Owner checked the local configuration", "Local configuration export",
                 decision["current"]["expires_at"], "Unverified (self-asserted)", assessed["confidence"]["reason"],
                 decision["evidence_fingerprint"], "Raw scanner open", "Scanner not reviewed: 0; errors: 0"):
        assert text in rendered
    assert assessed["status"] == "open"
    assert f.title not in [item["title"] for item in data["top"]]
    assert assessed["confidence"]["grade"] in {"medium", "low"}


def test_poam_retains_suppressions_with_raw_status_and_separate_review_columns(node):
    f = node.findings["empty"]
    decision = decide(node, f, reason='Owner checked, "local" export | configuration')
    text = poam_csv(node, SCAN)
    row = next(row for row in csv.DictReader(io.StringIO(text)) if row["Finding ID"] == f.id)
    assert row["Status"] == "Suppressed (review)"
    assert row["Scanner Status"] == "open" and row["Scanner Evidence"] == f.evidence
    assert row["Review Disposition"] == "false_positive" and row["Review Suppressed"] == "yes"
    assert row["Review Active"] == "yes" and row["Reviewed By"] == "ITC Rivera"
    assert row["Review Reason"] == decision["current"]["reason"]
    assert row["Review Expires At"] == decision["current"]["expires_at"]
    assert row["Reviewer Identity"] == "Unverified (self-asserted)"
    assert row["Confidence Grade"] == assess_for_context(node, f)["grade"]
    assert row["Confidence Reason"] == assess_for_context(node, f)["reason"]
    assert row["Milestone"] == "Reassess before review expiry; suppression is not remediation"
    assert "\r\n" not in text


def test_suppression_does_not_complete_existing_proposal_or_rewrite_checklist(node, raw_cklb):
    raw_before = raw_cklb.read_bytes()
    f = node.findings["empty"]
    decide(node, f)
    checklist_doc = checklist.build_checklist(node, SCAN, "rhel-01")
    rule = next(r for stig in checklist_doc["stigs"] for r in stig["rules"] if r["rule_version"] == f.rule_version)
    assert rule["status"] == "open"
    assert rule["finding_details"] == f.evidence
    assert next(p for p in node.gate.list() if p.finding_id == f.id).state.value == "proposed"
    assert raw_cklb.read_bytes() == raw_before


def test_unchecked_results_and_errors_are_retained_and_never_reported_as_passes(node):
    error = replace(node.findings["root"], status=Status.ERROR, evidence="SSH collection failed")
    unchecked = Finding(host="rhel-01", source="openscap", rule_id="unchecked", title="Rule was not checked",
                        severity="high", status="not_reviewed", evidence="Not executed")
    findings = [error if f.id == error.id else f for f in node.findings.values()]
    node.store.save_findings(SCAN, [*findings, unchecked])
    data, rows = evidence_rows(node)
    assert data["assurance"]["counts"]["scanner_pass"] == 1
    assert data["assurance"]["counts"]["scanner_error"] == 1
    assert data["assurance"]["counts"]["scanner_not_reviewed"] == 1
    exported = {r["Finding ID"]: r for r in poam_rows(node, SCAN)}
    for f in (error, unchecked):
        assert rows[f.id]["status"] == f.status.value
        assert rows[f.id]["confidence"]["grade"] == "unknown"
        assert exported[f.id]["Scanner Status"] == f.status.value
        assert exported[f.id]["Status"] == "Needs investigation"
        assert "Closed" not in exported[f.id]["Milestone"]


@pytest.mark.parametrize("changes", [{"evidence": "Different local observation"}, {"benchmark_release": "V99R1"}])
def test_historical_scan_does_not_inherit_review_of_changed_current_evidence(node, changes):
    old = node.findings["empty"]
    current = replace(old, **changes, scan_id="new-scan")
    persist_new_scan(node, [current if f.id == old.id else f for f in node.findings.values()])
    decide(node, current)
    old_data, old_rows = evidence_rows(node)
    new_data, new_rows = evidence_rows(node, "new-scan")
    assert not old_rows[old.id]["review"]["suppressed"]
    assert old_rows[old.id]["review"]["disposition"] == "unreviewed"
    assert old_rows[old.id]["review"]["reopened_reason"]
    assert old_data["assurance"]["counts"]["suppressed"] == 0
    assert new_rows[old.id]["review"]["suppressed"]
    assert new_data["assurance"]["counts"]["suppressed"] == 1
    old_poam = next(row for row in poam_rows(node, SCAN) if row["Finding ID"] == old.id)
    assert old_poam["Review Suppressed"] == "no"
    assert old_poam["Review Reopened Reason"]
    assert old_poam["Scanner Evidence"] == old.evidence


def test_matching_historical_evidence_keeps_review_across_scan_timestamps(node):
    old = node.findings["empty"]
    decide(node, old)
    new = replace(old, scan_id="new-scan", raw_ref="raw/new-result.xml",
                  collected_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat())
    persist_new_scan(node, [new if f.id == old.id else f for f in node.findings.values()])
    for scan_id in (SCAN, "new-scan"):
        _, rows = evidence_rows(node, scan_id)
        assert rows[old.id]["review"]["suppressed"]


def test_expiry_reopens_reports_and_preserves_reason_and_original_evidence(node, monkeypatch):
    f = node.findings["empty"]
    decision = decide(node, f)
    after_expiry = datetime.fromisoformat(decision["current"]["expires_at"]) + timedelta(seconds=1)

    class ReportClock:
        @staticmethod
        def now(tz):
            return after_expiry

    monkeypatch.setattr(assurance, "datetime", ReportClock)
    data, rows = evidence_rows(node)
    assert data["assurance"]["counts"]["suppressed"] == 0
    assert rows[f.id]["status"] == "open"
    assert rows[f.id]["review"]["disposition"] == "unreviewed"
    row = next(row for row in poam_rows(node, SCAN) if row["Finding ID"] == f.id)
    assert row["Status"] == "Open" and row["Review Active"] == "no"
    assert "expired" in row["Review Reopened Reason"].lower()
    assert row["Review Reason"] == decision["current"]["reason"]
    assert row["Last Review Disposition"] == "false_positive"


def test_legacy_documents_use_inventory_simulation_context_without_mutating_findings(node):
    node.inventory.add(Target(id="rhel-01", name="Local range", asset_type="linux", transport="simulated",
                              simulated=True))
    node.inventory.save()
    path = node.store.scans_dir / SCAN / "findings.json"
    legacy = node.store.read_json(path)
    for finding in legacy["findings"]:
        finding.pop("collection_provenance", None)
    node.store.write_json(path, legacy)
    data, rows = evidence_rows(node)
    row = rows[node.findings["empty"].id]
    assert row["confidence"]["grade"] == "low"
    assert "simulat" in row["confidence"]["reason"].lower()
    assert row["review"]["disposition"] == "unreviewed"
    assert data["assurance"]["counts"]["raw_open"] == 7
    assert node.store.read_json(path) == legacy
    poam = next(r for r in poam_rows(node, SCAN) if r["Finding ID"] == row["id"])
    assert poam["Confidence Grade"] == "low"
    assert "simulat" in poam["Confidence Reason"].lower()


def test_report_builds_are_read_only_and_saved_reports_retain_the_review_snapshot(node, monkeypatch):
    f = node.findings["empty"]
    decide(node, f)
    service = ReportService(node)
    original = service.commander(SCAN, "html")
    saved = history.search(node, kind="commander")["reports"][0]
    decide(node, f, "unreviewed", reason="Review reversed for another check", expires_at=None)
    assert history.get(node, saved["id"])["content"] == original
    before = node.store.read_json(node.store.scans_dir / SCAN / "findings.json")
    with monkeypatch.context() as m:
        m.setattr(node.store, "write_json", lambda *a, **kw: pytest.fail("report build wrote state"))
        m.setattr(node.audit, "append", lambda *a, **kw: pytest.fail("report build wrote audit"))
        text, data = onepager.render_commander(node, SCAN, "html")
        poam_csv(node, SCAN)
        assert data["assurance"]["counts"]["suppressed"] == 0
        assert "Review reversed for another check" in text
    assert node.store.read_json(node.store.scans_dir / SCAN / "findings.json") == before


def test_untrusted_review_text_is_literal_in_html_and_markdown(node):
    text = '<script>alert("review")</script> | [link](https://invalid.example)\nsecond line'
    decide(node, node.findings["empty"], reason=text, supporting_evidence=text)
    html, _ = onepager.render_commander(node, SCAN, "html")
    md, _ = onepager.render_commander(node, SCAN, "md")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert "\\|" in md and "\\[link\\]" in md and "<br>second line" in md


@pytest.mark.parametrize("observed,verified,closed", [
    ("2026-11-05T11:00:00Z", "2026-11-05T12:00:00Z", True),
    ("2026-11-05T12:00:00Z", "2026-11-05T12:00:00Z", True),
    ("2026-11-05T13:00:00Z", "2026-11-05T12:00:00Z", False),
    ("2026-11-05T08:00:00-04:00", "2026-11-05T12:00:00Z", True),
    ("2026-11-05T08:00:01-04:00", "2026-11-05T12:00:00Z", False),
    (None, "2026-11-05T12:00:00Z", False),
    ("", "2026-11-05T12:00:00Z", False),
    ("not a timestamp", "2026-11-05T12:00:00Z", False),
    ("2026-11-05T11:00:00", "2026-11-05T12:00:00Z", False),
    ("2026-11-05T11:00:00Z", None, False),
    ("2026-11-05T11:00:00Z", "", False),
    ("2026-11-05T11:00:00Z", "not a timestamp", False),
    ("2026-11-05T11:00:00Z", "2026-11-05T12:00:00", False),
    ("2026-11-05T11:00:00Z", "2026-11-05", False),
    ("2026-11-05T11:00:00Z", "2026-11-05T12:00:00+00:60", False),
    ("2026-11-05T11:00:00Z", "2026-11-05T12:00:00+24:00", False),
    ("2026-11-05T11:00:00Z", "2026-02-30T12:00:00Z", False),
    ("0001-01-01T00:00:00+02:00", "2026-11-05T12:00:00Z", False),
])
def test_verified_closure_requires_valid_comparable_timestamps(observed, verified, closed):
    finding = Finding(host="local", source="openscap", rule_id="r", title="t", severity="high", status="open",
                      collected_at=observed)
    proposal = Proposal(finding_id=finding.id, host=finding.host, title=finding.title, fix_ref="fix",
                        fix_preview="preview", rollback_plan="restore", risk="risk", state=ProposalState.VERIFIED,
                        history=[{"state": "verified", "ts": verified}])
    assert verified_closure(finding, proposal) is closed
    assert finding.status == Status.OPEN


def test_newer_open_observation_reopens_all_reports_but_older_observation_stays_closed(node, raw_cklb):
    old = node.findings["root"]
    proposal = next(p for p in node.gate.list() if p.finding_id == old.id)
    verified = datetime.fromisoformat(onepager.state_time(proposal, ProposalState.VERIFIED))
    old = replace(old, collected_at=(verified - timedelta(seconds=1)).isoformat())
    node.store.save_findings(SCAN, [old if f.id == old.id else f for f in node.findings.values()])
    decide(node, old, "confirmed")
    new = replace(old, collected_at=(verified + timedelta(seconds=1)).isoformat(), scan_id="new-scan")
    persist_new_scan(node, [new if f.id == old.id else f for f in node.findings.values()])
    raw_before = raw_cklb.read_bytes()
    for scan_id, expected_open in ((SCAN, False), ("new-scan", True)):
        data, rows = evidence_rows(node, scan_id)
        assert (old.title in [r["title"] for r in data["top"]]) is expected_open
        assert sum(row["total"] for row in data["by_host"]) == (7 if expected_open else 6)
        assert data["assurance"]["counts"]["raw_open"] == 7
        assert rows[old.id]["status"] == "open"
        assert rows[old.id]["evidence"] == old.evidence
        assert rows[old.id]["review"]["disposition"] == "confirmed"
        poam = next(row for row in poam_rows(node, scan_id) if row["Finding ID"] == old.id)
        assert poam["Status"] == ("Open" if expected_open else "Completed")
        assert bool(poam["Scheduled Completion"]) is expected_open
        assert poam["Scanner Status"] == "open" and poam["Proposal State"] == "verified"
        if expected_open:
            assert "prior verification does not establish closure" in poam["Milestone"].lower()
        doc = checklist.build_checklist(node, scan_id, "rhel-01")
        rule = next(r for stig in doc["stigs"] for r in stig["rules"] if r["rule_version"] == old.rule_version)
        assert rule["status"] == ("open" if expected_open else "not_a_finding")
    assert raw_cklb.read_bytes() == raw_before


def test_missing_or_invalid_closure_timestamps_never_close_report_observations(node, monkeypatch):
    original = node.findings["root"]
    proposal = next(p for p in node.gate.list() if p.finding_id == original.id)
    # Approval/creation timestamps remain valid: neither is a substitute for verification.
    invalid_cases = [
        (replace(original, collected_at=None), proposal),
        (replace(original, collected_at="invalid"), proposal),
        (original, replace(proposal, history=[])),
        (original, replace(proposal, history=None)),
        (original, replace(proposal, history=[{"state": "verified"}])),
        (original, replace(proposal, history=[*proposal.history, {"state": "verified", "ts": "invalid"}])),
    ]
    for finding, candidate in invalid_cases:
        node.store.save_findings(SCAN, [finding])
        monkeypatch.setattr(node.gate, "list", lambda: [candidate])
        data, rows = evidence_rows(node)
        assert [r["title"] for r in data["top"]] == [finding.title]
        assert data["assurance"]["counts"]["raw_open"] == 1
        assert rows[finding.id]["status"] == "open"
        row = poam_rows(node, SCAN)[0]
        assert row["Status"] == "Open" and row["Scheduled Completion"]
        rule = checklist.build_checklist(node, SCAN, "rhel-01")["stigs"][0]["rules"][0]
        assert rule["status"] == "open"
        assert "Fixed by approved change" not in rule["comments"]
