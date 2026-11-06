"""Risk stays visible in aggregate, rendered, checklist and CSV evidence."""
import csv
import io
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.api import util
from cyberthunder.findings.review import ReviewService
from cyberthunder.report import checklist, onepager
from cyberthunder.report.poam import poam_csv
from tests.findings.test_risk_acceptance import accept, revoke
from .conftest import SCAN


def list_findings(node, **filters):
    return util.list_findings(node, scan_id=None, limit=100, offset=0, **filters)


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_risk_accepted_is_still_open_in_reports_and_checklist(node, fmt):
    finding = node.findings["empty"]
    before = onepager.build_commander(node, SCAN, fmt)
    original = node.store.read_json(node.store.scans_dir / SCAN / "findings.json")
    accepted = accept(ReviewService(node), finding)
    rendered, after = onepager.render_commander(node, SCAN, fmt)
    counts = after["assurance"]["counts"]
    assert counts["raw_open"] == before["assurance"]["counts"]["raw_open"]
    assert counts["scanner_pass"] == before["assurance"]["counts"]["scanner_pass"]
    assert counts["risk_accepted"] == 1 and counts["suppressed"] == 0
    assert after["by_host"] == before["by_host"]
    assert after["verified"] == before["verified"]
    assert finding.title in [r["title"] for r in after["top"]]
    for text in ("REMEDIATION HELD", "Risk remains open", "risk_accepted", accepted["current"]["reason"],
                 accepted["current"]["expires_at"], finding.evidence):
        assert text in rendered
    rows = list(csv.DictReader(io.StringIO(poam_csv(node, SCAN))))
    row = next(r for r in rows if r["Finding ID"] == finding.id)
    assert row["Status"] == "Open (risk accepted; remediation held)"
    assert row["Scanner Status"] == "open" and row["Review Suppressed"] == "no"
    assert row["Remediation Held"] == "yes" and row["Risk Acceptance Status"] == "active"
    assert json.loads(row["Risk Decision Evidence"]) == accepted["current"]
    doc = checklist.build_checklist(node, SCAN, "rhel-01")
    rule = next(r for stig in doc["stigs"] for r in stig["rules"] if r["rule_version"] == finding.rule_version)
    assert rule["status"] == "open" and rule["finding_details"] == finding.evidence
    assert node.store.read_json(node.store.scans_dir / SCAN / "findings.json") == original


def test_current_filters_and_reversal_retain_risk_history(node):
    finding = node.findings["empty"]
    service = ReviewService(node)
    accepted = accept(service, finding)
    result = list_findings(node, review="risk_accepted")
    assert result["total"] == 1 and result["findings"][0]["scanner_status"] == "open"
    assert result["findings"][0]["status"] == "open" and result["findings"][0]["remediated"] is None
    revoke(service, finding)
    assert list_findings(node, review="risk_accepted")["total"] == 0
    result = list_findings(node, review="risk_revoked")
    assert result["total"] == 1 and result["findings"][0]["review"]["disposition"] == "unreviewed"
    assert service.history(finding)["history"][0] == accepted["current"]


@pytest.mark.parametrize("status", ["expired", "reopened"])
def test_expired_and_reopened_filters_and_reports_retain_original_risk_fingerprint(node, monkeypatch, status):
    from cyberthunder.findings import review
    finding = node.findings["empty"]
    service = ReviewService(node)
    if status == "expired":
        # Create a legitimate bounded decision in the past, then restore the actual clock.
        past = datetime.now(timezone.utc) - timedelta(days=3)
        with monkeypatch.context() as patch:
            patch.setattr(review, "_now", lambda value=None: past)
            accepted = accept(service, finding, expires_at=(past + timedelta(days=1)).isoformat())
    else:
        accepted = accept(service, finding)
        changed = replace(finding, evidence="Changed scanner evidence")
        node.store.save_findings(SCAN, [changed if f.id == finding.id else f for f in node.findings.values()])
    result = list_findings(node, review="risk_" + status)
    assert result["total"] == 1 and result["findings"][0]["status"] == "open"
    assert not result["findings"][0]["review"]["remediation_held"]
    rendered, _ = onepager.render_commander(node, SCAN, "md")
    assert accepted["current"]["evidence_fingerprint"] in rendered
    assert accepted["current"]["reason"] in rendered
    assert "Risk acceptance: **" + status + "**" in rendered


def test_report_does_not_recommend_manual_remediation_for_a_held_unproposed_risk(node):
    # All high risks without proposals are held, but remain in the raw and operational counts.
    for key in ("cron", "accts"):
        accept(ReviewService(node), node.findings[key])
    rendered, report = onepager.render_commander(node, SCAN, "md")
    assert report["assurance"]["counts"]["risk_accepted"] == 2
    assert "Remediation remains held" in rendered
    assert "remediate by hand or add a library entry" not in rendered
