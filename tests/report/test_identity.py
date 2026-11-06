"""Readable recorded identity never replaces canonical audit attribution."""
import csv
import io
from dataclasses import replace
import time

import pytest

from cyberthunder.control.approvals import ProposalState
from cyberthunder.control.principal import principal_scope
from cyberthunder.report import checklist, history, onepager, poam
from cyberthunder.report.identity import attribution
from cyberthunder.report.service import ReportService
from tests.findings.test_review_identity import reviewer
from tests.report.conftest import SCAN
from tests.report.test_assurance import decide


def decision(node, principal):
    proposal = next(p for p in node.gate.list() if p.state == ProposalState.VERIFIED)
    proposal.decided_by = principal.actor
    proposal.decided_principal = principal.evidence()
    node.gate._save()
    return proposal


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_review_and_approval_provenance_render_and_snapshot_roundtrip(node, fmt):
    principal = reviewer()
    proposal = decision(node, principal)
    with principal_scope(principal):
        decide(node, node.findings["empty"], actor=principal.actor)
    # The saved decision is historical even after the credential expires.
    proposal.decided_principal["expires_at"] = time.time() - 1
    node.gate._save()
    text = ReportService(node).commander(SCAN, fmt)
    for value in (principal.display_name, principal.actor, "Verified at decision", principal.issuer, principal.subject):
        assert value in text
    _, data = onepager.render_commander(node, SCAN, fmt)
    assert data["verified"][0]["decided_by"] == principal.actor
    assert data["verified"][0]["decision_identity"]["verified"] is True
    row = next(row for row in data["assurance"]["findings"] if row["id"] == node.findings["empty"].id)
    assert row["review"]["identity_verified"] is True
    assert row["reviewer_identity"]["actor"] == principal.actor
    snapshot = history.search(node)["reports"][0]
    saved = history.get(node, snapshot["id"])["content"]
    proposal.decided_principal = None
    node.gate._save()
    assert saved == text == history.get(node, snapshot["id"])["content"]


def test_csv_and_checklist_preserve_canonical_actor_with_readable_provenance(node):
    principal = reviewer()
    proposal = decision(node, principal)
    with principal_scope(principal):
        decide(node, node.findings["empty"], actor=principal.actor)
    rows = list(csv.DictReader(io.StringIO(poam.poam_csv(node, SCAN))))
    review = next(row for row in rows if row["Finding ID"] == node.findings["empty"].id)
    assert review["Reviewed By"] == principal.actor
    assert principal.display_name in review["Reviewer Identity"]
    assert principal.issuer in review["Reviewer Identity"]
    approved = next(row for row in rows if row["Finding ID"] == proposal.finding_id)
    assert principal.actor in approved["Comments"] and principal.display_name in approved["Comments"]
    status, comment = checklist._status_for(node.findings["root"], proposal)
    assert status == "not_a_finding"
    for value in (principal.display_name, principal.actor, principal.subject, "Verified at decision"):
        assert value in comment


def test_legacy_hash_is_not_inferred_to_be_verified(node):
    principal = reviewer()
    proposal = decision(node, principal)
    proposal.decided_principal = None
    node.gate._save()
    text, data = onepager.render_commander(node, SCAN, "html")
    assert principal.actor in text
    assert not data["verified"][0]["decision_identity"]["verified"]
    assert "Unverified (self-asserted)" in text


@pytest.mark.parametrize("mutation", [{"sub": "forged"}, {"iss": "https://other.example"}, {"verified": 1},
                                      {"via": "dev"}, {"kind": "workload"}, {"name": "\nforged"}])
def test_mismatched_approval_evidence_cannot_claim_verification(node, mutation):
    principal = reviewer()
    proposal = decision(node, principal)
    proposal.decided_principal.update(mutation)
    node.gate._save()
    _, data = onepager.render_commander(node, SCAN, "html")
    assert data["verified"][0]["decision_identity"]["verified"] is False


def test_manual_rollback_uses_bound_history_principal(node):
    principal = reviewer()
    proposal = decision(node, principal)
    proposal.state = ProposalState.ROLLED_BACK
    proposal.history.append({"state": "rolled_back", "actor": principal.actor, "principal": principal.evidence(),
                             "ts": "2026-11-05T23:00:00Z", "note": "operator request"})
    row = onepager._reverted(proposal)
    assert principal.display_name in row["why"] and principal.subject in row["why"]
    assert row["decided_by"] == principal.actor
    proposal.history[-1]["actor"] = "typed-name"
    assert "Unverified (self-asserted)" in onepager._reverted(proposal)["why"]


def test_display_fields_are_escaped_in_html_and_markdown(node):
    principal = replace(reviewer(), display_name='<script>x</script>|[click](https://invalid.example)',
                        subject='user|<b>123</b>')
    decision(node, principal)
    with principal_scope(principal):
        decide(node, node.findings["empty"], actor=principal.actor)
    for fmt in ("html", "md"):
        text = ReportService(node).commander(SCAN, fmt)
        assert "<script>" not in text and "<b>123</b>" not in text
        assert "&lt;script&gt;" in text
        if fmt == "md":
            assert r"\|\[click\]" in text


def test_recorded_identity_does_not_revalidate_expired_login():
    principal = replace(reviewer(), expires_at=1)
    assert attribution(principal.actor, principal.evidence())["verified"] is True
