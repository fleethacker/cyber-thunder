"""Explicit-host exports authorize their own contributors, never unrelated hosts."""
import json

import pytest

from cyberthunder.control.approvals import Proposal
from cyberthunder.findings.schema import Finding
from cyberthunder.report import history, onepager
from cyberthunder.report.render import ReportError
from cyberthunder.report.service import ReportService
from tests.report.test_access import policy, stamp


@pytest.fixture
def scoped(node, policy, monkeypatch):
    policy.owners.update(alpha=stamp("alpha"), beta=stamp("beta"))
    policy.allowed.clear()
    policy.allowed.add("alpha")
    findings = [Finding(host=host, source="openscap", rule_id="check-1", title=f"{host} observation",
                        severity="high", status="open", evidence=f"{host}-only evidence")
                for host in ("alpha", "beta")]
    for finding in findings:
        finding.authorization_scope = stamp(finding.host)
    proposals = [Proposal(finding_id=f.id, host=f.host, title=f.title, fix_ref="test:fix", fix_preview="inert",
                          rollback_plan="inert", risk=f"{f.host}-only proposal") for f in findings]
    for proposal in proposals:
        proposal.authorization_scope = stamp(proposal.host)
    # Same finding ID on another host must not qualify as an alpha contributor.
    proposals[1].finding_id = findings[0].id
    unrelated = Proposal(finding_id="unrelated", host="alpha", title="Unrelated", fix_ref="test:fix",
                         fix_preview="inert", rollback_plan="inert", risk="not in this checklist")
    proposals.append(unrelated)  # deliberately missing scope
    run = {"id": "mixed", "targets": ["alpha", "beta"], "status": "done",
           "authorization_scopes": [stamp("alpha"), stamp("beta")], "errors": {"beta": "hidden error"}}
    monkeypatch.setattr(node.store, "load_scan_run", lambda sid: run)
    monkeypatch.setattr(node.store, "load_findings", lambda *a, **kw: list(findings))
    monkeypatch.setattr(node.gate, "list", lambda: list(proposals))
    node.audit.append("remediation.rollback", "system", {"finding_id": findings[1].id, "target_id": "beta",
                      "ok": False, "finished_at": "2026-11-05T23:00:00Z"}, subject="orphan-beta")
    node.settings.auth_mode = "oidc"
    return node, policy, findings, proposals, run


def test_alpha_checklist_exports_with_inaccessible_beta_findings_proposals_and_rollback(scoped):
    node, policy, _, _, _ = scoped
    doc = ReportService(node).checklist_cklb("mixed", "alpha")
    text = json.dumps(doc)
    assert doc["target_data"]["host_name"] == "alpha"
    assert "alpha-only evidence" in text
    assert "beta" not in text and "Unrelated" not in text
    assert ("export", "alpha") in policy.calls
    assert all(target != "beta" for _, target in policy.calls)
    saved = history.get(node, history.search(node)["reports"][0]["id"])
    assert saved["targets"] == ["alpha"]
    assert saved["authorization_scopes"] == [stamp("alpha")]
    assert "beta" not in saved["content"]


@pytest.mark.parametrize("source", ["run", "finding", "proposal"])
def test_stale_historical_alpha_contributor_is_still_denied(scoped, source):
    node, _, findings, proposals, run = scoped
    old = stamp("alpha", generation="previous-machine")
    if source == "run":
        run["authorization_scopes"][0] = old
    elif source == "finding":
        findings[0].authorization_scope = old
    else:
        proposals[0].authorization_scope = old
    with pytest.raises(PermissionError):
        ReportService(node).checklist_cklb("mixed", "alpha")
    assert not node.store.list_json(node.store.root / "reports/history")


def test_scoped_scan_and_empty_checklist_never_expose_other_host_facets(scoped):
    node, _, findings, _, _ = scoped
    _, run, selected = onepager.resolve_scan(node, "mixed", target="alpha")
    assert run == {"id": "mixed", "targets": ["alpha"], "authorization_scopes": [stamp("alpha")]}
    assert [f.host for f in selected] == ["alpha"]
    findings[:] = [f for f in findings if f.host == "beta"]
    with pytest.raises(ReportError) as exc:
        ReportService(node).checklist_cklb("mixed", "alpha")
    assert "beta" not in str(exc.value) and "hidden error" not in str(exc.value)


@pytest.mark.parametrize("kind", ["commander", "poam", "checklist"])
def test_unscoped_reports_still_require_all_contributors(scoped, kind):
    node, _, _, _, _ = scoped
    with pytest.raises(PermissionError):
        ReportService(node).render_kind(kind, "mixed")


def test_selected_orphan_rollback_cannot_escape_ownership_check(scoped):
    node, _, findings, _, _ = scoped
    node.audit.append("remediation.rollback", "system", {"finding_id": findings[0].id, "target_id": "alpha",
                      "ok": False, "finished_at": "2026-11-05T23:00:00Z"}, subject="orphan-alpha")
    with pytest.raises(PermissionError):
        ReportService(node).checklist_cklb("mixed", "alpha")
