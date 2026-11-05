"""Current observations and review lifecycle across independent cluster and full scans."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings.review import ReviewService
from cyberthunder.findings.lifecycle import ReviewConflict, finding_lifecycle_lock
from cyberthunder.findings.schema import Finding, findings_doc
from cyberthunder.state import is_document
from cyberthunder.store import StateStore


def cluster(rule="CVE-2026-10000", scope="scope-a", host="cluster-a", **kwargs):
    return Finding(host=host, source="trivy", rule_id=rule, title=rule, severity="high", status="open",
                   evidence="package 1.0 is affected", collection_provenance={
                       "producer": "cluster_vulnerabilities", "observation_scope": scope,
                       "database": {"generation": "g1"}}, **kwargs)


def host_finding(rule="stig-rule", host="server-a"):
    return Finding(host=host, source="openscap", rule_id=rule, title=rule, severity="medium", status="open")


def publish(store, sid, minute, findings, trigger="cluster_vulnerabilities", **kwargs):
    if "assessed_scopes" in kwargs:
        kwargs["summary"] = {"cluster_vulnerabilities": {"assessed_scopes": kwargs.pop("assessed_scopes")}}
    store.save_findings(sid, findings)
    store.save_scan_run({"id": sid, "started_at": f"2026-11-05T10:{minute:02d}:00Z", "status": "done",
                         "trigger": trigger, **kwargs})


def test_partial_only_history_keeps_all_targets_and_sources(state_dir):
    store = StateStore(state_dir)
    a, b, hunt = cluster(), cluster(host="cluster-b", scope="scope-b"), host_finding("hunt")
    publish(store, "one", 1, [a])
    publish(store, "two", 2, [b])
    publish(store, "three", 3, [hunt], trigger="verify")
    assert {f.id for f in store.current_findings()} == {a.id, b.id, hunt.id}
    store.close()


def test_full_scan_retains_cluster_and_scoped_success_preserves_unassessed(state_dir):
    store = StateStore(state_dir)
    a, b, other = cluster(), cluster("CVE-2026-10001", "scope-b"), cluster(host="cluster-b", scope="scope-c")
    stig = host_finding()
    publish(store, "cluster", 1, [a, b, other])
    publish(store, "full", 2, [stig], trigger="manual")
    assert {f.id for f in store.current_findings()} == {a.id, b.id, other.id, stig.id}
    publish(store, "recheck", 3, [], assessed_scopes=["scope-a"])
    assert {f.id for f in store.current_findings()} == {b.id, other.id, stig.id}
    publish(store, "another-full", 4, [stig], trigger="manual")
    assert {f.id for f in store.current_findings()} == {b.id, other.id, stig.id}
    store.close()


def test_in_progress_missing_documents_and_failed_runs_do_not_clear_prior(state_dir):
    store = StateStore(state_dir)
    a, stig = cluster(), host_finding()
    publish(store, "full", 1, [stig], trigger="manual")
    publish(store, "cluster", 2, [a])
    store.save_scan_run({"id": "no-findings", "started_at": "2026-11-05T10:03:00Z", "status": "done"})
    publish(store, "running", 4, [], trigger="manual", status="running")
    publish(store, "failed", 5, [], status="failed", assessed_scopes=["scope-a"])
    assert {f.id for f in store.current_findings()} == {a.id, stig.id}
    publish(store, "partial-full", 6, [], trigger="manual", status="partial")
    assert {f.id for f in store.current_findings()} == {a.id, stig.id}
    store.close()


def test_late_older_publication_does_not_resurrect_reconciled_findings(state_dir):
    store = StateStore(state_dir)
    a = cluster()
    publish(store, "old", 1, [a])
    publish(store, "clean", 4, [], assessed_scopes=["scope-a"])
    publish(store, "late", 2, [replace(a, evidence="older package")])
    assert store.current_findings() == []
    store.close()


def test_projected_publication_matches_persisted_current_view(state_dir):
    store = StateStore(state_dir)
    a, b = cluster(), cluster(host="cluster-b", scope="scope-b")
    publish(store, "old", 1, [a, b])
    run = {"id": "new", "started_at": "2026-11-05T10:02:00Z", "status": "partial",
           "trigger": "cluster_vulnerabilities",
           "summary": {"cluster_vulnerabilities": {"assessed_scopes": ["scope-a"]}}}
    store.save_findings("new", [])
    projected, can_remove = store.projected_observations("new", run, "run")
    assert can_remove and set(projected) == {b.id}
    store.save_scan_run(run)
    assert set(projected) == {f.id for f in store.current_findings()}
    replacement = replace(b, evidence="new evidence")
    projected, _ = store.projected_observations("new", findings_doc([replacement]), "findings")
    store.save_findings("new", [replacement])
    assert {fid: f.to_dict() for fid, f in projected.items()} == {
        f.id: f.to_dict() for f in store.current_findings()}
    store.close()


def test_review_survives_unrelated_full_scan_but_not_reconciliation_and_return(state_dir):
    store = StateStore(state_dir)
    audit = AuditLog(store.audit_log)
    ctx = SimpleNamespace(store=store, audit=audit, killswitch=KillSwitch(state_dir, audit))
    reviews, a = ReviewService(ctx), cluster()
    publish(store, "cluster", 1, [a])
    summary = reviews.summary(a)
    reviews.save(a, actor="ITC Rivera", disposition="false_positive", reason="Reviewed package applicability",
                 supporting_evidence="Fixture vendor evidence", expected_revision=summary["revision"],
                 evidence_fingerprint=summary["evidence_fingerprint"],
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    publish(store, "full", 2, [host_finding()], trigger="manual")
    assert reviews.summary(a)["suppressed"]
    publish(store, "recheck", 3, [], assessed_scopes=["scope-a"])
    publish(store, "return", 4, [a])
    assert not reviews.summary(a)["suppressed"]
    assert "durably reopened" in reviews.summary(a)["reopened_reason"]
    assert audit.verify().ok
    store.close()


def test_vulnerability_documents_use_backend_while_database_payloads_stay_files(state_dir):
    store = StateStore(state_dir)
    documents = ["vulnerabilities/state.json", "vulnerabilities/settings.json", "vulnerabilities/jobs/job-1.json"]
    files = ["vulnerabilities/generations/g1/db/metadata.json", "vulnerabilities/generations/g1/manifest.json"]
    for path in documents + files:
        store.write_json(state_dir / path, {"test": path})
        assert is_document(path) == (path in documents)
        assert store.read_json(state_dir / path) == {"test": path}
        assert (state_dir / path).exists() == (path in files or store.backend_name == "json")
    assert [p.name for p in store.list_json(state_dir / "vulnerabilities/jobs")] == ["job-1.json"]
    store.close()


def test_scoped_removal_uses_existing_lifecycle_lock(state_dir):
    store = StateStore(state_dir)
    a = cluster()
    publish(store, "old", 1, [a])
    with finding_lifecycle_lock(store.root, a.id):
        with pytest.raises(ReviewConflict, match="lifecycle is busy"):
            publish(store, "clean", 2, [], assessed_scopes=["scope-a"])
        assert store.load_scan_run("clean") is None
        assert {f.id for f in store.current_findings()} == {a.id}
    publish(store, "clean", 2, [], assessed_scopes=["scope-a"])
    assert store.current_findings() == []
    store.close()


def test_unrelated_full_scan_does_not_need_cluster_lifecycle_lock(state_dir):
    store = StateStore(state_dir)
    a, stig = cluster(), host_finding()
    publish(store, "old", 1, [a])
    with finding_lifecycle_lock(store.root, a.id):
        publish(store, "full", 2, [stig], trigger="manual")
    assert {f.id for f in store.current_findings()} == {a.id, stig.id}
    store.close()


@pytest.mark.parametrize("status", ["done", "partial", "failed", "running"])
def test_incomplete_full_scan_retains_unobserved_findings_and_remains_latest(state_dir, status):
    store = StateStore(state_dir)
    before, unassessed = host_finding(), host_finding("other-rule", host="server-b")
    cve = cluster()
    publish(store, "full", 1, [before, unassessed], trigger="manual")
    publish(store, "cluster", 2, [cve])
    observed = replace(before, status="not_a_finding", evidence="Observed corrected setting")
    publish(store, "limited", 3, [observed], trigger="manual", status=status, coverage_incomplete=True)
    current = {f.id: f for f in store.current_findings()}
    assert set(current) == {before.id, unassessed.id, cve.id}
    assert current[before.id].status.value == "not_a_finding"
    assert current[unassessed.id].to_dict() == unassessed.to_dict()
    assert store.latest_scan_id() == "limited"
    assert [f.id for f in store.load_findings("limited")] == [before.id]
    store.close()


def test_only_incomplete_scans_accumulate_without_disabling_cluster_reconciliation(state_dir):
    store = StateStore(state_dir)
    a, b, cve = host_finding(), host_finding("second-rule", host="server-b"), cluster()
    publish(store, "native-a", 1, [a], trigger="manual", coverage_incomplete=True)
    publish(store, "native-b", 2, [b], trigger="manual", coverage_incomplete=True)
    publish(store, "cluster", 3, [cve])
    publish(store, "empty-incomplete", 4, [], trigger="manual", coverage_incomplete=True)
    assert {f.id for f in store.current_findings()} == {a.id, b.id, cve.id}
    publish(store, "cluster-clean", 5, [], assessed_scopes=["scope-a"])
    assert {f.id for f in store.current_findings()} == {a.id, b.id}
    assert store.latest_scan_id() == "empty-incomplete"
    store.close()


def test_incomplete_scan_preserves_review_and_projection_matches_publication(state_dir):
    store = StateStore(state_dir)
    audit = AuditLog(store.audit_log)
    ctx = SimpleNamespace(store=store, audit=audit, killswitch=KillSwitch(state_dir, audit))
    reviews, finding = ReviewService(ctx), host_finding()
    publish(store, "full", 1, [finding], trigger="manual")
    summary = reviews.summary(finding)
    reviews.save(finding, actor="ITC Rivera", disposition="false_positive", reason="Reviewed applicability",
                 supporting_evidence="Fixture evidence", expected_revision=summary["revision"],
                 evidence_fingerprint=summary["evidence_fingerprint"],
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    run = {"id": "limited", "started_at": "2026-11-05T10:02:00Z", "status": "done",
           "trigger": "manual", "coverage_incomplete": True}
    store.save_findings("limited", [])
    projected, _ = store.projected_observations("limited", run, "run")
    assert set(projected) == {finding.id}
    store.save_scan_run(run)
    assert {f.id for f in store.current_findings()} == set(projected)
    assert reviews.summary(finding)["suppressed"]
    assert audit.verify().ok
    store.close()
