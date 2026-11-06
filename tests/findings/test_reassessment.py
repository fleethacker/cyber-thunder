"""Retained evidence stays immutable on both document backends; no collection occurs."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.findings.review import ReviewService, evidence_fingerprint
from cyberthunder.findings.schema import Finding, Reference
from cyberthunder.inventory.targets import Target

OLD = "2026-11-05T10:00:00Z"
LATER = "2026-11-05T11:00:00Z"
NEWEST = "2026-11-05T12:00:00Z"


def observation(**overrides):
    return Finding(**dict(dict(host="alpha", source="native", rule_id="ssh-root", rule_version="RHEL-09-255045",
                               title="SSH root login", severity="high", status="open", evidence="PermitRootLogin yes",
                               asset_type="linux", collected_at=OLD, scan_id="base"), **overrides))


def save_run(ctx, sid="later", *, at=LATER, findings=(), publish=True, **changes):
    run = dict(id=sid, targets=["alpha"], started_at=at, finished_at=at, trigger="manual",
               modules=["check", "hunt", "cve"], status="done", coverage_incomplete=True,
               results={"alpha": {"target_id": "alpha", "status": "done"}},
               scheduling={"unavailable_targets": [], "partial_targets": [],
                           "omitted_observations": "retain_without_revalidation"})
    run.update(changes)
    ctx.store.save_scan_run(run)
    if publish:
        ctx.store.save_findings(sid, findings)
    return ctx.store.load_scan_run(sid)


def seed(ctx, **overrides):
    for tid in ("alpha", "beta"):
        ctx.inventory.add(Target(tid, tid, "linux", transport="simulated", simulated=True, environment=tid))
    ctx.inventory.save()
    f = observation(**overrides)
    save_run(ctx, "base", at=OLD, findings=[f], coverage_incomplete=False, scheduling=None)
    return ctx.store.load_findings("base")[0]


@pytest.fixture
def env(state_dir):
    ctx = AppContext(Settings(state_dir=state_dir, llm_backend="template", auto_propose=False, explain_precompute=False))
    f = seed(ctx)
    yield ctx, f
    ctx.close()


def assess(ctx, f, **kwargs):
    return ReassessmentView(ctx, **kwargs).assess(f.to_dict())


@pytest.mark.parametrize(("status", "reason"), [
    ("error", "target_unavailable"), ("timed_out", "target_unavailable"),
    ("skipped", "target_not_started"), ("pending", "target_not_started"),
    ("stopped", "target_not_started"), ("cancelled", "target_not_started"),
    ("partial", "partial_collection"), ("done", "omitted_observation"),
])
def test_terminal_missing_failed_unstarted_partial_and_empty_success(env, status, reason):
    ctx, f = env
    before = f.to_dict()
    save_run(ctx, status="partial", results={"alpha": {"status": status, "errors": ["PRIVATE diagnostic"]}})
    result = assess(ctx, f)
    assert result["status"] == "not_reassessed" and result["reason"] == reason
    assert result["observation"] == {"observed_at": OLD, "source": "native", "scan_id": "base"}
    assert result["latest_attempt"]["started_at"] == LATER
    assert "PRIVATE" not in str(result)
    assert ctx.store.load_findings()[0].to_dict() == before


@pytest.mark.parametrize("publish", [True, False])
def test_missing_results_or_missing_findings_document_retains_observation(env, publish):
    ctx, f = env
    save_run(ctx, publish=publish, status="error", results={})
    assert assess(ctx, f)["reason"] == "target_not_started"
    assert ctx.store.load_findings()[0].id == f.id


@pytest.mark.parametrize(("field", "reason"), [("partial_targets", "partial_collection"), ("unavailable_targets", "target_unavailable")])
def test_scheduler_target_lists_are_supported(env, field, reason):
    ctx, f = env
    save_run(ctx, scheduling={field: ["alpha"], "omitted_observations": "retain_without_revalidation"})
    assert assess(ctx, f)["reason"] == reason


def test_retention_metadata_identifies_withheld_uncertain_replacement_without_changing_evidence(env):
    ctx, f = env
    before = f.to_dict()
    fingerprint = evidence_fingerprint(f)
    peer = observation(rule_id="banner", scan_id="later", collected_at=LATER)
    save_run(ctx, findings=[peer], status="partial", results={"alpha": {"status": "partial"}},
             scheduling={"partial_targets": ["alpha"], "retained_incomplete_observations": {"alpha": [f.id]},
                         "omitted_observations": "retain_without_revalidation"})
    current = ctx.store.get_finding(f.id)
    result = assess(ctx, current)
    assert result["reason"] == "retained_incomplete_observation"
    assert result["status"] == "not_reassessed" and result["latest_attempt"]["scan_id"] == "later"
    assert current.to_dict() == before and evidence_fingerprint(current) == fingerprint
    assert assess(ctx, ctx.store.get_finding(peer.id))["status"] == "no_known_gap"


@pytest.mark.parametrize("metadata", [None, {}, {"beta": ["matching"]}, {"alpha": ["other"]},
                                       {"alpha": "matching"}, ["matching"]])
def test_retention_metadata_requires_exact_target_and_finding_list_and_preserves_old_mode(env, metadata):
    ctx, f = env
    f = replace(f, id="matching")
    save_run(ctx, results={"alpha": {"status": "partial"}},
             scheduling={"partial_targets": ["alpha"], "retained_incomplete_observations": metadata})
    assert assess(ctx, f)["reason"] == "partial_collection"


def test_retention_metadata_does_not_override_withdrawn_collection_or_new_actual_observation(env):
    ctx, f = env
    metadata = {"retained_incomplete_observations": {"alpha": [f.id]}, "unavailable_targets": ["alpha"]}
    save_run(ctx, results={"alpha": {"status": "error"}}, scheduling=metadata)
    assert assess(ctx, f)["reason"] == "target_unavailable"
    save_run(ctx, "newest", at=NEWEST, findings=[replace(f, scan_id="newest", collected_at=NEWEST)],
             scheduling={"retained_incomplete_observations": {"alpha": [f.id]}})
    assert assess(ctx, f)["reason"] == "newer_observation"


def test_partial_scan_only_marks_omitted_observation_and_new_evidence_clears_badge(env):
    ctx, f = env
    other = observation(rule_id="banner", scan_id="later", collected_at=LATER)
    save_run(ctx, findings=[other], results={"alpha": {"status": "partial"}})
    current = {r.rule_id: r for r in ctx.store.load_findings()}
    assert assess(ctx, current["ssh-root"])["status"] == "not_reassessed"
    assert assess(ctx, current["banner"])["status"] == "no_known_gap"
    fresh = replace(f, scan_id="newest", collected_at=NEWEST)
    save_run(ctx, "newest", at=NEWEST, findings=[fresh])
    assert assess(ctx, ctx.store.get_finding(f.id))["status"] == "no_known_gap"
    assert assess(ctx, f)["reason"] == "newer_observation"


def test_copying_old_row_into_later_run_does_not_revalidate(env):
    ctx, f = env
    save_run(ctx, findings=[f])
    assert assess(ctx, ctx.store.get_finding(f.id))["status"] == "not_reassessed"


def test_import_time_does_not_substitute_for_actual_observation_time(env):
    ctx, f = env
    carried = replace(f, scan_id="later", collected_at=LATER, collection_provenance={"observed_at": OLD})
    save_run(ctx, findings=[carried])
    assert assess(ctx, f)["status"] == "not_reassessed"


@pytest.mark.parametrize("changes", [
    {"targets": ["beta"]}, {"modules": ["hunt"]}, {"modules": []},
    {"rule_filter": ["different-rule"]}, {"rule_filter": [{"invalid": "rule"}]}, {"modules": "check"},
    {"trigger": "bulletin"},
    {"trigger": "scanner_import"}, {"trigger": "cluster_vulnerabilities"},
    {"status": "running"}, {"status": "pending"}, {"started_at": OLD},
    {"started_at": "invalid"},
])
def test_unrelated_unfinished_or_unordered_runs_do_not_affect_badge(env, changes):
    ctx, f = env
    save_run(ctx)
    expected = assess(ctx, f)
    save_run(ctx, "unrelated", at=NEWEST, **changes)
    assert assess(ctx, f) == expected


@pytest.mark.parametrize("rule", ["ssh-root", "RHEL-09-255045", "V-12345", "CCI-000001"])
def test_rule_filter_matches_scanner_identifiers_and_newest_target_attempt_wins(env, rule):
    ctx, f = env
    f = replace(f, group_id="V-12345", references=[Reference("cci", "CCI-000001")])
    save_run(ctx)
    save_run(ctx, "newest", at=NEWEST, rule_filter=[rule], results={"alpha": {"status": "error"}})
    assert assess(ctx, f)["latest_attempt"]["scan_id"] == "newest"


def test_historical_scan_bounds_history_including_retained_rows(env):
    ctx, f = env
    save_run(ctx, findings=[f])
    save_run(ctx, "newest", at=NEWEST)
    assert assess(ctx, f, scan_id="base")["status"] == "no_known_gap"
    historical = assess(ctx, f, scan_id="later")
    assert historical["view"] == "scan" and historical["latest_attempt"]["scan_id"] == "later"
    assert assess(ctx, f)["latest_attempt"]["scan_id"] == "newest"


@pytest.mark.parametrize("changes", [
    {"collected_at": "invalid"}, {"collected_at": "2026-11-05T10:00:00"},
    {"authorization_scope": None}, {"source": "future-scanner"},
    {"collection_provenance": {"observed_at": "invalid"}},
    {"source": "trivy", "collection_provenance": {"producer": "cluster_vulnerabilities"}},
])
def test_unknown_metadata_never_invents_freshness_or_scan_time(env, changes):
    ctx, f = env
    save_run(ctx)
    result = assess(ctx, replace(f, **changes))
    assert result["status"] == "unknown" and result["latest_attempt"] is None


def test_orders_actual_instants_and_does_not_order_ties_by_identifier(env):
    ctx, f = env
    save_run(ctx, at="2026-11-05T12:00:00+02:00")  # equal to observation
    assert assess(ctx, f)["status"] == "no_known_gap"
    save_run(ctx, "utc", at=LATER)
    assert assess(ctx, f)["latest_attempt"]["scan_id"] == "utc"
    save_run(ctx, "offset", at="2026-11-05T12:00:00+01:00")
    assert assess(ctx, f)["reason"] == "ambiguous_order"


def test_complete_omission_is_unknown_not_a_pass_and_latest_metadata_is_not_overstated(env):
    ctx, f = env
    save_run(ctx)
    save_run(ctx, "complete", at=NEWEST, coverage_incomplete=False, scheduling=None)
    result = assess(ctx, f)
    assert result["status"] == "unknown" and result["latest_attempt"] is None


def test_legacy_complete_run_without_target_outcomes_does_not_claim_failure(env):
    ctx, f = env
    save_run(ctx, coverage_incomplete=None, scheduling=None, results={})
    assert assess(ctx, f)["reason"] == "coverage_unavailable"


def test_page_index_reads_each_selected_run_once(env, monkeypatch):
    ctx, f = env
    save_run(ctx)
    load = ctx.store.load_findings
    reads = []
    def tracked(sid=None):
        reads.append(sid)
        return load(sid)
    monkeypatch.setattr(ctx.store, "load_findings", tracked)
    view = ReassessmentView(ctx)
    for index in range(10):
        assert view.assess(replace(f, id=f"fixture-{index}").to_dict())["status"] == "not_reassessed"
    assert reads == ["later"]


def test_reads_do_not_write_or_change_review_fingerprint_or_approvals(env, monkeypatch):
    ctx, f = env
    reviews = ReviewService(ctx)
    summary = reviews.summary(f)
    reviews.save(f, actor="Joshua Ott", disposition="false_positive", reason="Checked local evidence",
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                 expected_revision=summary["revision"], evidence_fingerprint=summary["evidence_fingerprint"])
    before = reviews.summary(f)
    p = ctx.gate.propose(actor="Joshua Ott", finding_id=f.id, host=f.host, title="Fixture",
                         fix_ref="fixture", fix_preview="test", rollback_plan="restore", risk="test")
    ctx.gate.approve(p.id, "Joshua Ott")
    proposals = deepcopy([p.to_dict() for p in ctx.gate.list()])
    fingerprint = evidence_fingerprint(f)
    save_run(ctx)
    paths = sorted(str(p.relative_to(ctx.store.root)) for p in ctx.store.root.rglob("*"))
    monkeypatch.setattr(ctx.store, "write_json", lambda *a, **kw: pytest.fail("reassessment wrote state"))
    monkeypatch.setattr(ctx.audit, "append", lambda *a, **kw: pytest.fail("reassessment wrote audit"))
    assert assess(ctx, f)["status"] == "not_reassessed"
    assert reviews.summary(f) == before and evidence_fingerprint(f) == fingerprint
    assert [p.to_dict() for p in ctx.gate.list()] == proposals
    assert sorted(str(p.relative_to(ctx.store.root)) for p in ctx.store.root.rglob("*")) == paths
