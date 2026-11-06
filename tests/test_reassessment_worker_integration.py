"""Bounded scanner output flows through reassessment, API decisions and retention."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.findings.schema import Finding, Status
from cyberthunder.state import retention
from tests.scan_workers.test_workers import (
    FixtureAdapter, FixtureTransport, environment,
)
from tests.security.test_identity_boundary import headers, identity, verified_app


URL = "/api/v1/findings"
HOST = "host-000"


@pytest.fixture(autouse=True)
def fixture_transports_only(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("integration scans must use the injected fixture transport")

    # The API client's Windows event loop needs its own loopback socket pair.
    # Block the production transport factory without interfering with that pair.
    monkeypatch.setattr("cyberthunder.context.make_transport", forbidden)


@pytest.fixture
def timeline(monkeypatch):
    """Separate real runs without sleeps or editing their persisted timestamps."""
    clock = SimpleNamespace(at=datetime(2026, 1, 1, tzinfo=timezone.utc))

    class ScanClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.at

    monkeypatch.setattr("cyberthunder.findings.schema.datetime", ScanClock)
    from cyberthunder.findings import confidence
    assess = confidence.assess_for_context
    monkeypatch.setattr(confidence, "assess_for_context", lambda ctx, finding, **kw:
                        assess(ctx, finding, now=datetime(2026, 1, 10, tzinfo=timezone.utc)))
    return clock


@pytest.fixture
def native_collection(monkeypatch, timeline):
    def install(adapter):
        control = SimpleNamespace(outcome="open", detected=[])
        collect = adapter.collect

        def collect_evidence(*args, **kwargs):
            if control.outcome == "unavailable":
                raise OSError("fixture target unavailable")
            result = collect(*args, **kwargs)
            if control.outcome != "open":
                result.errors.append("required fixture evidence unavailable")
            return result

        def detect(target, collected):
            assert Path(collected.artifacts["fixture"]).read_text() == target.id
            if control.outcome == "omitted":
                return []
            status = "open" if control.outcome == "fresh_partial" else control.outcome
            finding = Finding(
                host=target.id, source="native", rule_id="INTEGRATION-1",
                title="Native collection observation", severity="high", status=status,
                evidence=f"{status} evidence at {timeline.at.isoformat()}",
                raw_ref=collected.artifacts["fixture"],
            )
            control.detected.append(deepcopy(finding.to_dict()))
            return [finding]

        monkeypatch.setattr(adapter, "collect", collect_evidence)
        monkeypatch.setattr(adapter, "run_detection", detect)
        return control

    return install


@pytest.fixture
def worker_case(environment, native_collection):
    ctx, adapter = environment
    return ctx, adapter, native_collection(adapter)


@pytest.fixture
def client(worker_case):
    ctx, _, _ = worker_case
    with TestClient(create_app(ctx)) as result:
        yield result


def run_scan(ctx, timeline, targets=(HOST,), **kwargs):
    timeline.at += timedelta(days=1)
    run = ctx.scanner.start(targets, modules=["check"], background=False, **kwargs)
    assert run.scheduling["max_workers"] == ctx.settings.scan_max_workers > 1
    assert run.scheduling["omitted_observations"] == "retain_without_revalidation"
    assert ctx.store.load_scan_run(run.id) == run.to_dict()
    assert not ctx.scanner.threads and not ctx.scanner._collection_transports
    return run


def detail(client, fid, **kwargs):
    response = client.get(f"{URL}/{fid}", **kwargs)
    assert response.status_code == 200, response.text
    return response.json()


def assert_unchanged_decisions(before, after):
    for key in ("id", "source", "scan_id", "collected_at", "collection_provenance",
                "authorization_scope", "evidence", "raw_ref", "scanner_status", "status",
                "confidence", "review", "remediated", "rollback", "needs_rescan", "proposal"):
        assert after[key] == before[key], key


@pytest.mark.parametrize("outcome,reason", [
    ("not_reviewed", "retained_incomplete_observation"),
    ("error", "retained_incomplete_observation"),
    ("not_a_finding", "retained_incomplete_observation"),
    ("not_applicable", "retained_incomplete_observation"),
    ("omitted", "partial_collection"),
    ("unavailable", "target_unavailable"),
])
def test_worker_metadata_decorates_retained_evidence_without_inflation(
        worker_case, client, timeline, outcome, reason):
    ctx, adapter, control = worker_case
    origin = run_scan(ctx, timeline)
    assert origin.status == "done"
    finding = ctx.store.load_findings(origin.id)[0]
    original = finding.to_dict()
    raw = Path(finding.raw_ref).read_bytes()
    before = detail(client, finding.id)
    assert before["reassessment"]["status"] == "no_known_gap"
    last_scan = ctx.inventory.get(HOST).last_scan
    control.outcome = outcome
    later = run_scan(ctx, timeline)
    target_status = "error" if outcome == "unavailable" else "partial"
    assert later.status == later.results[HOST].status == target_status
    assert later.coverage_incomplete is True
    assert later.scheduling["unavailable_targets"] == ([HOST] if outcome == "unavailable" else [])
    assert later.scheduling["partial_targets"] == ([] if outcome == "unavailable" else [HOST])
    retained = {HOST: [finding.id]} if reason == "retained_incomplete_observation" else {}
    assert later.scheduling["retained_incomplete_observations"] == retained
    assert ctx.store.load_findings(later.id) == []
    assert later.findings_count == later.results[HOST].findings == 0
    assert ctx.inventory.get(HOST).last_scan == last_scan
    assert 0 < adapter.peak <= ctx.settings.scan_max_workers
    if retained:
        assert control.detected[-1]["status"] == outcome

    audit_length = len(ctx.audit)
    after = detail(client, finding.id)
    annotation = after["reassessment"]
    assert annotation == ReassessmentView(ctx).assess(original)
    assert annotation["status"] == "not_reassessed" and annotation["reason"] == reason
    assert annotation["observation"] == {
        "observed_at": finding.collected_at, "source": "native", "scan_id": origin.id,
    }
    assert annotation["latest_attempt"] == {
        "scan_id": later.id, "started_at": later.started_at,
        "finished_at": later.finished_at, "target_status": target_status,
    }
    page = client.get(URL, params={"limit": 1, "status": "open"}).json()
    assert page["total"] == page["unfiltered_total"] == page["summary"]["total"] == 1
    assert page["findings"][0]["reassessment"] == annotation
    assert_unchanged_decisions(before, after)
    historical = detail(client, finding.id, params={"scan_id": origin.id})
    assert historical["reassessment"]["status"] == "no_known_gap"
    assert historical["reassessment"]["latest_attempt"] is None
    assert ctx.store.load_findings(origin.id)[0].to_dict() == original
    assert ctx.store.current_findings()[0].to_dict() == original
    assert Path(finding.raw_ref).read_bytes() == raw
    assert ctx.store.load_scan_run(later.id) == later.to_dict()
    assert len(ctx.audit) == audit_length


@pytest.mark.parametrize("lifecycle", ["reviewed", "verified", "rolled_back"])
def test_worker_withheld_result_preserves_existing_decisions(worker_case, client, timeline, lifecycle):
    from cyberthunder.findings.review import ReviewService

    ctx, _, control = worker_case
    origin = run_scan(ctx, timeline)
    finding = ctx.store.load_findings(origin.id)[0]
    if lifecycle == "reviewed":
        service = ReviewService(ctx)
        summary = service.summary(finding)
        service.save(finding, actor="Joshua Ott", disposition="false_positive",
                     reason="Manual evidence review",
                     expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                     expected_revision=summary["revision"],
                     evidence_fingerprint=summary["evidence_fingerprint"])
    else:
        proposal = ctx.gate.propose(
            actor="Joshua Ott", finding_id=finding.id, host=finding.host,
            title="Fixture change", fix_ref="fixture", fix_preview="reviewed setting",
            rollback_plan="restore", risk="test fixture",
        )
        ctx.gate.approve(proposal.id, "Joshua Ott")
        ctx.gate.start_apply(proposal.id, "Joshua Ott")
        ctx.gate.applied(proposal.id)
        ctx.gate.verified(proposal.id)
        if lifecycle == "rolled_back":
            ctx.gate.rolled_back(proposal.id, "Joshua Ott")
    before = detail(client, finding.id)
    control.outcome = "not_a_finding"
    later = run_scan(ctx, timeline)
    assert later.scheduling["retained_incomplete_observations"] == {HOST: [finding.id]}
    after = detail(client, finding.id)
    assert after["reassessment"]["reason"] == "retained_incomplete_observation"
    assert_unchanged_decisions(before, after)
    assert ctx.store.load_findings(origin.id)[0].to_dict() == finding.to_dict()


def test_partial_worker_can_publish_a_real_new_observation(worker_case, client, timeline):
    ctx, _, control = worker_case
    origin = run_scan(ctx, timeline)
    original = ctx.store.load_findings(origin.id)[0]
    last_scan = ctx.inventory.get(HOST).last_scan
    control.outcome = "fresh_partial"
    later = run_scan(ctx, timeline)
    assert later.status == "partial" and later.coverage_incomplete is True
    assert later.scheduling["retained_incomplete_observations"] == {}
    fresh = ctx.store.load_findings(later.id)[0]
    assert fresh.id == original.id and fresh.scan_id == later.id
    assert fresh.collected_at == later.started_at > original.collected_at
    assert fresh.evidence != original.evidence and fresh.status == Status.OPEN
    after = detail(client, original.id)
    assert after["scan_id"] == later.id and after["collected_at"] == fresh.collected_at
    assert after["scanner_status"] == after["status"] == "open"
    assert after["reassessment"]["status"] == "no_known_gap"
    assert after["reassessment"]["latest_attempt"] is None
    assert ReassessmentView(ctx).assess(original.to_dict())["reason"] == "newer_observation"
    assert ctx.inventory.get(HOST).last_scan == last_scan


def test_retention_pins_source_after_actual_incomplete_worker_run(worker_case, timeline):
    ctx, _, control = worker_case
    origin = run_scan(ctx, timeline)
    original = ctx.store.load_findings(origin.id)[0]
    control.outcome = "not_reviewed"
    later = run_scan(ctx, timeline)
    assert later.scheduling["retained_incomplete_observations"] == {HOST: [original.id]}
    before = [f.to_dict() for f in ctx.store.current_findings()]
    raw = Path(original.raw_ref).read_bytes()
    selected = retention.plan(ctx.store.root, ctx.store.backend_name,
                              cutoff_utc="2026-02-01T00:00:00Z")
    assert "current-observation" in selected["pinned"][origin.id]
    assert "cutoff" not in selected["pinned"][origin.id]
    assert "latest-scan" not in selected["pinned"][origin.id]
    assert "latest-target-producer" not in selected["pinned"][origin.id]
    assert "incomplete-scan" in selected["pinned"][later.id]
    assert origin.id not in selected["eligible"] and selected["deletion_enabled"] is False
    assert [f.to_dict() for f in ctx.store.current_findings()] == before
    assert ctx.store.load_scan_run(origin.id) == origin.to_dict()
    assert ctx.store.load_scan_run(later.id) == later.to_dict()
    assert Path(original.raw_ref).read_bytes() == raw


def test_actual_mixed_worker_run_cannot_expand_history_authority(
        verified_app, native_collection, timeline, monkeypatch):
    ctx, _, tokens, api, _ = verified_app
    ctx.settings.scan_max_workers = 2
    adapter = FixtureAdapter()
    control = native_collection(adapter)
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)
    monkeypatch.setattr(ctx, "transport_for", lambda target: FixtureTransport(adapter, target.id))
    person = identity()
    with principal_scope(person):
        origin = run_scan(ctx, timeline, ["alpha"], requested_by=person.actor)
    finding = ctx.store.load_findings(origin.id)[0]
    h = headers(tokens, person)
    before = detail(api, finding.id, headers=h)
    control.outcome = "not_reviewed"
    with principal_scope(person):
        visible = run_scan(ctx, timeline, ["alpha"], requested_by=person.actor)
    expected = detail(api, finding.id, headers=h)
    assert expected["reassessment"]["latest_attempt"]["scan_id"] == visible.id
    assert expected["reassessment"]["reason"] == "retained_incomplete_observation"
    assert_unchanged_decisions(before, expected)

    policy = json.loads(ctx.access.path.read_text())
    original_policy = deepcopy(policy)
    policy["entries"][0]["grants"][0]["target_ids"].append("beta")
    ctx.access.path.write_text(json.dumps(policy))
    with principal_scope(person):
        mixed = run_scan(ctx, timeline, ["alpha", "beta"], requested_by=person.actor)
    assert mixed.status == "partial"
    assert mixed.scheduling["retained_incomplete_observations"] == {"alpha": [finding.id]}
    ctx.access.path.write_text(json.dumps(original_policy))
    after = detail(api, finding.id, headers=h)
    assert after["reassessment"] == expected["reassessment"]
    assert_unchanged_decisions(expected, after)
    page = api.get(URL, headers=h).json()
    assert next(row for row in page["findings"] if row["id"] == finding.id)["reassessment"] == after["reassessment"]
    assert mixed.id not in json.dumps(page) and "beta" not in json.dumps(page)
    for path in (URL, f"{URL}/{finding.id}"):
        assert api.get(path, params={"scan_id": mixed.id}, headers=h).status_code == 403
    assert api.get(f"{URL}/{finding.id}", headers=headers(tokens, identity("second-user"))).status_code == 403
    with principal_scope(person):
        assert ReassessmentView(ctx).assess(finding.to_dict()) == after["reassessment"]
    assert not ctx.scanner.threads and adapter.active == 0
    assert all(transport.closed for transport in adapter.opened)
    assert ctx.audit.verify().ok
