"""Unavailable coverage never turns an older unresolved observation into a pass."""
from contextvars import ContextVar
from types import SimpleNamespace
import threading

import pytest

from cyberthunder.findings.schema import Finding
from cyberthunder.scan import ScanRun
from cyberthunder import scan_workers
from tests.scan_workers.test_workers import environment, offline


@pytest.mark.parametrize("outcome", ["failed", "timed_out", "unstarted", "empty_success"])
def test_full_run_omissions_preserve_complete_baseline(environment, monkeypatch, outcome):
    ctx, adapter = environment
    ids = [target.id for target in ctx.inventory.all()]
    old_time = "2026-01-01T00:00:00Z"
    baseline = ScanRun("complete-baseline", ids, status="done", started_at=old_time,
                       finished_at=old_time, coverage_incomplete=False)
    ctx.scanner._save(baseline)
    old = [Finding(host=tid, source="fixture", rule_id=rule, title="Unresolved baseline observation",
                   severity="high", status="open", collected_at=old_time, scan_id=baseline.id)
           for tid in ids for rule in ("FIXTURE-1", "OMITTED-2")]
    ctx.store.save_findings(baseline.id, old)
    before = {finding.id: finding.to_dict() for finding in ctx.store.current_findings()}
    assert len(before) == 12

    # A local clock makes timeout and queue ordering deterministic without wall sleeps.
    clock = [0.0]
    monkeypatch.setattr(scan_workers, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    ctx.settings.scan_max_workers = 1
    ctx.settings.scan_host_budget_s = 1

    def collect(target, transport):
        if outcome == "unstarted" and target.id == ids[0]:
            ctx.killswitch.engage("operator", "fixture stops before queued targets")
        if target.id == ids[1]:
            if outcome == "failed":
                raise RuntimeError("fixture collection unavailable")
            if outcome == "timed_out":
                clock[0] = 100.0

    adapter.hook = collect
    if outcome == "empty_success":
        monkeypatch.setattr(adapter, "run_detection", lambda *args: [])

    # Exercise a caller-supplied false flag: the scanner must set its own conservative
    # coverage policy before the first save, not rely on start() having supplied it.
    run = ScanRun("new-full-run", ids[:3], coverage_incomplete=False)
    saves = []
    save = ctx.store.save_scan_run

    def save_run(document):
        if document["id"] == run.id:
            saves.append((document["status"], document["coverage_incomplete"]))
            assert document["coverage_incomplete"] is True
        return save(document)

    monkeypatch.setattr(ctx.store, "save_scan_run", save_run)
    run = ctx.scanner.run(run)
    expected_status = {"failed": "partial", "timed_out": "partial", "unstarted": "stopped", "empty_success": "done"}
    assert run.status == expected_status[outcome]
    assert saves[0] == ("running", True) and saves[-1] == (run.status, True)
    unavailable = ids[:3] if outcome == "unstarted" else [ids[1]] if outcome != "empty_success" else []
    assert run.scheduling["unavailable_targets"] == unavailable
    assert run.scheduling["omitted_observations"] == "retain_without_revalidation"
    saved = ctx.store.load_scan_run(run.id)
    assert saved["scheduling"] == run.scheduling and saved["coverage_incomplete"] is True

    current = {finding.id: finding.to_dict() for finding in ctx.store.current_findings()}
    assert current.keys() == before.keys()
    observed = {finding.id for finding in ctx.store.load_findings(run.id)}
    for fid, old_finding in before.items():
        if fid not in observed:
            assert current[fid] == old_finding  # no freshness, status, source, or identity rewrite
    assert all(finding["status"] == "open" for finding in current.values())
    for tid in unavailable:
        assert ctx.inventory.get(tid).last_scan is None
        assert not (ctx.store.scans_dir / run.id / "raw" / tid / "collected.json").exists()
    if outcome == "unstarted":
        assert [transport.tid for transport in adapter.opened] == [ids[0]]
    if outcome == "timed_out":
        assert run.results[ids[1]].status == "timed_out"
        # The third host waited past the first two hosts' budget. Its own budget
        # begins at execution, so it must still collect successfully at clock=100.
        assert run.results[ids[2]].status == "done"
    if outcome == "empty_success":
        assert ctx.store.load_findings(run.id) == [] and len(current) == 12


def test_each_overlapping_worker_enters_a_distinct_request_context():
    request = ContextVar("scan_fixture_request", default="missing")
    scanner = SimpleNamespace(_lock=threading.Lock(), threads=[])
    barrier = threading.Barrier(2)

    def collect(tid):
        assert request.get() == "caller"
        request.set(tid)
        barrier.wait(5)
        assert request.get() == tid
        return tid

    token = request.set("caller")
    try:
        assert list(scan_workers._ordered_workers(scanner, ["first", "second"], 2, collect)) == ["first", "second"]
        assert request.get() == "caller"
        assert not scanner.threads
    finally:
        request.reset(token)
