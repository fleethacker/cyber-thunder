"""Publication capacity and process exclusion with real native filesystem locks."""
from dataclasses import replace
import multiprocessing
import os
from pathlib import Path
import traceback
from types import SimpleNamespace

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings import lifecycle, review
from cyberthunder.findings.review import ReviewService, evidence_fingerprint
from cyberthunder.findings.schema import Finding
from cyberthunder.store import StateStore


def _context(root, backend):
    store = StateStore(root, backend=backend)
    audit = AuditLog(store.audit_log, node="publication-capacity-test")
    return SimpleNamespace(store=store, audit=audit, killswitch=KillSwitch(root, audit))


def _rows(count, scan_id="capacity", evidence="original"):
    return [Finding(host="fixture-target", source="trivy", rule_id=f"fixture-rule-{i}",
                    title="Publication capacity fixture", severity="high", status="open",
                    evidence=evidence, scan_id=scan_id) for i in range(count)]


def _run(scan_id="capacity", started="2026-11-06T10:00:00Z"):
    return {"id": scan_id, "started_at": started, "status": "done",
            "trigger": "cluster_vulnerabilities", "targets": ["fixture-target"]}


def _decision(service, finding, *, revision=0, fingerprint=None, reason="Fixture review"):
    return service.save(finding, actor="Joshua Ott", disposition="confirmed", reason=reason,
                        expected_revision=revision, evidence_fingerprint=fingerprint or evidence_fingerprint(finding))


def _join(worker):
    worker.join(10)
    if worker.is_alive():
        worker.terminate()
        worker.join(5)
        pytest.fail("publication worker did not terminate")
    assert worker.exitcode == 0


def _capacity_worker(root, backend, count, findings_first, result):
    ctx = None
    try:
        limit = None
        if os.name != "nt":
            import resource
            _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))
            limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        ctx = _context(root, backend)
        current = peak = 0
        acquire, release = lifecycle._try_lock, lifecycle._unlock

        def track_acquire(handle, **kwargs):
            nonlocal current, peak
            acquire(handle, **kwargs)
            current += 1
            peak = max(current, peak)

        def track_release(handle, **kwargs):
            nonlocal current
            try:
                release(handle, **kwargs)
            finally:
                current -= 1

        lifecycle._try_lock, lifecycle._unlock = track_acquire, track_release
        rows = _rows(count)
        if findings_first:
            ctx.store.save_findings("capacity", rows)
            ctx.store.save_scan_run(_run())
        else:
            ctx.store.save_scan_run(_run())
            ctx.store.save_findings("capacity", rows)
        assert len(ctx.store.current_findings()) == count
        # Exercise additions and a later changed batch, without any cached current view.
        ctx.store.save_findings("capacity", [replace(f, evidence="changed") for f in rows])
        assert {f.evidence for f in ctx.store.current_findings()} == {"changed"}
        assert len(ctx.store.load_findings("capacity")) == count
        assert current == 0
        result.send({"ok": True, "peak": peak, "limit": limit, "count": count})
    except BaseException:
        result.send({"ok": False, "traceback": traceback.format_exc()})
    finally:
        if ctx:
            ctx.store.close()
        result.close()


@pytest.mark.parametrize("count", [32, 1100])
@pytest.mark.parametrize("findings_first", [False, True])
def test_large_publication_with_bounded_native_descriptors(state_dir, count, findings_first, record_property):
    mp = multiprocessing.get_context("spawn")
    reader, writer = mp.Pipe(duplex=False)
    worker = mp.Process(target=_capacity_worker, args=(str(state_dir), os.environ["CT_STATE_BACKEND"],
                                                     count, findings_first, writer))
    worker.start()
    writer.close()
    try:
        assert reader.poll(30), "publication failed to finish under the descriptor limit"
        result = reader.recv()
        assert result["ok"], result.get("traceback")
        for key in ["peak", "limit", "count"]:
            record_property(key, result[key] if result[key] is not None else "native Windows")
        assert result["peak"] <= 257
        assert result["count"] == count
        if os.name != "nt":
            assert result["limit"] == 1024
    finally:
        reader.close()
        _join(worker)


def _stripe_examples(root):
    by_path = {}
    collision = None
    for i in range(10000):
        identity = f"stripe-fixture-{i}"
        path = lifecycle._stripe_path(root, identity)
        if path in by_path:
            collision = (by_path[path], identity)
        else:
            by_path[path] = identity
        if len(by_path) == 256 and collision:
            ordered = sorted(by_path)
            return by_path[ordered[0]], by_path[ordered[-1]], collision
    raise AssertionError("could not exercise the entire fixed stripe space")


def test_batch_deduplicates_collisions_and_preserves_outer_ownership(tmp_path):
    first, last, collision = _stripe_examples(tmp_path)
    with lifecycle.finding_lifecycle_lock(tmp_path, last):
        with pytest.raises(lifecycle.LifecycleReentry):
            with lifecycle.finding_lifecycle_locks(tmp_path, [last, first, first]):
                pytest.fail("nested acquisition entered")
        # Rejecting the nested batch must not leave another stripe owned.
        with lifecycle.finding_lifecycle_lock(tmp_path, first):
            pass
        with pytest.raises(lifecycle.LifecycleReentry):
            with lifecycle.finding_lifecycle_lock(tmp_path, last):
                pytest.fail("outer ownership was lost")
    with lifecycle.finding_lifecycle_locks(tmp_path, [*collision, *collision]):
        with pytest.raises(lifecycle.LifecycleReentry):
            with lifecycle.finding_lifecycle_lock(tmp_path, collision[1]):
                pytest.fail("collision bypassed the owned stripe")
    with lifecycle.finding_lifecycle_locks(tmp_path, [last, first, *collision]):
        pass


def _stripe_owner(root, identity, bulk, ready, release):
    guard = (lifecycle.finding_lifecycle_locks(Path(root), [identity, identity]) if bulk else
             lifecycle.finding_lifecycle_lock(Path(root), identity))
    with guard:
        ready.set()
        assert release.wait(20)


def test_batch_reentry_precedes_contention_on_another_process(tmp_path):
    first, last, _ = _stripe_examples(tmp_path)
    mp = multiprocessing.get_context("spawn")
    ready, release = mp.Event(), mp.Event()
    worker = mp.Process(target=_stripe_owner, args=(str(tmp_path), first, True, ready, release))
    worker.start()
    try:
        assert ready.wait(15)
        with lifecycle.finding_lifecycle_lock(tmp_path, last):
            # Otherwise an earlier busy stripe can hide known same-thread reentry
            # and incorrectly turn a non-retryable request into a publication wait.
            with pytest.raises(lifecycle.LifecycleReentry):
                with lifecycle.finding_lifecycle_locks(tmp_path, [first, last]):
                    pytest.fail("batch reentered its own stripe")
    finally:
        release.set()
        _join(worker)


@pytest.mark.parametrize("bulk", [False, True])
def test_single_and_batch_share_collision_exclusion_across_processes(tmp_path, bulk):
    first, last, collision = _stripe_examples(tmp_path)
    independent = next(i for i in [first, last] if lifecycle._stripe_path(tmp_path, i) !=
                       lifecycle._stripe_path(tmp_path, collision[0]))
    mp = multiprocessing.get_context("spawn")
    ready, release = mp.Event(), mp.Event()
    worker = mp.Process(target=_stripe_owner, args=(str(tmp_path), collision[0], bulk, ready, release))
    worker.start()
    try:
        assert ready.wait(15)
        guard = (lifecycle.finding_lifecycle_lock(tmp_path, collision[1]) if bulk else
                 lifecycle.finding_lifecycle_locks(tmp_path, [independent, collision[1]]))
        with pytest.raises(lifecycle.ReviewConflict):
            with guard:
                pytest.fail("colliding identities acquired different process locks")
        with lifecycle.finding_lifecycle_lock(tmp_path, independent):
            pass
    finally:
        release.set()
        _join(worker)
    with lifecycle.finding_lifecycle_locks(tmp_path, collision):
        pass


def _operation_owner(root, backend, owner, ready, release):
    ctx = _context(root, backend)
    service = ReviewService(ctx)
    finding = ctx.store.current_findings()[0]
    try:
        if owner == "remediation":
            with service.remediation_guard(finding):
                ready.set()
                assert release.wait(25)
        else:
            append = ctx.audit.append

            def pause_review(*args, **kwargs):
                receipt = append(*args, **kwargs)
                if kwargs.get("outcome") == "pending":
                    ready.set()
                    assert release.wait(25)
                return receipt

            ctx.audit.append = pause_review
            _decision(service, finding)
    finally:
        ctx.store.close()


def _large_publisher(root, backend, conflict, writing=None, release=None, initialized=None, begin=None):
    ctx = _context(root, backend)
    # SQLite schema initialization can need a writer. Finish it before deliberately
    # holding the other process's review transaction; the test targets publication.
    if initialized is not None:
        initialized.set()
        assert begin.wait(25)
    publish = review._publish_observation_once

    def observe_conflict(*args, **kwargs):
        try:
            return publish(*args, **kwargs)
        except lifecycle.ReviewConflict:
            conflict.set()
            raise

    review._publish_observation_once = observe_conflict
    write = ctx.store.write_json

    def pause_publication(path, document):
        if writing is not None and path == ctx.store.scans_dir / "updated" / "run.json":
            writing.set()
            assert release.wait(25)
        return write(path, document)

    ctx.store.write_json = pause_publication
    try:
        ctx.store.save_findings("updated", _rows(1100, "updated", "changed"))
        ctx.store.save_scan_run(_run("updated", "2026-11-06T11:00:00Z"))
    finally:
        ctx.store.close()


@pytest.mark.parametrize("owner", ["remediation", "review"])
def test_large_publisher_with_simultaneous_review_and_remediation(state_dir, owner, request):
    backend = os.environ["CT_STATE_BACKEND"]
    ctx = _context(state_dir, backend)
    request.addfinalizer(ctx.store.close)
    ctx.store.save_findings("capacity", _rows(1100))
    ctx.store.save_scan_run(_run())
    service = ReviewService(ctx)
    finding = ctx.store.current_findings()[0]
    mp = multiprocessing.get_context("spawn")
    ready, release, conflict = mp.Event(), mp.Event(), mp.Event()
    initialized, begin = mp.Event(), mp.Event()
    holder = mp.Process(target=_operation_owner, args=(str(state_dir), backend, owner, ready, release))
    publisher = mp.Process(target=_large_publisher, args=(str(state_dir), backend, conflict),
                           kwargs={"initialized": initialized, "begin": begin})
    publisher.start()
    try:
        assert initialized.wait(15)
        holder.start()
        assert ready.wait(15)
        begin.set()
        assert conflict.wait(15), "publication did not meet the active operation's lock"
        # A third actor tries the opposite operation while the first two overlap.
        if owner == "remediation":
            with pytest.raises(lifecycle.ReviewConflict):
                _decision(service, finding)
            ctx.store.write_json(ctx.store.link_state, {"connected": False})
        else:
            with pytest.raises(lifecycle.ReviewConflict):
                with service.remediation_guard(finding):
                    pytest.fail("remediation entered an active review")
        assert ctx.store.load_scan_run("updated") is None
        assert {f.evidence for f in ctx.store.current_findings()} == {"original"}
        if owner == "remediation":
            assert len(ctx.store.load_findings("updated")) == 1100  # staged, not yet published
    finally:
        release.set()
        begin.set()
        if holder.pid is not None:
            _join(holder)
        _join(publisher)
    try:
        assert ctx.store.load_scan_run("updated")["status"] == "done"
        assert len(ctx.store.current_findings()) == 1100
        assert {f.evidence for f in ctx.store.current_findings()} == {"changed"}
        current = ctx.store.get_finding(finding.id)
        history = service.history(current)
        assert history["history_count"] == (1 if owner == "review" else 0)
        assert history["revision"] == (2 if owner == "review" else 0)
        assert history["disposition"] == "unreviewed"
        with pytest.raises(lifecycle.ReviewConflict):
            _decision(service, finding)  # old evidence/revision cannot overwrite the changed view
        fresh = _decision(service, current, revision=history["revision"])
        assert fresh["history_count"] == history["history_count"] + 1
        assert fresh["revision"] == history["revision"] + 1
        assert ctx.audit.verify().ok
    finally:
        ctx.store.close()


def test_large_publication_holds_all_affected_stripes_through_write(state_dir, request):
    backend = os.environ["CT_STATE_BACKEND"]
    ctx = _context(state_dir, backend)
    request.addfinalizer(ctx.store.close)
    ctx.store.save_findings("capacity", _rows(1100))
    ctx.store.save_scan_run(_run())
    service = ReviewService(ctx)
    findings = ctx.store.current_findings()
    mp = multiprocessing.get_context("spawn")
    conflict, writing, release = mp.Event(), mp.Event(), mp.Event()
    publisher = mp.Process(target=_large_publisher, args=(str(state_dir), backend, conflict, writing, release))
    publisher.start()
    try:
        assert writing.wait(15)
        for finding in [findings[0], findings[-1]]:
            with pytest.raises(lifecycle.ReviewConflict):
                _decision(service, finding)
            with pytest.raises(lifecycle.ReviewConflict):
                with service.remediation_guard(finding):
                    pytest.fail("remediation entered during publication write")
        assert ctx.store.load_scan_run("updated") is None
        assert {f.evidence for f in ctx.store.current_findings()} == {"original"}
    finally:
        release.set()
        _join(publisher)
        ctx.store.close()
