"""Local review decisions: scoping, expiry, immutable observations and concurrent persistence."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import multiprocessing
import errno
import sys
import time
from types import SimpleNamespace

import pytest

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.killswitch import KillSwitch, KillSwitchEngaged
from cyberthunder.findings import review
from cyberthunder.findings import lifecycle
from cyberthunder.findings.review import ReviewConflict, ReviewService, evidence_fingerprint
from cyberthunder.findings.schema import Finding, Reference
from cyberthunder.state import is_document
from cyberthunder.store import StateStore


def context(root, backend=None):
    store = StateStore(root, backend=backend)
    audit = AuditLog(store.audit_log, node="review-test")
    return SimpleNamespace(store=store, audit=audit, killswitch=KillSwitch(root, audit))


def observation(**changes):
    return Finding(**{"host": "range-01", "source": "openscap", "rule_id": "SV-12345r1_rule",
                      "title": "SSH configuration", "severity": "high", "status": "open",
                      "benchmark": "RHEL_9", "benchmark_release": "V2R5",
                      "evidence": "PermitRootLogin yes", "scan_id": "scan-1", **changes})


def persist(ctx, finding, scan_id="scan-1", started_at="2026-11-05T10:00:00Z", **run):
    ctx.store.save_scan_run({"id": scan_id, "started_at": started_at, "status": "done", **run})
    ctx.store.save_findings(scan_id, [finding])


@pytest.fixture
def env(state_dir):
    ctx = context(state_dir)
    finding = observation()
    persist(ctx, finding)
    yield ctx, ReviewService(ctx), finding
    assert ctx.audit.verify().ok
    ctx.store.close()


def decision(service, finding, **changes):
    summary = service.summary(finding)
    args = {"actor": "ITC Rivera", "disposition": "false_positive", "reason": "Verified with the owner",
            "supporting_evidence": "Local configuration export", "expected_revision": summary["revision"],
            "evidence_fingerprint": summary["evidence_fingerprint"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(), **changes}
    return service.save(finding, **args)


def test_unreviewed_pass_is_not_a_human_decision_and_reads_do_not_write(env, monkeypatch):
    ctx, service, finding = env
    paths_before = sorted(str(path.relative_to(ctx.store.root)) for path in ctx.store.root.rglob("*"))
    monkeypatch.setattr(ctx.store, "write_json", lambda *a, **kw: pytest.fail("read wrote state"))
    monkeypatch.setattr(ctx.audit, "append", lambda *a, **kw: pytest.fail("read wrote audit"))
    for status in ("not_a_finding", "not_applicable", "not_reviewed", "error", "open"):
        result = service.history(replace(finding, status=status))
        assert result == {"disposition": "unreviewed", "active": False, "suppressed": False,
                          "revision": 0, "evidence_fingerprint": evidence_fingerprint(replace(finding, status=status)),
                          "current": None, "history_count": 0, "reopened_reason": None,
                          "identity_verified": False, "history": []}
    assert ctx.store.list_json(ctx.store.root / "finding_reviews") == []
    assert sorted(str(path.relative_to(ctx.store.root)) for path in ctx.store.root.rglob("*")) == paths_before


@pytest.mark.parametrize("disposition", sorted(review.DISPOSITIONS))
def test_all_decisions_audited_original_unchanged_and_persisted_on_selected_backend(env, disposition):
    ctx, service, finding = env
    before = ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json")
    result = decision(service, finding, disposition=disposition)
    assert result["revision"] == result["history_count"] == 1
    assert result["suppressed"] == (disposition in review.SUPPRESSING)
    assert result["active"] == (disposition != "unreviewed")
    assert result["current"]["reviewed_by"] == "ITC Rivera"
    assert result["current"]["identity_verified"] is False
    assert result["identity_verified"] is False
    assert ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json") == before
    path = ctx.store.list_json(ctx.store.root / "finding_reviews")[0]
    assert is_document(ctx.store.logical_path(path))
    assert path.exists() == (ctx.store.backend_name == "json")
    audit = list(ctx.audit.records())
    assert audit[0]["details"]["event"] == result["current"]
    assert audit[0]["outcome"] == "pending" and audit[-1]["outcome"] == "ok"
    reopened = context(ctx.store.root, ctx.store.backend_name)
    assert ReviewService(reopened).history(finding) == result
    reopened.store.close()


def test_reversal_appends_without_deleting_or_reactivating_old_review(env):
    _, service, finding = env
    original = decision(service, finding)
    reversed_view = decision(service, finding, disposition="unreviewed", reason="Recheck the evidence", expires_at=None)
    assert reversed_view["history_count"] == reversed_view["revision"] == 2
    assert reversed_view["history"][0] == original["current"]
    assert reversed_view["current"]["disposition"] == "unreviewed"
    assert not reversed_view["suppressed"] and not reversed_view["active"]


def test_expiry_exact_boundary_reopens_read_only(env, monkeypatch):
    ctx, service, finding = env
    result = decision(service, finding)
    expiry = review.parse_timestamp(result["current"]["expires_at"])
    assert service.summary(finding, now=expiry - timedelta(microseconds=1))["suppressed"]
    monkeypatch.setattr(ctx.store, "write_json", lambda *a, **kw: pytest.fail("expiry wrote state"))
    expired = service.summary(finding, now=expiry)
    assert expired["disposition"] == "unreviewed" and not expired["suppressed"]
    assert "expired" in expired["reopened_reason"]
    assert expired["revision"] == 1 and expired["current"] == result["current"]


@pytest.mark.parametrize("change", [
    {"host": "range-02"}, {"source": "scc"}, {"rule_id": "SV-12345r2_rule"},
    {"rule_version": "RHEL-09-1"}, {"benchmark": "other"}, {"benchmark_release": "V2R6"},
    {"severity": "low"}, {"status": "error"}, {"status": "not_a_finding"},
    {"evidence": "PermitRootLogin no"}, {"check_text": "New detector check"},
    {"tags": ["image:sha256:updated"]}, {"references": [Reference("cve", "CVE-2026-12345")]},
])
def test_relevant_changes_reopen_without_altering_history(env, change):
    _, service, finding = env
    result = decision(service, finding)
    current = replace(finding, **change)
    reopened = service.summary(current)
    assert reopened["disposition"] == "unreviewed" and not reopened["active"] and not reopened["suppressed"]
    assert reopened["evidence_fingerprint"] != result["evidence_fingerprint"]
    assert "changed" in reopened["reopened_reason"] and reopened["revision"] == 1
    assert reopened["current"] == result["current"]


def test_canonical_fingerprint_excludes_bookkeeping_and_includes_provenance():
    finding = observation(tags=["image:stable", "native"], references=[Reference("cve", "one"), Reference("cve", "two")])
    finding.collection_provenance = {"detector": {"version": "1", "name": "local-check"},
                                     "package": {"name": "ssh", "version": "9.1"},
                                     "image": {"digest": "sha256:abc"}, "collected_at": "old"}
    updated = deepcopy(finding)
    updated.scan_id, updated.collected_at, updated.raw_ref = "new", "new time", "elsewhere.xml"
    updated.tags.reverse()
    updated.references.reverse()
    updated.collection_provenance = {"collected_at": "new", "image": {"digest": "sha256:abc"},
                                     "package": {"version": "9.1", "name": "ssh"},
                                     "detector": {"name": "local-check", "version": "1"},
                                     "model_output": "display", "confidence": {"grade": "high"},
                                     "raw_ref": "copy.xml"}
    assert evidence_fingerprint(finding) == evidence_fingerprint(updated)
    for group, field in (("detector", "version"), ("package", "version"), ("image", "digest")):
        changed = deepcopy(updated)
        changed.collection_provenance[group][field] = "changed"
        assert evidence_fingerprint(changed) != evidence_fingerprint(finding)


def test_timestamp_only_rescan_preserves_review_and_save_uses_current_observation(env):
    ctx, service, finding = env
    initial = decision(service, finding)
    new = replace(finding, scan_id="scan-2", collected_at="2026-11-05T11:00:00Z", raw_ref="new.xml")
    persist(ctx, new, "scan-2", "2026-11-05T11:00:00Z")
    assert service.summary(new)["suppressed"]
    changed = replace(new, evidence="new finding facts")
    persist(ctx, changed, "scan-2", "2026-11-05T11:00:00Z")
    with pytest.raises(ReviewConflict, match="(revision|evidence) changed"):
        decision(service, finding, expected_revision=initial["revision"])
    # A stale object cannot overwrite the scope or evidence after the operator reloads the digest.
    saved = decision(service, finding, evidence_fingerprint=service.summary(changed)["evidence_fingerprint"])
    assert saved["evidence_fingerprint"] == evidence_fingerprint(changed)


def test_stale_revision_and_missing_current_finding_cannot_write(env):
    ctx, service, finding = env
    decision(service, finding)
    with pytest.raises(ReviewConflict, match="revision changed"):
        decision(service, finding, expected_revision=0)
    ctx.store.save_scan_run({"id": "scan-2", "started_at": "2026-11-05T11:00:00Z", "status": "done"})
    ctx.store.save_findings("scan-2", [])
    assert ctx.store.get_finding(finding.id) is not None  # historical fallback is deliberately bypassed
    with pytest.raises(KeyError, match="not in the current"):
        decision(service, finding)
    assert service.history(finding)["history_count"] == 1


@pytest.mark.parametrize("value", [None, "", "2026-12-01", "2026-12-01T12:00:00", "tomorrow", 123,
                                  "2026-02-30T12:00:00Z", "2026-12-01T12:00:00+01:60", "2001-01-01T00:00:00Z"])
def test_suppression_rejects_missing_malformed_or_expired_timestamps(env, value):
    _, service, finding = env
    with pytest.raises(ValueError):
        decision(service, finding, expires_at=value)
    assert service.history(finding)["history_count"] == 0


@pytest.mark.parametrize("changes", [
    {"reason": " "}, {"reason": None}, {"reason": "x" * (review.MAX_REASON_LENGTH + 1)},
    {"supporting_evidence": "x" * (review.MAX_SUPPORTING_EVIDENCE_LENGTH + 1)},
    {"disposition": "pass"}, {"expected_revision": True}, {"expected_revision": -1},
    {"evidence_fingerprint": "not-a-digest"}, {"disposition": "unreviewed", "reason": ""},
])
def test_invalid_and_oversized_input_never_writes(env, changes):
    ctx, service, finding = env
    with pytest.raises(ValueError):
        decision(service, finding, **changes)
    assert not list(ctx.audit.records()) and service.history(finding)["history_count"] == 0


@pytest.mark.parametrize("actor", ["", "system", "agent:test", "policy:window", "Bad\nName"])
def test_named_human_required(env, actor):
    _, service, finding = env
    with pytest.raises(PermissionError):
        decision(service, finding, actor=actor)
    assert service.history(finding)["history_count"] == 0


def test_kill_guard_and_audit_failure_prevent_review_persistence(env, monkeypatch):
    ctx, service, finding = env
    ctx.killswitch.engage("ITC Rivera", "stop")
    with pytest.raises(KillSwitchEngaged):
        decision(service, finding)
    assert service.summary(finding)["revision"] == 0
    ctx.killswitch.release("ITC Rivera", "resume")
    def broken_audit(*args, **kwargs):
        raise OSError("audit unavailable")
    monkeypatch.setattr(ctx.audit, "append", broken_audit)
    with pytest.raises(OSError, match="audit unavailable"):
        decision(service, finding)
    assert service.summary(finding)["revision"] == 0


def test_history_limit_preserves_every_existing_event(env, monkeypatch):
    _, service, finding = env
    monkeypatch.setattr(review, "MAX_HISTORY_EVENTS", 2)
    decision(service, finding)
    with pytest.raises(ValueError, match="reserved for reversal"):
        decision(service, finding)
    before = decision(service, finding, disposition="unreviewed", reason="Reconsider")
    with pytest.raises(ValueError, match="existing events are preserved"):
        decision(service, finding)
    assert service.history(finding) == before


def test_persisted_detector_content_and_package_changes_reopen(env):
    ctx, service, finding = env
    finding.collection_provenance = {"detector": {"name": "local-check", "version": "1"},
                                     "content": {"id": "RHEL_9", "version": "V2R5"},
                                     "package": {"name": "openssh", "version": "9.1"},
                                     "image": {"digest": "sha256:abc"}, "observed_at": "2026-11-05T10:00:00Z"}
    persist(ctx, finding)
    decision(service, finding)
    for group, field in (("detector", "version"), ("content", "version"), ("package", "version"), ("image", "digest")):
        changed = deepcopy(finding)
        changed.collection_provenance[group][field] = "new"
        persist(ctx, changed, "scan-2", "2026-11-05T11:00:00Z")
        assert not service.summary(ctx.store.current_findings()[0])["suppressed"]
    timestamp_only = deepcopy(finding)
    timestamp_only.collection_provenance["observed_at"] = "2026-11-05T11:00:00Z"
    persist(ctx, timestamp_only, "scan-2", "2026-11-05T11:00:00Z")
    assert not service.summary(ctx.store.current_findings()[0])["suppressed"]
    assert "durably reopened" in service.summary(ctx.store.current_findings()[0])["reopened_reason"]


def test_scan_changes_between_validation_and_write_are_rejected(env, monkeypatch):
    ctx, service, finding = env
    original = ctx.audit.append
    def change_after_pending(*args, **kwargs):
        record = original(*args, **kwargs)
        if kwargs.get("outcome") == "pending":
            persist(ctx, replace(finding, evidence="changed during review"))
        return record
    monkeypatch.setattr(ctx.audit, "append", change_after_pending)
    with pytest.raises(ReviewConflict, match="lifecycle is busy"):
        decision(service, finding)
    assert service.history(finding)["history_count"] == 0
    assert list(ctx.audit.records())[-1]["outcome"] == "pending"
    assert ctx.store.current_findings()[0].evidence == finding.evidence


def test_failed_document_write_keeps_prior_history_and_pending_audit(env, monkeypatch):
    ctx, service, finding = env
    before = decision(service, finding)
    def failed_write(*args, **kwargs):
        raise OSError("document unavailable")
    monkeypatch.setattr(ctx.store, "write_json", failed_write)
    with pytest.raises(OSError, match="document unavailable"):
        decision(service, finding, disposition="unreviewed", reason="Reconsider")
    assert service.history(finding) == before
    pending = list(ctx.audit.records())[-1]
    assert pending["outcome"] == "pending" and pending["details"]["event"]["revision"] == 2


def test_corrupt_history_is_never_reset(env):
    ctx, service, finding = env
    decision(service, finding)
    path = ctx.store.list_json(ctx.store.root / "finding_reviews")[0]
    broken = ctx.store.read_json(path)
    broken["history"][0]["expires_at"] = "bad date"
    ctx.store.write_json(path, broken)
    with pytest.raises(ValueError):
        service.summary(finding)
    assert ctx.store.read_json(path) == broken


def _race_worker(root, backend, ready, start, results):
    ctx = context(root, backend)
    service = ReviewService(ctx)
    finding = ctx.store.current_findings()[0]
    digest = service.summary(finding)["evidence_fingerprint"]
    ready.put(True)
    if not start.wait(15):
        results.put("timeout")
        return
    try:
        decision(service, finding, expected_revision=0, evidence_fingerprint=digest)
        results.put("saved")
    except ReviewConflict:
        results.put("conflict")
    finally:
        ctx.store.close()


def test_cross_process_competing_saves_keep_one_event(env):
    ctx, service, finding = env
    mp = multiprocessing.get_context("spawn")
    ready, results, start = mp.Queue(), mp.Queue(), mp.Event()
    processes = [mp.Process(target=_race_worker, args=(str(ctx.store.root), ctx.store.backend_name,
                                                     ready, start, results)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        for _ in processes:
            assert ready.get(timeout=20)
        start.set()
        assert sorted(results.get(timeout=20) for _ in processes) == ["conflict", "saved"]
        for process in processes:
            process.join(timeout=5)
            assert process.exitcode == 0
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        ready.close()
        results.close()
    assert service.history(finding)["history_count"] == 1


@pytest.mark.parametrize("change", ["status", "release", "detector"])
@pytest.mark.parametrize("order", ["run_first", "findings_first"])
def test_recurrence_never_reactivates_old_review_without_intermediate_get(env, change, order):
    ctx, service, original = env
    original.collection_provenance = {"detector": {"name": "local", "version": "1"}}
    persist(ctx, original)
    saved = decision(service, original)
    historical = ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json")
    changed = deepcopy(original)
    if change == "status":
        changed.status = type(original.status).NOT_A_FINDING
    elif change == "release":
        changed.benchmark_release = "V2R6"
    else:
        changed.collection_provenance["detector"]["version"] = "2"
    # No summary/history call between A -> B -> A. Publication alone must invalidate.
    for index, finding in ((2, changed), (3, original)):
        sid = f"scan-{index}"
        run = {"id": sid, "started_at": f"2026-11-05T1{index}:00:00Z", "status": "done"}
        if order == "findings_first":
            ctx.store.save_findings(sid, [finding])
            ctx.store.save_scan_run(run)
        else:
            ctx.store.save_scan_run(run)
            ctx.store.save_findings(sid, [finding])
    view = service.history(ctx.store.current_findings()[0])
    assert view["revision"] == 2 and view["history_count"] == 1
    assert view["history"] == saved["history"]
    assert not view["suppressed"] and view["disposition"] == "unreviewed"
    assert "durably reopened" in view["reopened_reason"]
    assert ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json") == historical
    with pytest.raises(ReviewConflict, match="revision changed"):
        decision(service, original, expected_revision=1)
    fresh = decision(service, original)
    assert fresh["suppressed"] and fresh["revision"] == 3 and fresh["history_count"] == 2
    invalidations = [r for r in ctx.audit.records() if r["action"] == "finding.review_invalidated"]
    assert len(invalidations) == 1
    record = invalidations[0]
    assert record["actor"] == "system" and record["details"]["source"]["scan_id"] == "scan-2"
    assert record["details"]["review_event_id"] == saved["current"]["id"]
    doc = ctx.store.read_json(service._path(original))
    assert doc["invalidations"][0]["audit"] == {"seq": record["seq"], "hash": record["hash"]}


def test_identical_observations_keep_review_across_partial_and_full_scans(env):
    ctx, service, finding = env
    finding.collection_provenance = {"detector": {"version": "1"}, "observed_at": "2026-11-05T10:00:00Z"}
    persist(ctx, finding)
    before = decision(service, finding)
    for index, trigger in ((2, "verify"), (3, "manual")):
        same = deepcopy(finding)
        same.scan_id, same.collected_at, same.raw_ref = f"scan-{index}", "2026-11-05T15:00:00Z", "moved.xml"
        same.collection_provenance["observed_at"] = "2026-11-05T15:00:00Z"
        persist(ctx, same, f"scan-{index}", f"2026-11-05T1{index}:00:00Z", trigger=trigger)
    after = service.history(ctx.store.current_findings()[0])
    assert after == before


def test_partial_overlay_and_completed_full_scan_absence_invalidate_correctly(env):
    ctx, service, finding = env
    before = decision(service, finding)
    # A partial scan of an unrelated rule must not remove this review.
    other = observation(rule_id="other-rule")
    persist(ctx, other, "scan-2", "2026-11-05T11:00:00Z", trigger="verify")
    assert service.history(finding) == before
    # Incremental full-scan publication is not a final removal of an unseen rule.
    ctx.store.save_scan_run({"id": "scan-3", "started_at": "2026-11-05T12:00:00Z", "status": "running"})
    ctx.store.save_findings("scan-3", [other])
    assert service.history(finding) == before
    ctx.store.save_scan_run({"id": "scan-3", "started_at": "2026-11-05T12:00:00Z", "status": "done"})
    # Reappearance cannot resurrect the pre-removal decision.
    persist(ctx, finding, "scan-4", "2026-11-05T13:00:00Z")
    assert not service.summary(finding)["suppressed"] and service.summary(finding)["revision"] == 2


def test_partial_change_and_late_older_publication_respect_current_order(env):
    ctx, service, finding = env
    persist(ctx, finding, "new-full", "2026-11-05T12:00:00Z")
    saved = decision(service, finding)
    changed = replace(finding, evidence="different result")
    persist(ctx, changed, "late-old", "2026-11-05T11:00:00Z", trigger="verify")
    assert service.history(finding) == saved
    persist(ctx, changed, "new-partial", "2026-11-05T13:00:00Z", trigger="verify")
    persist(ctx, finding, "next-partial", "2026-11-05T14:00:00Z", trigger="verify")
    assert not service.summary(finding)["suppressed"]


def test_invalidation_failure_blocks_new_evidence_and_preserves_history(env, monkeypatch):
    ctx, service, finding = env
    saved = decision(service, finding)
    before = ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json")
    append = AuditLog.append
    def failed_invalidation(self, action, *args, **kwargs):
        if action == "finding.review_invalidated":
            raise OSError("invalidation audit unavailable")
        return append(self, action, *args, **kwargs)
    monkeypatch.setattr(AuditLog, "append", failed_invalidation)
    with pytest.raises(OSError, match="invalidation audit unavailable"):
        ctx.store.save_findings("scan-1", [replace(finding, status="not_a_finding")])
    assert ctx.store.read_json(ctx.store.scans_dir / "scan-1" / "findings.json") == before
    assert service.history(finding) == saved


def test_missing_invalidation_ledger_fails_closed(env):
    ctx, service, finding = env
    decision(service, finding)
    ctx.store.save_findings("scan-1", [replace(finding, status="not_a_finding")])
    ctx.store.save_findings("scan-1", [finding])
    doc = ctx.store.read_json(service._path(finding))
    doc["invalidations"] = []
    ctx.store.write_json(service._path(finding), doc)
    with pytest.raises(ValueError, match="ledger is incomplete"):
        service.summary(finding)


def test_remediation_guard_rejects_same_thread_save_and_releases_after_exception(env):
    _, service, finding = env
    with pytest.raises(RuntimeError, match="apply interrupted"):
        with service.remediation_guard(finding):
            assert not service.summary(finding)["suppressed"]
            started = time.monotonic()
            with pytest.raises(ReviewConflict, match="lifecycle is busy"):
                decision(service, finding)
            assert time.monotonic() - started < 1
            assert service.summary(finding)["history_count"] == 0
            raise RuntimeError("apply interrupted")
    assert decision(service, finding)["suppressed"]


def _lifecycle_owner(root, backend, mode, ready, release):
    ctx = context(root, backend)
    service = ReviewService(ctx)
    finding = ctx.store.current_findings()[0]
    try:
        if mode == "apply":
            with service.remediation_guard(finding):
                ready.set()
                assert release.wait(20)
        else:
            append = ctx.audit.append
            def pause_save(*args, **kwargs):
                receipt = append(*args, **kwargs)
                if kwargs.get("outcome") == "pending":
                    ready.set()
                    assert release.wait(20)
                return receipt
            ctx.audit.append = pause_save
            decision(service, finding)
    finally:
        ctx.store.close()


@pytest.mark.parametrize("owner", ["apply", "review"])
def test_cross_process_lifecycle_conflict_is_immediate_without_sqlite_deadlock(env, owner):
    ctx, service, finding = env
    mp = multiprocessing.get_context("spawn")
    ready, release = mp.Event(), mp.Event()
    worker = mp.Process(target=_lifecycle_owner, args=(str(ctx.store.root), ctx.store.backend_name,
                                                     owner, ready, release))
    worker.start()
    try:
        assert ready.wait(15)
        started = time.monotonic()
        if owner == "apply":
            with pytest.raises(ReviewConflict):
                decision(service, finding)
            # Holding the apply guard does not hold a SQLite transaction during remote work.
            ctx.store.write_json(ctx.store.link_state, {"connected": False})
        else:
            with pytest.raises(ReviewConflict):
                with service.remediation_guard(finding):
                    pytest.fail("apply entered while review was saving")
        assert time.monotonic() - started < 1
    finally:
        release.set()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
    assert worker.exitcode == 0
    if owner == "apply":
        assert service.summary(finding)["history_count"] == 0
        assert decision(service, finding)["suppressed"]
    else:
        with service.remediation_guard(finding):
            assert service.summary(finding)["suppressed"]


@pytest.mark.parametrize("windows", [False, True])
def test_platform_lock_calls_are_nonblocking_and_unlock_only_on_success(tmp_path, monkeypatch, windows):
    calls = []
    if windows:
        def locking(fd, mode, count):
            calls.append((mode, count))
        fake = SimpleNamespace(LK_NBLCK=10, LK_UNLCK=11, locking=locking)
        monkeypatch.setitem(sys.modules, "msvcrt", fake)
        expected = [(10, 1), (11, 1)]
    else:
        def flock(fd, mode):
            calls.append(mode)
        fake = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, flock=flock)
        monkeypatch.setitem(sys.modules, "fcntl", fake)
        expected = [6, 8]
    acquire, release = lifecycle._try_lock, lifecycle._unlock
    monkeypatch.setattr(lifecycle, "_try_lock", lambda handle, **kw: acquire(handle, windows=windows))
    monkeypatch.setattr(lifecycle, "_unlock", lambda handle, **kw: release(handle, windows=windows))
    with lifecycle.finding_lifecycle_lock(tmp_path, "finding-1"):
        pass
    assert calls == expected
    calls.clear()
    def busy(*args):
        raise OSError(errno.EAGAIN, "lock is busy")
    monkeypatch.setattr(fake, "locking" if windows else "flock", busy)
    monkeypatch.setattr(lifecycle, "_unlock", lambda *a, **kw: pytest.fail("unlocked without ownership"))
    with pytest.raises(ReviewConflict):
        with lifecycle.finding_lifecycle_lock(tmp_path, "finding-1"):
            pytest.fail("acquired busy lock")


def test_scan_publish_while_apply_owns_reviewed_finding_fails_without_deadlock(env):
    ctx, service, finding = env
    decision(service, finding, disposition="confirmed", expires_at=None)
    with service.remediation_guard(finding):
        started = time.monotonic()
        with pytest.raises(ReviewConflict):
            ctx.store.save_findings("scan-1", [replace(finding, status="not_a_finding")])
        assert time.monotonic() - started < 1
    ctx.store.save_findings("scan-1", [replace(finding, status="not_a_finding")])
    assert service.summary(finding)["disposition"] == "unreviewed"


def test_publication_retries_changed_review_but_unrelated_and_identical_writes_proceed(env):
    ctx, service, finding = env
    before = decision(service, finding, disposition="confirmed", expires_at=None)
    changed = replace(finding, status="not_a_finding")
    with ThreadPoolExecutor(max_workers=1) as pool:
        with service.remediation_guard(finding):
            pending = pool.submit(ctx.store.save_findings, "scan-1", [changed])
            time.sleep(0.1)
            assert not pending.done()
            # The blocked publisher must release coordination on each retry. Neither an
            # identical observation nor an unrelated partial scan needs the held lock.
            started = time.monotonic()
            ctx.store.save_findings("scan-1", [finding])
            persist(ctx, observation(rule_id="unrelated"), "unrelated-scan", "2026-11-05T11:00:00Z", trigger="verify")
            assert time.monotonic() - started < 2
            assert service.history(finding) == before
        pending.result(timeout=5)
    assert ctx.store.load_findings("scan-1")[0].status.value == "not_a_finding"
    assert not service.summary(finding)["active"] and service.summary(finding)["revision"] == 2


def test_publication_timeout_keeps_observations_and_review_intact(env, monkeypatch):
    ctx, service, finding = env
    saved = decision(service, finding)
    monkeypatch.setattr(review, "PUBLICATION_LOCK_TIMEOUT", 0.05)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with service.remediation_guard(finding):
            pending = pool.submit(ctx.store.save_findings, "scan-1", [replace(finding, status="not_a_finding")])
            with pytest.raises(TimeoutError, match="publication busy"):
                pending.result(timeout=2)
    assert ctx.store.load_findings("scan-1")[0].status.value == "open"
    assert service.history(finding) == saved


def _publication_worker(root, backend, index, ready, start, results):
    ctx = context(root, backend)
    ready.put(True)
    try:
        assert start.wait(15)
        for n in range(6):
            sid = f"parallel-{index}-{n}"
            f = observation(rule_id=f"rule-{index}-{n}", scan_id=sid)
            run = {"id": sid, "started_at": f"2026-11-05T12:{index:02d}:{n:02d}Z", "status": "running",
                   "trigger": "verify"}
            if n % 2:
                ctx.store.save_findings(sid, [f])
                ctx.store.save_scan_run(run)
            else:
                ctx.store.save_scan_run(run)
                ctx.store.save_findings(sid, [f])
            ctx.store.save_scan_run(dict(run, status="done"))
        results.put("published")
    except Exception as exc:
        results.put(repr(exc))
    finally:
        ctx.store.close()


@pytest.mark.parametrize("existing_review", [False, True])
def test_parallel_scan_publishers_preserve_every_run_and_finding(env, existing_review):
    ctx, service, finding = env
    saved = decision(service, finding) if existing_review else None
    mp = multiprocessing.get_context("spawn")
    ready, results, start = mp.Queue(), mp.Queue(), mp.Event()
    workers = [mp.Process(target=_publication_worker,
                          args=(str(ctx.store.root), ctx.store.backend_name, index, ready, start, results))
               for index in range(3)]
    try:
        for worker in workers:
            worker.start()
        for _ in workers:
            assert ready.get(timeout=15)
        start.set()
        assert [results.get(timeout=25) for _ in workers] == ["published"] * 3
        for worker in workers:
            worker.join(timeout=5)
            assert worker.exitcode == 0
    finally:
        start.set()
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        ready.close()
        results.close()
    for index in range(3):
        for n in range(6):
            sid = f"parallel-{index}-{n}"
            assert ctx.store.load_scan_run(sid)["status"] == "done"
            assert ctx.store.load_findings(sid)[0].rule_id == f"rule-{index}-{n}"
    if existing_review:
        assert service.history(finding) == saved


def test_no_review_policy_evidence_cannot_change_inside_apply_callback(env):
    ctx, service, finding = env
    changed = replace(finding, collection_provenance={"partial": True})
    before = ctx.store.load_findings("scan-1")[0].to_dict()
    with service.remediation_guard(finding):
        started = time.monotonic()
        with pytest.raises(ReviewConflict, match="lifecycle is busy"):
            ctx.store.save_findings("scan-1", [changed])
        assert time.monotonic() - started < 1
        assert ctx.store.load_findings("scan-1")[0].to_dict() == before
    assert service.summary(finding)["history_count"] == 0


def test_no_review_changed_evidence_waits_while_identical_and_unrelated_scans_proceed(env):
    ctx, service, finding = env
    changed = replace(finding, collection_provenance={"partial": True})
    with ThreadPoolExecutor(max_workers=1) as pool:
        with service.remediation_guard(finding):
            pending = pool.submit(ctx.store.save_findings, "scan-1", [changed])
            time.sleep(0.1)
            assert not pending.done()
            assert ctx.store.load_findings("scan-1")[0].collection_provenance == finding.collection_provenance
            started = time.monotonic()
            same = replace(finding, collected_at="2026-11-05T15:00:00Z", raw_ref="moved-result.xml")
            ctx.store.save_findings("scan-1", [same])
            ctx.store.save_scan_run({"id": "scan-1", "started_at": "2026-11-05T10:00:00Z",
                                     "status": "done", "progress": "updated"})
            persist(ctx, observation(rule_id="unrelated"), "other-partial", "2026-11-05T11:00:00Z", trigger="verify")
            assert time.monotonic() - started < 2
            assert not pending.done()
        pending.result(timeout=5)
    assert ctx.store.load_findings("scan-1")[0].collection_provenance == {"partial": True}
    assert service.summary(finding)["history_count"] == 0
    assert ctx.store.list_json(ctx.store.root / "finding_reviews") == []
    assert not list(ctx.audit.records())


@pytest.mark.parametrize("with_rows", [False, True])
def test_no_review_full_scan_completion_locks_removal_but_progress_does_not(env, with_rows):
    ctx, service, finding = env
    run = {"id": "new-full", "started_at": "2026-11-05T11:00:00Z", "status": "running"}
    rows = [observation(rule_id="other-rule")] if with_rows else []
    with service.remediation_guard(finding):
        # Pending metadata and incremental findings cannot turn omissions into final removals.
        ctx.store.save_scan_run(run)
        ctx.store.save_findings("new-full", rows)
        ctx.store.save_scan_run(dict(run, progress="scanning"))
        with pytest.raises(ReviewConflict, match="lifecycle is busy"):
            ctx.store.save_scan_run(dict(run, status="done"))
        assert ctx.store.load_scan_run("new-full")["status"] == "running"
    ctx.store.save_scan_run(dict(run, status="done"))
    assert all(f.id != finding.id for f in ctx.store.current_findings())
    assert not list(ctx.audit.records())


def test_no_review_findings_first_run_publication_locks_baseline_changes(env):
    ctx, service, finding = env
    changed = replace(finding, collection_provenance={"partial": True})
    run = {"id": "imported", "started_at": "2026-11-05T11:00:00Z", "status": "done", "trigger": "verify"}
    with service.remediation_guard(finding):
        ctx.store.save_findings("imported", [changed])  # not published until its run appears
        with pytest.raises(ReviewConflict, match="lifecycle is busy"):
            ctx.store.save_scan_run(run)
        assert ctx.store.load_scan_run("imported") is None
        assert ctx.store.current_findings()[0].collection_provenance == finding.collection_provenance
    ctx.store.save_scan_run(run)
    assert ctx.store.current_findings()[0].collection_provenance == {"partial": True}


def test_no_review_metadata_reordering_locks_changed_current_observation(env):
    ctx, service, finding = env
    changed = replace(finding, collection_provenance={"partial": True})
    persist(ctx, changed, "older-partial", "2026-11-05T09:00:00Z", trigger="verify")
    assert ctx.store.current_findings()[0].collection_provenance == finding.collection_provenance
    with service.remediation_guard(finding):
        with pytest.raises(ReviewConflict, match="lifecycle is busy"):
            ctx.store.save_scan_run({"id": "older-partial", "started_at": "2026-11-05T11:00:00Z",
                                     "status": "done", "trigger": "verify"})
    assert ctx.store.load_scan_run("older-partial")["started_at"] == "2026-11-05T09:00:00Z"
