"""Independent regressions for passive import bounds and publication authority."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import errno
import os
import sqlite3
import threading
from unittest.mock import Mock

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.lifecycle import finding_lifecycle_lock
from cyberthunder.ingest import scap_results as scap
from tests.ingest.test_scap_results import auth, load, manifest, prepared, xml
from tests.security.job_helpers import revoke


@pytest.mark.parametrize("error", [
    PermissionError(errno.EACCES, "denied", "PRIVATE_STORAGE_PATH"),
    sqlite3.OperationalError("PRIVATE_STORAGE_PATH"),
])
def test_storage_failures_have_fixed_diagnostics(prepared, monkeypatch, error):
    monkeypatch.setattr(prepared.store, "save_scan_run", Mock(side_effect=error))
    with pytest.raises(OSError, match="^SCAP import storage is unavailable$"):
        load(prepared)
    assert not prepared.store.list_scan_runs()


@pytest.mark.parametrize("change", ["revoke", "kill", "session"])
def test_authority_is_rechecked_after_publication_lock_wait(prepared, monkeypatch, change):
    first = load(prepared)
    fid = next(f.id for f in prepared.store.current_findings() if f.rule_id == "r0")
    p = auth(prepared)
    from cyberthunder.findings import review
    entered = threading.Event()
    attempt = review._publish_observation_once
    def observe(*args, **kw):
        if kw["kind"] == "run":
            entered.set()
        return attempt(*args, **kw)
    monkeypatch.setattr(review, "_publish_observation_once", observe)
    revoked = threading.Event()
    def validity():
        if revoked.is_set():
            raise PermissionError("session revoked")
    def publish():
        with principal_scope(p, validity=validity):
            return load(prepared, actor=p.actor, data=xml(["fail"]), declaration=manifest(1))
    from cyberthunder.control.killswitch import KillSwitchEngaged
    with ThreadPoolExecutor(max_workers=1) as pool:
        with finding_lifecycle_lock(prepared.store.root, fid):
            pending = pool.submit(publish)
            assert entered.wait(5)
            if change == "revoke":
                revoke(prepared)
            elif change == "kill":
                (prepared.store.root / "KILL").write_text("stop")
            else:
                revoked.set()
        with pytest.raises((PermissionError, KillSwitchEngaged)):
            pending.result(timeout=10)
    assert [r["id"] for r in prepared.store.list_scan_runs()] == [first["scan_id"]]
    assert next(f for f in prepared.store.current_findings() if f.rule_id == "r0").status.value == "not_a_finding"


def test_regular_file_reader_rejects_devices():
    with pytest.raises(ValueError, match="regular file"):
        scap.read_local_file(os.devnull, 1024)


@pytest.mark.skipif(os.name != "posix", reason="requires native POSIX FIFO")
def test_fifo_is_rejected_before_open(tmp_path, monkeypatch):
    path = tmp_path / "input.fifo"
    os.mkfifo(path)
    from pathlib import Path
    monkeypatch.setattr(Path, "open", Mock(side_effect=AssertionError("FIFO must not be opened")))
    monkeypatch.setattr(os, "open", Mock(side_effect=AssertionError("FIFO must not be opened")))
    with pytest.raises(ValueError, match="regular file"):
        scap.read_local_file(path, 1024)


@pytest.mark.parametrize("start,end", [
    ("2026-11-05T13:00:00Z", "2026-11-05T12:00:00Z"),
    ("2026-11-05T12:00:00", "2026-11-05T12:00:00Z"),
])
def test_inconsistent_evaluation_times_cannot_claim_completion(start, end):
    data = xml(["pass"]).replace(b'end-time="2026-11-05T12:00:00Z"',
        f'start-time="{start}" end-time="{end}"'.encode())
    with pytest.raises(scap.ScapImportError, match="timestamp"):
        scap.parse_results(data, manifest(1))


@pytest.mark.parametrize("roles,actions,node,allowed", [
    (("analyst",), ["read", "import"], ["import"], True),
    (("admin",), ["read", "import"], ["import"], False),
    (("viewer",), ["read", "import"], ["import"], False),
    (("analyst",), ["import"], ["import"], False),
    (("analyst",), ["read"], ["import"], False),
    (("analyst",), ["read", "import"], [], False),
])
@pytest.mark.parametrize("kind", ["human", "workload"])
def test_minimal_current_permissions(prepared, roles, actions, node, allowed, kind):
    from tests.security.job_helpers import enable_auth
    p = replace(enable_auth(prepared, node=node,
        grants=[{"actions": actions, "target_ids": ["container-a"]}]), roles=roles, kind=kind)
    with principal_scope(p):
        if allowed:
            assert not load(prepared, actor=p.actor)["repeated"]
            assert load(prepared, actor=p.actor)["repeated"]
        else:
            with pytest.raises(PermissionError):
                load(prepared, actor=p.actor)
            assert not prepared.store.list_scan_runs()


def test_source_order_canonicalization_preserves_receipt_and_history(prepared):
    first = load(prepared)
    declaration = manifest()
    declaration["expected_rule_ids"].reverse()
    declaration = dict(reversed(list(declaration.items())))
    assert load(prepared, declaration=declaration) == {**first, "repeated": True}
    assert len(prepared.store.list_scan_runs()) == 1


def test_unselected_outside_expected_scope_has_bounded_comparisons():
    class RuleID(str):
        comparisons = 0
        __hash__ = str.__hash__
        def __eq__(self, other):
            type(self).comparisons += 1
            return super().__eq__(other)
    n = 300
    declaration = manifest(n)
    declaration["expected_rule_ids"] = [RuleID(f"r{i}") for i in range(n, 2 * n)]
    rows, coverage = scap.parse_results(xml(["notselected"] * n + ["pass"] * n), declaration)
    assert coverage["result_scope_complete"] and len(rows) == 2 * n
    # Instrument identifier equality instead of asserting a machine-dependent duration.
    assert RuleID.comparisons < 10 * len(rows)


def test_post_commit_audit_failure_is_an_idempotent_retry(prepared, monkeypatch):
    append = prepared.audit.append
    def fail_completion(action, *args, **kwargs):
        if action == "ingest.scap":
            raise OSError("PRIVATE_STORAGE_PATH")
        return append(action, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(prepared.audit, "append", fail_completion)
        with pytest.raises(OSError, match="storage is unavailable"):
            load(prepared)
    original = prepared.store.list_scan_runs()
    assert len(original) == 1 and prepared.store.current_findings()
    assert any(r["action"] == "ingest.scap.publish" for r in prepared.audit.records())
    assert load(prepared)["repeated"]
    assert prepared.store.list_scan_runs() == original


def test_unconsumed_xml_details_are_not_persisted(prepared):
    data = xml().replace(b"</TestResult>", b'<target-facts><fact name="private">'
        b'UNCONSUMED_SECRET_MARKER</fact></target-facts></TestResult>')
    receipt = load(prepared, data=data)
    import json
    recorded = json.dumps(prepared.store.read_json(
        prepared.store.scans_dir / receipt["scan_id"] / "findings.json"))
    assert "UNCONSUMED_SECRET_MARKER" not in recorded
    assert "UNCONSUMED_SECRET_MARKER" not in prepared.audit.path.read_text()
    assert not list((prepared.store.scans_dir / receipt["scan_id"] / "raw").iterdir())


def test_revised_import_invalidates_review_without_rewriting_history(prepared):
    from cyberthunder.findings.review import ReviewService
    from tests.findings.test_reviews import decision
    first = load(prepared)
    finding = next(f for f in prepared.store.current_findings() if f.rule_id == "r0")
    reviews = ReviewService(prepared)
    decision(reviews, finding)
    assert reviews.summary(finding)["disposition"] == "false_positive"
    revised = load(prepared, data=xml(["fail"]), declaration=manifest(1))
    current = next(f for f in prepared.store.current_findings() if f.id == finding.id)
    assert current.scan_id == revised["scan_id"]
    assert reviews.summary(current)["disposition"] == "unreviewed"
    assert next(f for f in prepared.store.load_findings(first["scan_id"]) if f.id == finding.id).status.value == "not_a_finding"
    assert prepared.audit.verify().ok


def test_database_writer_wait_rechecks_authority(prepared, monkeypatch):
    if prepared.store.backend_name != "sqlite":
        pytest.skip("SQLite writer contention only")
    from contextlib import contextmanager
    from cyberthunder.state.sqlite import SqliteBackend
    p = auth(prepared)
    trying = threading.Event()
    lock = prepared.store.lock
    @contextmanager
    def observed_lock(name):
        if name == "scap-publication":
            trying.set()
        with lock(name):
            yield
    monkeypatch.setattr(prepared.store, "lock", observed_lock)
    def publish():
        with principal_scope(p):
            return load(prepared, actor=p.actor)
    writer = SqliteBackend(prepared.store.root)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with writer.lock("independent-writer"):
                pending = pool.submit(publish)
                assert trying.wait(5)
                assert not pending.done()
                revoke(prepared)
            with pytest.raises(PermissionError):
                pending.result(timeout=10)
    finally:
        writer.close()
    assert not prepared.store.list_scan_runs()


@pytest.mark.skipif(os.name != "posix", reason="requires native POSIX FIFO replacement")
def test_file_replacement_cannot_turn_a_regular_file_into_a_blocking_pipe(tmp_path, monkeypatch):
    path = tmp_path / "input.xml"
    path.write_bytes(b"regular")
    opened = os.open
    def replace_before_open(name, flags):
        path.unlink()
        os.mkfifo(path)
        return opened(name, flags)
    monkeypatch.setattr(os, "open", replace_before_open)
    with pytest.raises(scap.ScapImportError, match="regular file"):
        scap.read_local_file(path, 1024)
