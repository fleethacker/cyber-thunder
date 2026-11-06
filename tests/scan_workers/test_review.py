"""Independent negative calibrations for collection ownership and publication."""
from types import SimpleNamespace
import threading

import pytest

from cyberthunder import scan_workers
from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.lifecycle import review_coordination_lock
from cyberthunder.findings.schema import Status
from tests.scan_workers.test_workers import (
    FixtureAdapter, FixtureTransport, assert_unpublished, environment, offline,
)
from tests.security.test_account_transports import bound_context


def test_inventory_failure_clears_success_fields_and_normalized_file(environment, monkeypatch):
    ctx, _ = environment

    def fail_update(*args, **kwargs):
        raise OSError("fixture freshness write failed")

    monkeypatch.setattr(ctx.inventory, "update", fail_update)
    run = ctx.scanner.start(["host-000"], background=False)
    assert run.status == "error" and run.results["host-000"].status == "error"
    assert_unpublished(ctx, run, run.targets)


@pytest.mark.parametrize("boundary", ["findings_lock", "terminal_run_lock", "target_audit"])
@pytest.mark.parametrize("workers", [1, 2], ids=["serial", "workers"])
def test_revocation_at_publication_discards_success(bound_context, monkeypatch, boundary, workers):
    ctx, target, person, _, _, _ = bound_context
    ctx.settings.scan_max_workers = workers
    adapter = FixtureAdapter()
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)
    monkeypatch.setattr("cyberthunder.context.make_transport",
                        lambda target, *args, **kwargs: FixtureTransport(adapter, target.id))
    revoked = threading.Event()
    reached = []

    def valid():
        if revoked.is_set():
            raise PermissionError("fixture session revoked at publication")

    # Exercise the real lock/retry path: contend exactly when the selected
    # publication begins, revoke while it waits, then release the lock.
    import cyberthunder.findings.review as review
    original = review._publish_observation_once
    threads = []

    def publish(store, scan_id, document, *, kind):
        selected = ((boundary == "findings_lock" and kind == "findings") or
                    (boundary == "terminal_run_lock" and kind == "run" and document["status"] == "done"))
        if selected and not reached:
            reached.append(True)
            ready, release = threading.Event(), threading.Event()

            def holder():
                with review_coordination_lock(ctx.store.root):
                    ready.set()
                    assert release.wait(5)

            thread = threading.Thread(target=holder)
            thread.start()
            threads.append(thread)
            assert ready.wait(5)
            try:
                with pytest.raises(review.ReviewConflict):
                    original(store, scan_id, document, kind=kind)
                revoked.set()
            finally:
                release.set()
                thread.join(5)
        return original(store, scan_id, document, kind=kind)

    monkeypatch.setattr(review, "_publish_observation_once", publish)
    audit = ctx.audit.append

    def append(action, *args, **kwargs):
        result = audit(action, *args, **kwargs)
        if action == "scan.target" and boundary == "target_audit":
            reached.append(True)
            revoked.set()
        return result

    monkeypatch.setattr(ctx.audit, "append", append)
    try:
        with principal_scope(person, validity=valid):
            run = ctx.scanner.start([target.id], requested_by=person.actor, background=False)
        assert reached and all(not thread.is_alive() for thread in threads)
        assert run.status == "error"
        assert_unpublished(ctx, run, run.targets)
        assert ctx.store.load_scan_run(run.id)["results"][target.id]["facts"] is None
    finally:
        assert ctx.close(5)


@pytest.mark.parametrize("mode", ["before_start", "after_start"])
def test_worker_start_failure_drains_every_started_child(monkeypatch, mode):
    scanner = SimpleNamespace(_lock=threading.Lock(), threads=[])
    original = threading.Thread.start
    join = threading.Thread.join
    entered, release = threading.Event(), threading.Event()
    children, finished, joined = [], [], []

    def collect(item):
        entered.set()
        assert release.wait(5)
        finished.append(item)
        return item

    def start(thread):
        children.append(thread)
        if len(children) == 2:
            if mode == "after_start":
                original(thread)
            release.set()
            raise RuntimeError("fixture thread start failed")
        original(thread)
        assert entered.wait(5)

    monkeypatch.setattr(threading.Thread, "start", start)

    def track_join(thread, *args, **kwargs):
        joined.append(thread)
        return join(thread, *args, **kwargs)

    monkeypatch.setattr(threading.Thread, "join", track_join)
    try:
        with pytest.raises(RuntimeError, match="fixture thread start failed"):
            list(scan_workers._ordered_workers(scanner, [0, 1, 2], 2, collect))
        assert all(not thread.is_alive() for thread in children)
        assert set(joined) == {thread for thread in children if thread.ident is not None}
        assert not scanner.threads
        assert set(finished) == ({0} if mode == "before_start" else {0, 1})
    finally:
        release.set()
        for thread in children:
            if thread.ident is not None:
                thread.join(5)


def test_background_start_failure_is_terminal_and_releases_registry(environment, monkeypatch):
    ctx, _ = environment

    def fail(thread):
        raise RuntimeError("fixture coordinator start failed")

    monkeypatch.setattr(threading.Thread, "start", fail)
    with pytest.raises(RuntimeError, match="fixture coordinator start failed"):
        ctx.scanner.start(["host-000"])
    run = ctx.scanner.latest()
    assert run.status == "error" and run.finished_at
    assert not ctx.scanner._threads and not ctx.scanner._active
    assert not ctx.scanner._cancellations
    assert_unpublished(ctx, run, run.targets)


def test_duplicate_active_transport_does_not_close_or_rewrap_its_owner(environment, monkeypatch):
    ctx, adapter = environment
    ready, duplicate = threading.Event(), threading.Event()
    shared = []
    close_calls = []

    class Connection(FixtureTransport):
        def close(self):
            close_calls.append(threading.get_ident())
            super().close()

    def factory(target):
        if target.id == "host-000":
            transport = Connection(adapter, target.id)
            shared.append(transport)
            return transport
        assert ready.wait(5)
        duplicate.set()
        return shared[0]

    # The duplicate fails before entering protect_transport; the owner can
    # still call its original guarded transport after that failure.
    original = scan_workers.HostWork.fail
    rejected = threading.Event()

    def fail(work, exc):
        original(work, exc)
        if work.tid == "host-001":
            rejected.set()

    def hold(target, transport):
        ready.set()
        assert duplicate.wait(5) and rejected.wait(5)
        assert not transport.closed

    adapter.hook = hold
    monkeypatch.setattr(ctx, "transport_for", factory)
    monkeypatch.setattr(scan_workers.HostWork, "fail", fail)
    run = ctx.scanner.start(["host-000", "host-001"], background=False)
    assert run.status == "partial" and run.results["host-000"].status == "done"
    assert run.results["host-001"].status == "error"
    assert close_calls == [shared[0].owner]
    assert_unpublished(ctx, run, ["host-001"])


def test_cancellation_is_closed_before_first_target_publication(environment, monkeypatch):
    ctx, _ = environment
    responses = []
    audit = ctx.audit.append

    def append(action, *args, **kwargs):
        if action == "scan.target":
            responses.append(ctx.scanner.cancel(kwargs["subject"]))
        return audit(action, *args, **kwargs)

    monkeypatch.setattr(ctx.audit, "append", append)
    run = ctx.scanner.start(["host-000"], background=False)
    assert run.status == "done" and responses == [False]


def test_partial_pass_does_not_replace_prior_unresolved_evidence(environment, monkeypatch):
    ctx, adapter = environment
    prior = ctx.scanner.start(["host-000"], background=False)
    prior.started_at = "2026-01-01T00:00:00Z"
    ctx.scanner._save(prior)
    before = ctx.store.load_findings(prior.id)[0].to_dict()
    collect, detect = adapter.collect, adapter.run_detection

    def partial(*args, **kwargs):
        result = collect(*args, **kwargs)
        result.errors.append("fixture required evidence is unavailable")
        return result

    def pass_result(*args, **kwargs):
        result = detect(*args, **kwargs)
        result[0].status = Status.NOT_A_FINDING
        return result

    monkeypatch.setattr(adapter, "collect", partial)
    monkeypatch.setattr(adapter, "run_detection", pass_result)
    run = ctx.scanner.start(["host-000"], background=False)
    assert run.status == "partial"
    assert ctx.store.current_findings()[0].to_dict() == before
    assert ctx.store.load_findings(run.id) == []


@pytest.mark.parametrize("phase", ["collect", "detect"])
def test_base_exception_drains_and_marks_unconsumed_hosts(environment, monkeypatch, phase):
    ctx, adapter = environment

    class FixtureAbort(BaseException):
        pass

    def abort(*args):
        raise FixtureAbort("fixture nonstandard abort")

    if phase == "collect":
        adapter.hook = abort
    else:
        adapter.detect_hook = abort
    with pytest.raises(FixtureAbort):
        ctx.scanner.start(background=False)
    run = ctx.scanner.latest()
    assert run.status == "error" and run.progress == {"done": 6, "total": 6}
    assert_unpublished(ctx, run, run.targets)


def test_shutdown_sees_coordinator_during_thread_start(environment, monkeypatch):
    ctx, _ = environment
    start = threading.Thread.start
    closed = []
    close = ctx.store.close
    monkeypatch.setattr(ctx.store, "close", lambda: (closed.append(True), close()))
    checked = []

    def starting(thread):
        if thread.name.startswith("scan-") and not thread.name.startswith("scan-collect-"):
            assert not thread.is_alive()
            checked.append(ctx.close(0.01))
            assert not closed
        start(thread)

    monkeypatch.setattr(threading.Thread, "start", starting)
    run = ctx.scanner.start(["host-000"])
    assert ctx.scanner.join(run.id, 10).status == "done"
    assert checked == [False]


@pytest.mark.parametrize("kind", ["findings", "run"])
def test_failed_publication_withdraws_only_new_observations(environment, monkeypatch, kind):
    ctx, _ = environment
    baseline = ctx.scanner.start(["host-000"], background=False)
    baseline.started_at = "2026-01-01T00:00:00Z"
    ctx.scanner._save(baseline)
    previous = [finding.to_dict() for finding in ctx.store.current_findings()]
    last_scan = ctx.inventory.get("host-000").last_scan
    import cyberthunder.findings.review as review
    publish = review._publish_observation_once
    failures = []

    def once(store, scan_id, document, *, kind):
        if kind == wanted and (kind == "findings" or document["status"] == "done") and not failures:
            failures.append(True)
            raise OSError("fixture publication write failure")
        return publish(store, scan_id, document, kind=kind)

    wanted = kind
    monkeypatch.setattr(review, "_publish_observation_once", once)
    run = ctx.scanner.start(["host-000"], background=False)
    assert failures and run.status == "error"
    assert ctx.store.load_findings(run.id) == []
    assert [finding.to_dict() for finding in ctx.store.current_findings()] == previous
    result = run.results["host-000"]
    assert result.facts is None and result.findings == 0 and result.open == 0
    assert ctx.inventory.get("host-000").last_scan == last_scan
    assert not list((ctx.store.scan_dir(run.id) / "raw").iterdir())


def test_sqlite_writer_admission_rechecks_authority(environment, monkeypatch):
    ctx, _ = environment
    if ctx.store.backend_name != "sqlite":
        pytest.skip("SQLite writer admission is specific to the SQLite backend")
    from contextlib import contextmanager
    lock = ctx.store.lock
    acquired = []

    @contextmanager
    def revoke_at_writer(name):
        with lock(name):
            if name == "scan-publication" and not acquired:
                acquired.append(True)
                ctx.killswitch.engage("operator", "fixture kill at writer admission")
            yield

    monkeypatch.setattr(ctx.store, "lock", revoke_at_writer)
    run = ctx.scanner.start(["host-000"], background=False)
    assert acquired and run.status == "stopped"
    assert_unpublished(ctx, run, run.targets)


def test_credential_registry_change_after_close_blocks_publication(bound_context, monkeypatch):
    from cyberthunder.security.secret_resolver import MountedSecret, SecretResolver
    ctx, target, person, _, _, _ = bound_context
    ctx.settings.scan_max_workers = 2
    adapter = FixtureAdapter()
    sources = [SecretResolver({"READ_ONLY": MountedSecret(str(ctx.store.root), name)},
                             security_mode="range", auth_mode="oidc")
               for name in ("first-fixture-secret", "replacement-fixture-secret")]
    current = [sources[0]]
    monkeypatch.setattr(ctx, "_credential_resolver", lambda: current[0])
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)
    monkeypatch.setattr("cyberthunder.context.make_transport",
                        lambda target, *args, **kwargs: FixtureTransport(adapter, target.id))

    def change(target, collected):
        assert adapter.active == 0  # every transport guard has already drained
        current[0] = sources[1]

    adapter.detect_hook = change
    try:
        with principal_scope(person):
            run = ctx.scanner.start([target.id], requested_by=person.actor, background=False)
        assert run.status == "error"
        assert_unpublished(ctx, run, run.targets)
    finally:
        assert ctx.close(5)
