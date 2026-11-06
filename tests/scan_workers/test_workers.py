"""Deterministic fixture-only scheduler and publication proofs, on both state backends."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import socket
import threading
import time

import pytest

from cyberthunder.adapters.base import AssetFacts, Collected
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import current_operation, current_principal, principal_scope
from cyberthunder.findings.schema import Finding, Status
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.security.resources import capture
from cyberthunder.transport.base import CommandResult, Transport
from tests.security.test_account_transports import bound_context


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("scan worker tests must not contact a network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)


class FixtureTransport(Transport):
    kind = "fixture"

    def __init__(self, adapter, tid):
        self.adapter, self.tid, self.closed = adapter, tid, False
        self.owner = threading.get_ident()
        with adapter.lock:
            adapter.active += 1
            adapter.peak = max(adapter.peak, adapter.active)
            adapter.opened.append(self)

    def run(self, command, **kwargs):
        assert threading.get_ident() == self.owner and not self.closed
        self.adapter.calls.append((self.tid, command))
        return CommandResult(command, 0, "fixture")

    def read_file(self, path):
        raise AssertionError("fixture performs no filesystem or network reads")

    def write_file(self, *args, **kwargs):
        raise AssertionError("scan cannot write a target")

    def close(self):
        assert threading.get_ident() == self.owner
        if not self.closed:
            self.closed = True
            with self.adapter.lock:
                self.adapter.active -= 1


class FixtureAdapter:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.opened, self.calls, self.contexts = [], [], []
        self.hook = lambda target, transport: None
        self.detect_hook = lambda target, collected: None

    def discover(self, target, transport):
        self.contexts.append((current_principal(), current_operation()))
        transport.run("discover")
        return AssetFacts(hostname=target.id)

    def collect(self, target, transport, workdir, **kwargs):
        self.hook(target, transport)
        transport.run("collect")
        artifact = workdir / "fixture.txt"
        artifact.write_text(target.id)
        return Collected(target.id, target.asset_type, str(workdir),
                         artifacts={"fixture": str(artifact)}, modules=list(kwargs["modules"]))

    def run_detection(self, target, collected):
        self.detect_hook(target, collected)
        assert Path(collected.artifacts["fixture"]).read_text() == target.id
        return [Finding(host=target.id, source="fixture", rule_id="FIXTURE-1", title="Fixture finding",
                        severity="high", status="open", raw_ref=collected.artifacts["fixture"],
                        collected_at="2026-11-06T00:00:00Z")]


@pytest.fixture
def environment(state_dir, monkeypatch):
    ctx = AppContext(Settings(state_dir=state_dir, llm_backend="template", auto_propose=False,
                              explain_precompute=False, scan_max_workers=3))
    adapter = FixtureAdapter()
    for n in range(6):
        ctx.inventory.add(Target(f"host-{n:03}", f"Fixture {n}", "linux", "simulated", simulated=True))
    ctx.inventory.save()
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)
    monkeypatch.setattr(ctx, "transport_for", lambda target: FixtureTransport(adapter, target.id))
    yield ctx, adapter
    assert ctx.close(5)
    assert not ctx.scanner.threads
    assert not ctx.scanner._collection_transports
    assert adapter.active == 0 and all(t.closed for t in adapter.opened)
    assert ctx.audit.verify().ok


def assert_unpublished(ctx, run, tids):
    for tid in tids:
        result = run.results[tid]
        assert result.facts is None and result.findings == 0 and result.open == 0
        assert not (ctx.store.scan_dir(run.id) / "raw" / tid / "collected.json").exists()
        assert not [f for f in ctx.store.load_findings(run.id) if f.host == tid]
        assert ctx.inventory.get(tid).last_scan is None
    assert not list(ctx.store.scan_dir(run.id).glob(".collect-*"))


@pytest.mark.parametrize("workers,budget", [(0, 0), (33, 0), (True, 0), (1, -1), (1, float("inf")),
                                          (1, float("nan")), (1, True)])
def test_settings_reject_unbounded_or_invalid_values(workers, budget):
    with pytest.raises(ValueError):
        Settings(scan_max_workers=workers, scan_host_budget_s=budget)
    with pytest.raises(ValueError):
        Settings.from_env(scan_max_workers=workers, scan_host_budget_s=budget)


def test_default_and_environment_settings(monkeypatch):
    monkeypatch.delenv("CT_SCAN_MAX_WORKERS", raising=False)
    monkeypatch.delenv("CT_SCAN_HOST_BUDGET_SECONDS", raising=False)
    assert Settings().scan_max_workers == 1 and Settings().scan_host_budget_s == 0
    monkeypatch.setenv("CT_SCAN_MAX_WORKERS", "4")
    monkeypatch.setenv("CT_SCAN_HOST_BUDGET_SECONDS", "0.25")
    assert Settings().scan_max_workers == 4 and Settings().scan_host_budget_s == 0.25


def test_scheduler_joins_owned_workers_when_consumer_aborts():
    from types import SimpleNamespace
    from cyberthunder.scan_workers import _ordered_workers
    scanner = SimpleNamespace(_lock=threading.Lock(), threads=[])
    finished = []

    def collect(item):
        if item == 1:
            time.sleep(0.02)
        assert not threading.current_thread().daemon
        finished.append(item)
        return item

    results = _ordered_workers(scanner, [0, 1, 2], 2, collect)
    try:
        assert next(results) == 0
    finally:
        results.close()
    assert set(finished) == {0, 1} and not scanner.threads


def test_bounded_collection_order_and_single_findings_publication(environment, monkeypatch):
    ctx, adapter = environment
    barrier = threading.Barrier(3)
    adapter.hook = lambda target, transport: barrier.wait(5)
    saved = []
    original = ctx.store.save_findings

    def save(*args, **kwargs):
        assert adapter.active == 0
        saved.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(ctx.store, "save_findings", save)
    run = ctx.scanner.start(background=False)
    assert run.status == "done" and adapter.peak == 3
    assert saved == [run.id]
    assert [f.host for f in ctx.store.load_findings(run.id)] == run.targets
    assert list(ctx.store.load_scan_run(run.id)["results"]) == run.targets
    assert run.progress == {"done": 6, "total": 6}
    for finding in ctx.store.load_findings(run.id):
        assert Path(finding.raw_ref).read_text() == finding.host
        assert finding.authorization_scope["target_id"] == finding.host
    assert all(operation == "scan" for _, operation in adapter.contexts)
    assert len({t.owner for t in adapter.opened[:3]}) == 3


def test_timeout_drains_and_has_no_normalized_or_followup_side_effects(environment, monkeypatch):
    ctx, adapter = environment
    ctx.settings.scan_host_budget_s = 0.01
    adapter.hook = lambda target, transport: time.sleep(0.03)
    after = []
    monkeypatch.setattr(ctx.scanner, "_after_scan", lambda *args: after.append(True))
    run = ctx.scanner.start(background=False)
    assert run.status == "error" and run.coverage_incomplete
    assert set(r.status for r in run.results.values()) == {"timed_out"}
    assert not after and not ctx.gate.list()
    assert not [command for _, command in adapter.calls if command == "collect"]
    assert_unpublished(ctx, run, run.targets)
    assert run.scheduling["outcomes"]["timed_out"] == 6


def test_budget_does_not_abandon_a_blocked_transport_call(environment, monkeypatch):
    ctx, adapter = environment
    ctx.settings.scan_host_budget_s = 0.5
    entered, release = threading.Event(), threading.Event()

    class BlockedTransport(FixtureTransport):
        def run(self, command, **kwargs):
            if command == "collect":
                entered.set()
                assert release.wait(5)
            return super().run(command, **kwargs)

    monkeypatch.setattr(ctx, "transport_for", lambda target: BlockedTransport(adapter, target.id))
    run = ctx.scanner.start(["host-000"])
    try:
        assert entered.wait(5)
        time.sleep(0.55)
        assert ctx.scanner.is_running(run.id) and not ctx.close(0.01)
        assert adapter.active == 1
        assert ctx.store.load_scan_run(run.id)["status"] == "running"
    finally:
        release.set()
    run = ctx.scanner.join(run.id, 10)
    assert run.status == "error" and run.results["host-000"].status == "timed_out"
    assert_unpublished(ctx, run, run.targets)


def test_collection_errors_cannot_publish_a_pass(environment, monkeypatch):
    ctx, adapter = environment
    original = adapter.collect

    def partial(*args, **kwargs):
        collected = original(*args, **kwargs)
        collected.errors.append("required fixture evidence unavailable")
        return collected

    def pass_finding(target, collected):
        return [Finding(host=target.id, source="fixture", rule_id="UNAVAILABLE", title="Unavailable",
                        severity="high", status=Status.NOT_A_FINDING)]

    monkeypatch.setattr(adapter, "collect", partial)
    monkeypatch.setattr(adapter, "run_detection", pass_finding)
    run = ctx.scanner.start(background=False)
    assert run.status == "partial" and all(r.status == "partial" for r in run.results.values())
    assert {f.status for f in ctx.store.load_findings(run.id)} == {Status.NOT_REVIEWED}
    assert all(ctx.inventory.get(tid).last_scan is None for tid in run.targets)


@pytest.mark.parametrize("change", ["missing_inventory", "source_identity"])
def test_fresh_source_identity_required_before_opening_a_transport(environment, monkeypatch, change):
    ctx, adapter = environment
    original = ctx.scanner._execute

    def change_then_execute(run, **kwargs):
        if change == "missing_inventory":
            ctx.inventory.path.unlink()
        else:
            ctx.inventory.update(run.targets[0], authorization_id="changed-source")
            ctx.inventory.save()
        return original(run, **kwargs)

    monkeypatch.setattr(ctx.scanner, "_execute", change_then_execute)
    run = ctx.scanner.start(["host-000"], background=False)
    assert run.status == "error" and not adapter.opened
    assert_unpublished(ctx, run, run.targets)


@pytest.mark.parametrize("stop", ["kill", "cancel"])
def test_stop_during_collection_discards_late_work_and_stops_queued_targets(environment, stop):
    ctx, adapter = environment
    entered, release = threading.Event(), threading.Event()

    def hold(target, transport):
        entered.set()
        assert release.wait(5)

    adapter.hook = hold
    run = ctx.scanner.start()
    try:
        assert entered.wait(5)
        if stop == "kill":
            ctx.killswitch.engage("operator", "fixture stop")
        else:
            assert ctx.scanner.cancel(run.id)
        assert ctx.scanner.is_running(run.id)
    finally:
        release.set()
    run = ctx.scanner.join(run.id, 10)
    expected = "stopped" if stop == "kill" else "cancelled"
    assert run.status == expected and all(r.status == expected for r in run.results.values())
    assert len(adapter.opened) <= 3
    assert_unpublished(ctx, run, run.targets)


def test_context_shutdown_keeps_database_open_until_workers_and_publisher_finish(environment, monkeypatch):
    ctx, adapter = environment
    entered, release = threading.Event(), threading.Event()
    adapter.hook = lambda target, transport: (entered.set(), release.wait(5))
    closed = []
    original = ctx.store.close
    monkeypatch.setattr(ctx.store, "close", lambda: (closed.append(True), original()))
    run = ctx.scanner.start()
    try:
        assert entered.wait(5)
        assert not ctx.close(0.01) and not closed
        assert ctx.store.load_scan_run(run.id)["status"] == "running"
    finally:
        release.set()
    assert ctx.close(10) and closed == [True]
    assert ctx.scanner.get(run.id).status == "done"


def test_failed_host_preserves_prior_observations_and_report_incompleteness(environment, monkeypatch):
    from cyberthunder.report.onepager import resolve_scan
    from cyberthunder.report.assurance import build_assurance
    ctx, adapter = environment
    prior = ctx.scanner.start(background=False)
    prior_findings = {f.host: f.id for f in ctx.store.load_findings(prior.id)}

    def fail_one(target, transport):
        if target.id == "host-001":
            raise RuntimeError("fixture unavailable")

    adapter.hook = fail_one
    after = []
    monkeypatch.setattr(ctx.scanner, "_after_scan", lambda *args: after.append(True))
    run = ctx.scanner.start(background=False)
    assert run.status == "partial" and not after
    assert run.results["host-001"].status == "error"
    assert {f.host: f.id for f in ctx.store.current_findings()} == prior_findings
    _, reported_run, findings = resolve_scan(ctx, run.id)
    assert reported_run["status"] == "partial" and reported_run["coverage_incomplete"] is True
    report = build_assurance(ctx, findings)
    assert report["counts"]["scanner_pass"] == 0 and report["counts"]["total"] == 5
    assert build_assurance(ctx, ctx.store.load_findings())["counts"]["total"] == 6


@pytest.mark.parametrize("change", ["unchanged", "grant", "session", "identity", "scope", "reuse", "binding", "auth_mode"])
def test_worker_identity_authority_and_publication_rechecks(bound_context, monkeypatch, change):
    ctx, target, person, path, policy, _ = bound_context
    ctx.settings.scan_max_workers = 2
    adapter = FixtureAdapter()
    revoked = threading.Event()

    def validity():
        if revoked.is_set():
            raise PermissionError("fixture session revoked")

    def detect(target, collected):
        if change == "grant":
            policy["entries"][0]["grants"] = []
            path.write_text(json.dumps(policy))
        elif change == "session":
            revoked.set()
        elif change == "scope":
            ctx.inventory.update(target.id, in_scope=False)
            ctx.inventory.save()
        elif change == "reuse":
            ctx.inventory.update(target.id, authorization_id="replacement")
            ctx.inventory.save()
        elif change == "binding":
            policy["entries"][0]["grants"][0]["credential"]["username"] = "replacement"
            path.write_text(json.dumps(policy))
        elif change == "auth_mode":
            ctx.settings.auth_mode = "dev"

    adapter.detect_hook = detect
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)
    selected = []

    def factory(target, *args, **kwargs):
        selected.append(target.username)
        return FixtureTransport(adapter, target.id)

    monkeypatch.setattr("cyberthunder.context.make_transport", factory)
    if change == "identity":
        def use_other(target, transport):
            from dataclasses import replace
            with principal_scope(replace(person, subject="other")):
                transport.run("forbidden")
        adapter.hook = use_other
    with principal_scope(person, validity=validity):
        run = ctx.scanner.start([target.id], requested_by=person.actor)
    run = ctx.scanner.join(run.id, 10)
    assert all(p == person and operation == "scan" for p, operation in adapter.contexts)
    assert selected == ["alice-reader"] and adapter.active == 0
    if change == "unchanged":
        assert run.status == "done"
    else:
        assert run.status == "error"
        assert_unpublished(ctx, run, [target.id])
    assert ctx.close(5)


def test_simultaneous_accounts_keep_distinct_connections_and_audit_identity(bound_context, monkeypatch):
    from dataclasses import replace
    ctx, target, alice, path, policy, _ = bound_context
    bob = replace(alice, subject="bob", display_name="Bob")
    policy["entries"].append({"issuer": bob.issuer, "subject": bob.subject, "node_actions": [], "grants": [
        {"target_ids": [target.id], "actions": ["scan"], "credential": {
            "username": "bob-reader", "credential_ref": "BOB_ONLY", "sudo": False, "options": {}}}]})
    path.write_text(json.dumps(policy))
    ctx.settings.scan_max_workers = 2
    adapter, accounts = FixtureAdapter(), []
    barrier = threading.Barrier(2)
    adapter.hook = lambda *args: barrier.wait(10)
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)

    def factory(selected, *args, **kwargs):
        accounts.append((current_principal(), selected.username, selected.credential_ref))
        return FixtureTransport(adapter, selected.id)

    monkeypatch.setattr("cyberthunder.context.make_transport", factory)
    with principal_scope(alice):
        first = ctx.scanner.start([target.id], requested_by=alice.actor)
    with principal_scope(bob):
        second = ctx.scanner.start([target.id], requested_by=bob.actor)
    assert ctx.scanner.join(first.id, 15).status == "done"
    assert ctx.scanner.join(second.id, 15).status == "done"
    assert set(accounts) == {(alice, "alice-reader", "READ_ONLY"), (bob, "bob-reader", "BOB_ONLY")}
    assert adapter.peak == 2 and len({id(t) for t in adapter.opened}) == 2
    rows = [row for row in ctx.audit.records() if row["action"] == "scan.target"]
    assert {(row["subject"], row["actor"]) for row in rows} == {(first.id, alice.actor), (second.id, bob.actor)}
    assert ctx.audit.verify().ok and ctx.close(5)


@pytest.mark.parametrize("expired", [False, True])
def test_credential_lease_is_created_and_closed_inside_worker_context(bound_context, monkeypatch, expired):
    from cyberthunder.security.secret_resolver import SecretResolver, MountedSecret
    ctx, target, person, _, _, _ = bound_context
    ctx.settings.scan_max_workers = 2
    adapter, leases = FixtureAdapter(), []
    canary = "disposable-scan-worker-canary"
    secret_dir = ctx.store.root / "worker-fixture-secret"
    secret_dir.mkdir(mode=0o700)
    secret_path = secret_dir / "password"
    secret_path.write_text(canary)
    secret_path.chmod(0o600)
    resolver = SecretResolver({"READ_ONLY": MountedSecret(str(secret_dir), "password")},
                              security_mode="range", auth_mode="oidc")
    monkeypatch.setattr(ctx, "_credential_resolver", lambda: resolver)
    monkeypatch.setattr(ctx, "adapter_for", lambda target: adapter)

    def factory(target, settings, *, credential_use, **kwargs):
        assert current_principal() == person and current_operation() == "scan"
        with credential_use.lease() as lease:
            leases.append(lease)
            if expired:
                lease._deadline = 0  # deterministic lease expiry, no global clock change
            assert lease.secret.reveal() == canary
        return FixtureTransport(adapter, target.id)

    monkeypatch.setattr("cyberthunder.context.make_transport", factory)
    with principal_scope(person):
        run = ctx.scanner.start([target.id], requested_by=person.actor, background=False)
    assert run.status == ("error" if expired else "done")
    assert leases and all(lease._closed and lease._secret is None for lease in leases)
    assert canary not in json.dumps(run.to_dict()) + ctx.audit.path.read_text()
    if expired:
        assert not adapter.opened
        assert_unpublished(ctx, run, run.targets)
    assert ctx.close(5)


@pytest.mark.parametrize("workers", [1, 4])
def test_500_host_simulation(environment, monkeypatch, workers, record_property):
    ctx, adapter = environment
    # Deliberately in-memory fixture inventory: this measures scheduling, not YAML parsing or networking.
    targets = [Target(f"host-{n:03}", f"Fixture {n}", "linux", "simulated", simulated=True) for n in range(500)]
    ctx.inventory = Inventory(targets=targets)
    monkeypatch.setattr(ctx.store, "capture_resources", lambda ids: capture(ctx, ids))
    monkeypatch.setattr(ctx, "save_inventory", lambda *args, **kwargs: None)
    ctx.settings.scan_max_workers = workers
    ctx.settings.scan_host_budget_s = 60  # selects the scheduler for its serial comparison

    def collect(target, transport):
        if target.id == "host-250":
            time.sleep(0.03)
            raise RuntimeError("delayed fixture failure")
        time.sleep(0.001)

    adapter.hook = collect
    start = time.perf_counter()
    run = ctx.scanner.start(background=False)
    elapsed = time.perf_counter() - start
    assert run.status == "partial" and run.findings_count == 499
    assert run.progress == {"done": 500, "total": 500}
    assert 1 <= adapter.peak <= workers
    assert Counter(r.status for r in run.results.values()) == {"done": 499, "error": 1}
    assert [f.host for f in ctx.store.load_findings(run.id)] == [t.id for t in targets if t.id != "host-250"]
    assert run.scheduling["outcomes"]["error"] == 1
    assert not ctx.scanner.threads and not ctx.scanner._collection_transports
    record_property("simulation_seconds", round(elapsed, 3))
    print(f"SIMULATION backend={ctx.store.backend_name} hosts=500 workers={workers} peak={adapter.peak} seconds={elapsed:.3f}")
