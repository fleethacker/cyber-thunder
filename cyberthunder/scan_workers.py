"""Opt-in, bounded host collection. Blocking calls are drained, never abandoned."""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from contextvars import copy_context
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import authorize, current_principal
from cyberthunder.findings.schema import Status, utcnow
from cyberthunder.inventory.host import persisted_target
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.security.resources import check_record, target_scope
from cyberthunder.security.transport_guard import protect_transport


class CollectionBudgetExpired(TimeoutError):
    pass


class CollectionCancelled(Exception):
    pass


@contextmanager
def tracked_thread(scanner, thread):
    with scanner._lock:
        scanner.threads.append(thread)
    try:
        yield
    finally:
        with scanner._lock:
            scanner.threads.remove(thread)


def _ordered_workers(scanner, items, limit, collect):
    """At most limit outstanding hosts, including completed but unconsumed results.

    Each host gets a distinct Context and thread. All started threads are joined even
    if the consumer raises. The coordinator is tracked for its entire run, including
    the interval between starting a child and that child registering itself.
    """
    pending = deque()
    iterator = iter(items)

    def submit(item):
        result = []
        inherited = copy_context()

        def work():
            with tracked_thread(scanner, threading.current_thread()):
                try:
                    result.append((True, collect(item)))
                except BaseException as exc:
                    result.append((False, exc))

        thread = threading.Thread(target=inherited.run, args=(work,), name=f"scan-collect-{item}", daemon=False)
        thread.start()
        pending.append((thread, result))

    try:
        for _ in range(limit):
            item = next(iterator, None)
            if item is None:
                break
            submit(item)
        while pending:
            thread, result = pending[0]
            thread.join()
            pending.popleft()
            ok, value = result[0]
            if not ok:
                raise value
            yield value
            item = next(iterator, None)
            if item is not None:
                submit(item)
    finally:
        for thread, _ in pending:
            thread.join()


def _configuration(target):
    return {k: v for k, v in target.to_dict().items() if k not in {"last_scan", "notes", "added_at"}}


@dataclass
class HostWork:
    tid: str
    started_at: str = field(default_factory=utcnow)
    status: str = "running"
    errors: list[str] = field(default_factory=list)
    target: object = None
    adapter: object = None
    collected: object = None
    scratch: object = None
    guard: object = None
    findings: list = field(default_factory=list)
    coverage: dict | None = None

    def fail(self, exc):
        self.status = ("timed_out" if isinstance(exc, CollectionBudgetExpired) else
                       "stopped" if isinstance(exc, KillSwitchEngaged) else
                       "cancelled" if isinstance(exc, CollectionCancelled) else
                       "skipped" if isinstance(exc, (ScopeViolation, KeyError)) else "error")
        self.errors.append(str(exc))
        self.findings = []
        self.collected = None
        self.coverage = None


def collect_run(scanner, run):
    """Workers only collect; the coordinator detects, checks and publishes in input order."""
    from cyberthunder.scan import TargetScanResult
    from cyberthunder.scan_content import ScanContentService
    from cyberthunder.catalog_rule_metadata import annotate_native_findings

    ctx, actor = scanner.ctx, run.requested_by
    limit, budget = ctx.settings.scan_max_workers, ctx.settings.scan_host_budget_s
    scopes = {s["target_id"]: s for s in run.authorization_scopes or []}
    works = []
    # Scratch directories are owned here, including when a worker raises BaseException.
    scratch_dirs = []
    scratch_lock = threading.Lock()
    cancelled = scanner._cancellations[run.id]

    def live():
        if cancelled.is_set():
            raise CollectionCancelled("scan cancellation requested; active calls must drain")
        ctx.killswitch.guard(f"scan.collect:{run.id}", actor)

    def collect(tid):
        work = HostWork(tid)
        deadline = time.monotonic() + budget if budget else None

        def boundary():
            live()
            if deadline is not None and time.monotonic() >= deadline:
                raise CollectionBudgetExpired("host collection budget expired at a timed boundary; blocking calls were drained")

        try:
            boundary()
            target = deepcopy(persisted_target(ctx.inventory, tid, require_scope=True))
            # Keep the original run's source identity even in development fixtures.
            if scopes.get(tid) != target_scope(target):
                raise PermissionError("target ownership changed since scan creation")
            configuration = _configuration(target)
            authorize(ctx, "scan", actor=actor, target=target)
            principal = current_principal()
            access_configuration = (ctx.settings.auth_mode, ctx.settings.security_mode, ctx.settings.credential_sources)
            binding = (ctx.access.credential(principal, "scan", target).evidence()
                       if ctx.settings.auth_mode != "dev" else None)

            def guard():
                live()
                if (current_principal() != principal or
                        (ctx.settings.auth_mode, ctx.settings.security_mode, ctx.settings.credential_sources) != access_configuration):
                    raise PermissionError("scan identity or credential configuration changed")
                current = persisted_target(ctx.inventory, tid, require_scope=True)
                if _configuration(current) != configuration:
                    raise PermissionError("target configuration changed during collection")
                check_record(ctx, {"host": tid, "authorization_scope": scopes.get(tid)}, "scan")
                authorize(ctx, "scan", actor=actor, target=target)
                if binding is not None and ctx.access.credential(current_principal(), "scan", current).evidence() != binding:
                    raise PermissionError("target account binding changed during collection")

            def io_guard():
                boundary()
                guard()
                boundary()

            work.target, work.guard = target, guard
            work.adapter = ctx.adapter_for(target)
            io_guard()
            transport = ctx.transport_for(target)  # constructed inside the worker's request context
            # Never wrap or close a transport already owned by another collection.
            with scanner._lock:
                if id(transport) in scanner._collection_transports:
                    raise RuntimeError("transport factory reused an active connection")
                scanner._collection_transports.add(id(transport))
            try:
                protect_transport(transport, io_guard, sudo_allowed=True)
                # Existing account/sudo/lease guards remain inside these additional wrappers.
                io_guard()
                work.scratch = TemporaryDirectory(prefix=f".collect-{tid}-", dir=ctx.store.scan_dir(run.id))
                with scratch_lock:
                    scratch_dirs.append(work.scratch)
                facts = None
                try:
                    facts = work.adapter.discover(target, transport)
                except Exception as exc:
                    work.errors.append(f"discover: {exc}")
                io_guard()
                collected = work.adapter.collect(target, transport, Path(work.scratch.name),
                                                 modules=run.modules, rule_filter=run.rule_filter)
                io_guard()
                if collected.target_id != tid or collected.asset_type != target.asset_type:
                    raise ValueError("collected evidence belongs to another target")
                if collected.facts is None:
                    collected.facts = facts
                work.collected = collected
                work.errors.extend(collected.errors)
                work.status = "partial" if work.errors else "done"
            finally:
                try:
                    transport.close()
                finally:
                    with scanner._lock:
                        scanner._collection_transports.remove(id(transport))
            # Close can block too. It is drained and included in the collection budget.
            io_guard()
        except Exception as exc:
            work.fail(exc)
        return work

    try:
        results = _ordered_workers(scanner, run.targets, limit, collect)
        try:
            for work in results:
                works.append(work)
                if work.collected is not None:
                    try:
                        work.guard()
                        work.findings = scanner._filter(work.adapter.run_detection(work.target, work.collected), run.rule_filter)
                        annotate_native_findings(ctx, work.target, work.collected, work.findings, actor=actor)
                        work.guard()
                        for finding in work.findings:
                            if finding.host != work.tid:
                                raise ValueError("detector evidence belongs to another target")
                            finding.collection_provenance = dict(finding.collection_provenance or {}, simulated=bool(work.target.simulated))
                            finding.scan_id = run.id
                            finding.authorization_scope = scopes[work.tid]
                            finding.asset_type = finding.asset_type or work.target.asset_type
                            if work.errors and finding.status in (Status.NOT_A_FINDING, Status.NOT_APPLICABLE):
                                finding.status = Status.NOT_REVIEWED
                                finding.collection_provenance["collection_incomplete"] = True
                        work.coverage = ScanContentService(ctx).observed(work.target, work.collected, work.findings)
                    except Exception as exc:
                        work.fail(exc)
        finally:
            results.close()  # joins even if detection or iteration aborts

        # Close cancellation admission before publication. A cancel acknowledged before
        # this point is observed by every candidate; later requests return False.
        with scanner._lock:
            scanner._cancellations.pop(run.id, None)
        # No collection remains alive here. Revalidate all candidates after the drain;
        # an early host must not publish under a session revoked by a later host.
        for work in works:
            if work.collected is not None:
                try:
                    work.guard()
                    if work.collected.raw.get("catalog_rule_metadata", {}).get("snapshot_generation") is not None:
                        authorize(ctx, "read", actor=actor)
                except Exception as exc:
                    work.fail(exc)

        findings, updated = [], []
        for work in works:
            res = TargetScanResult(work.tid, status=work.status, started_at=work.started_at,
                                   finished_at=utcnow(), errors=list(work.errors), coverage=work.coverage)
            if work.collected is not None:
                try:
                    work.guard()
                    scanner._apply_known_good(work.target, work.findings, actor)
                    work.guard()
                    source = Path(work.scratch.name)
                    destination = ctx.store.scan_dir(run.id) / "raw" / work.tid
                    # Rewrite only paths owned by this host, preserving artifact identity.
                    for name, path in work.collected.artifacts.items():
                        work.collected.artifacts[name] = str(destination / Path(path).relative_to(source))
                    for finding in work.findings:
                        if finding.raw_ref and finding.raw_ref.startswith(str(source)):
                            finding.raw_ref = str(destination) + finding.raw_ref[len(str(source)):]
                    work.collected.workdir = str(destination)
                    work.collected.raw["coverage"] = work.coverage
                    source.rename(destination)
                    ctx.store.write_json(destination / "collected.json", work.collected.to_dict())
                    res.findings = len(work.findings)
                    res.open = sum(f.is_open for f in work.findings)
                    res.facts = work.collected.facts.to_dict() if work.collected.facts is not None else None
                    if work.status == "done":
                        ctx.inventory.update(work.tid, last_scan=utcnow())
                        updated.append(work.tid)
                    findings.extend(work.findings)
                except Exception as exc:
                    work.fail(exc)
                    res.status, res.errors, res.coverage = work.status, work.errors, None
            run.results[work.tid] = res
            ctx.audit.append("scan.target", actor, {"scan_id": run.id, "target": work.tid,
                "status": res.status, "findings": res.findings, "open": res.open, "errors": res.errors[:20]},
                subject=run.id, outcome="ok" if res.status == "done" else "error")

        counts = {status: sum(w.status == status for w in works)
                  for status in ("done", "partial", "error", "skipped", "timed_out", "stopped", "cancelled")}
        run.scheduling = {"max_workers": limit, "host_budget_s": budget,
                          "budget_semantics": "collection_boundaries_with_drain", "outcomes": counts}
        run.coverage_incomplete = True
        run.status = ("stopped" if counts["stopped"] else "cancelled" if counts["cancelled"] else
                      "done" if all(w.status == "done" for w in works) else
                      "partial" if any(w.collected is not None for w in works) else "error")
        if run.status != "done":
            run.error = "scan incomplete; see per-target collection outcomes"
        return findings, updated
    finally:
        for scratch in scratch_dirs:
            scratch.cleanup()
