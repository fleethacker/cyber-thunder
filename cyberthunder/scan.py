"""Scan orchestration: for each in-scope target, open its transport, run the adapter's collect and detection,
persist findings per scan run, audit everything, then (optionally) auto-propose fixes and precompute
explanations in the background.

Scans honour the kill switch: start() refuses while it is engaged, a running scan checks it before each target
and marks the targets it has not reached 'stopped', and nothing is proposed after a stopped scan.

ScanRun lives at store.scans/<id>/run.json; findings at findings.json; raw artifacts under raw/<target_id>/.
"""
from __future__ import annotations
from contextvars import copy_context
from cyberthunder.control.principal import authorize, operation

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Iterable

from cyberthunder.adapters.base import MODULES
from cyberthunder.adapters.kubernetes.known_good import KubernetesKnownGoodState
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding, summarize, utcnow
from cyberthunder.inventory.targets import ScopeViolation

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

STATUSES = ("pending", "running", "done", "error", "skipped", "cancelled", "stopped")


@dataclass
class TargetScanResult:
    target_id: str
    status: str = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    findings: int = 0
    open: int = 0
    errors: list[str] = field(default_factory=list)
    facts: dict | None = None
    coverage: dict | None = None


@dataclass
class ScanRun:
    id: str
    targets: list[str]
    modules: list[str] = field(default_factory=lambda: ["check", "hunt", "cve"])
    rule_filter: list[str] | None = None          # targeted rescan (e.g. rules changed by a STIG delta)
    trigger: str = "manual"                       # manual | stig_delta | bulletin | verify | demo
    requested_by: str = "operator"
    status: str = "pending"
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    results: dict[str, TargetScanResult] = field(default_factory=dict)
    findings_count: int = 0
    summary: dict = field(default_factory=dict)   # findings.schema.summarize() output
    error: str | None = None
    coverage_incomplete: bool | None = None       # None for legacy runs without coverage observations
    authorization_scopes: list[dict] | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ScanRun":
        d = dict(d)
        d["results"] = {k: TargetScanResult(**v) for k, v in d.get("results", {}).items()}
        return cls(**d)

    @property
    def progress(self) -> dict:
        done = sum(1 for r in self.results.values() if r.status in ("done", "error", "skipped", "stopped"))
        return {"done": done, "total": len(self.targets)}


class Scanner:
    """Read-only orchestration. A scan never changes an asset; fixes go through RemediationEngine."""

    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self._threads: dict[str, threading.Thread] = {}
        self._active: dict[str, dict] = {}         # runs in progress, served from memory while they write
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------------------
    @operation("scan")
    def start(self, target_ids: Iterable[str] | None = None, *, modules: Iterable[str] | None = None,
              rule_filter: list[str] | None = None, trigger: str = "manual", requested_by: str = "operator",
              background: bool = True) -> ScanRun:
        """Create the run, persist it, and run it (in a daemon thread when background=True). Returns at once.
        Raises KillSwitchEngaged (after auditing the block) when the kill switch is engaged."""
        self.ctx.killswitch.guard("scan.start", requested_by)
        if target_ids is None:
            ids = [t.id for t in self.ctx.inventory.all() if t.in_scope]
            if getattr(self.ctx.settings, "auth_mode", "dev") != "dev":
                ids = [tid for tid in ids if self.ctx.may_access(tid, "scan")]
                if not ids:
                    raise PermissionError("no targets are authorized for scanning by this account")
        else:
            ids = list(dict.fromkeys(target_ids))
        for tid in ids:
            authorize(self.ctx, "scan", actor=requested_by, target=tid)
        run = ScanRun(id=self.ctx.store.new_id("scan-"), targets=ids,
                      modules=list(modules) if modules else list(MODULES),
                      rule_filter=list(rule_filter) if rule_filter else None,
                      trigger=trigger, requested_by=requested_by, coverage_incomplete=True)
        run.results = {tid: TargetScanResult(tid) for tid in ids}
        self._save(run)
        if background:
            inherited = copy_context()
            th = threading.Thread(target=inherited.run, args=(self._run_quietly, run), name=f"scan-{run.id}", daemon=True)
            with self._lock:
                self._threads[run.id] = th
            th.start()
        else:
            self.run(run)
        return run

    def join(self, scan_id: str, timeout: float | None = None) -> ScanRun | None:
        """Wait for a background scan (tests and the CLI). Returns the persisted run."""
        with self._lock:
            th = self._threads.get(scan_id)
        if th is not None:
            th.join(timeout)
            if not th.is_alive():
                with self._lock:
                    self._threads.pop(scan_id, None)
        return self.get(scan_id)

    def is_running(self, scan_id: str) -> bool:
        with self._lock:
            th = self._threads.get(scan_id)
        return bool(th and th.is_alive())

    def _run_quietly(self, run: ScanRun) -> None:
        try:
            self.run(run)
        except Exception:  # noqa: BLE001  a background thread must not die silently; run() already recorded it
            if run.status == "pending":
                run.status, run.error, run.finished_at = "error", "scan authorization expired or was revoked before execution", utcnow()
                self._save(run)
            log.exception("scan %s failed", run.id)

    def _save(self, run: ScanRun) -> None:
        if run.authorization_scopes is None:
            previous = self.ctx.store.load_scan_run(run.id)
            run.authorization_scopes = (previous.get("authorization_scopes") if previous is not None else
                                        self.ctx.store.capture_resources(run.targets))
        d = run.to_dict()
        with self._lock:
            if run.status in ("pending", "running"):
                self._active[run.id] = d
            else:
                self._active.pop(run.id, None)
        # Windows refuses to replace a file another reader has open for a moment (the UI polling run.json);
        # retry briefly rather than lose the progress update.
        for attempt in range(20):
            try:
                self.ctx.store.save_scan_run(d)
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)

    # -- execution ---------------------------------------------------------------------
    @operation("scan")
    def run(self, run: ScanRun) -> ScanRun:
        """Execute synchronously: per target -> assert_in_scope -> transport -> adapter.collect -> run_detection
        -> persist. Audit: scan.start, scan.target (per target, with counts/errors), scan.finish."""
        ctx = self.ctx
        actor = run.requested_by
        for tid in run.targets:
            authorize(ctx, "scan", actor=actor, target=tid)
        run.status = "running"
        self._save(run)
        ctx.audit.append("scan.start", actor, {"targets": run.targets, "modules": run.modules,
                                               "rule_filter": run.rule_filter, "trigger": run.trigger}, subject=run.id)
        all_findings: list[Finding] = []
        updated: list[str] = []
        try:
            for i, tid in enumerate(run.targets):
                if self._stopped(run, i):
                    break
                res = run.results.setdefault(tid, TargetScanResult(tid))
                found = self._scan_target(run, res)
                if found is not None:
                    all_findings.extend(found)
                    updated.append(tid)
                run.findings_count = len(all_findings)
                ctx.store.save_findings(run.id, all_findings, meta=self._meta(run))
                self._save(run)
            run.summary = summarize(all_findings)
            run.findings_count = len(all_findings)
            ctx.store.save_findings(run.id, all_findings, meta=self._meta(run))
            if run.status != "stopped":
                if run.results and all(r.status == "error" for r in run.results.values()):
                    run.status, run.error = "error", "every target failed; see per-target errors"
                else:
                    run.status = "done"
        except Exception as e:  # noqa: BLE001
            log.exception("scan %s aborted", run.id)
            run.status, run.error = "error", str(e)
        run.finished_at = utcnow()
        self._save(run)
        if updated:
            try:
                ctx.save_inventory(actor, "inventory.update",
                                   {"reason": "last_scan", "scan_id": run.id, "targets": updated})
            except Exception as e:  # noqa: BLE001
                log.warning("inventory save after scan %s failed: %s", run.id, e)
        ctx.audit.append("scan.finish", actor, {"status": run.status, "summary": run.summary,
                                                "findings": run.findings_count, "error": run.error,
                                                "progress": run.progress}, subject=run.id,
                         outcome={"done": "ok", "stopped": "blocked"}.get(run.status, "error"))
        if run.trigger != "verify" and run.status == "done":
            try:
                ctx.killswitch.guard(f"scan.after:{run.id}", actor)
            except KillSwitchEngaged:
                run.summary["after_scan"] = "skipped: kill switch engaged"
                self._save(run)
            else:
                self._after_scan(run, all_findings)
        return run

    def _stopped(self, run: ScanRun, index: int) -> bool:
        """Check the kill switch before the next target. When engaged, mark this and every later target
        'stopped' and the run 'stopped'; the guard has already audited the block."""
        try:
            self.ctx.killswitch.guard(f"scan.target:{run.id}:{run.targets[index]}", run.requested_by)
            return False
        except KillSwitchEngaged as e:
            for tid in run.targets[index:]:
                res = run.results.setdefault(tid, TargetScanResult(tid))
                res.status, res.finished_at = "stopped", utcnow()
                res.errors.append(str(e))
            run.status, run.error = "stopped", str(e)
            return True

    @staticmethod
    def _meta(run: ScanRun) -> dict:
        return {"scan_id": run.id, "trigger": run.trigger, "targets": run.targets, "modules": run.modules}

    def _after_scan(self, run: ScanRun, findings: list[Finding]) -> None:
        ctx = self.ctx
        ingest = getattr(ctx, "ingest", None)
        rematch = getattr(ingest, "rematch_all", None) if ingest is not None else None
        if callable(rematch) and not run.rule_filter and run.trigger != "bulletin":
            # bulletins stay in force until patched: match them again against this full scan's inventories
            try:
                r = rematch(run.id) or {}
                run.summary["bulletins_rematched"] = {"scan_id": r.get("scan_id"), "bulletins": len(r.get("bulletins", [])),
                                                      "findings": r.get("findings", 0)}
            except Exception as e:  # noqa: BLE001
                log.warning("bulletin re-match after scan %s failed: %s", run.id, e)
                run.summary["bulletin_rematch_error"] = str(e)
        open_ = [f for f in findings if f.is_open]
        if ctx.settings.auto_propose and open_:
            try:
                created = ctx.engine.auto_propose(open_)
                run.summary["proposals_created"] = len(created)
            except Exception as e:  # noqa: BLE001
                log.exception("auto-propose after scan %s failed", run.id)
                run.summary["auto_propose_error"] = str(e)
        explain = getattr(ctx, "explain", None)
        if ctx.settings.explain_precompute and explain is not None and findings:
            try:
                run.summary["explanations_queued"] = explain.precompute(findings)
            except NotImplementedError:
                run.summary["explanations_queued"] = 0
            except Exception as e:  # noqa: BLE001
                run.summary["explain_error"] = str(e)
        self._save(run)

    def _scan_target(self, run: ScanRun, res: TargetScanResult) -> list[Finding] | None:
        """Scan one target. Returns its findings, or None when it was skipped or failed."""
        ctx = self.ctx
        actor = run.requested_by
        tid = res.target_id
        res.status, res.started_at, res.errors = "running", utcnow(), []
        self._save(run)
        t0 = time.monotonic()

        def finish(status: str, *, outcome: str = "ok", findings: list[Finding] | None = None) -> None:
            res.status, res.finished_at = status, utcnow()
            fl = findings or []
            ctx.audit.append("scan.target", actor, {
                "scan_id": run.id, "target": tid, "status": status, "findings": len(fl),
                "open": sum(1 for f in fl if f.is_open), "duration_s": round(time.monotonic() - t0, 3),
                "errors": res.errors[:20]}, subject=run.id, outcome=outcome)

        try:
            target = ctx.inventory.assert_in_scope(tid)
            authorize(ctx, "scan", actor=actor, target=target)
        except ScopeViolation as e:
            res.errors.append(str(e))
            ctx.audit.append("action.blocked", actor, {"action": "scan.collect", "target": tid, "scan_id": run.id,
                                                       "reason": str(e)}, subject=tid, outcome="blocked")
            finish("skipped", outcome="blocked")
            return None
        try:
            adapter = ctx.adapter_for(target)
        except KeyError as e:
            res.errors.append(str(e).strip("'\""))
            finish("skipped", outcome="skipped")
            return None
        from cyberthunder.scan_content import ScanContentService
        res.coverage = ScanContentService(ctx).preflight([tid], modules=run.modules)["targets"][0]
        try:
            transport = ctx.transport_for(target)
        except Exception as e:  # noqa: BLE001  TransportError or a connect failure inside the factory
            res.errors.append(f"transport: {e}")
            finish("error", outcome="error")
            return None

        workdir = ctx.store.scan_dir(run.id) / "raw" / tid
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            facts = None
            try:
                facts = adapter.discover(target, transport)
            except Exception as e:  # noqa: BLE001  discovery is informational
                res.errors.append(f"discover: {e}")
            collected = adapter.collect(target, transport, workdir, modules=run.modules, rule_filter=run.rule_filter)
            if collected.facts is None and facts is not None:
                collected.facts = facts
            findings = adapter.run_detection(target, collected)
            findings = self._filter(findings, run.rule_filter)
            self._apply_known_good(target, findings, actor)
            for f in findings:
                f.collection_provenance = dict(f.collection_provenance or {})
                f.collection_provenance["simulated"] = bool(target.simulated)
                f.scan_id = run.id
                f.asset_type = f.asset_type or target.asset_type
            res.coverage = ScanContentService(ctx).observed(target, collected, findings)
            collected.raw["coverage"] = res.coverage
            run.coverage_incomplete = True
            ctx.store.write_json(workdir / "collected.json", collected.to_dict())
            res.errors.extend(collected.errors)
            res.findings = len(findings)
            res.open = sum(1 for f in findings if f.is_open)
            res.facts = collected.facts.to_dict() if collected.facts is not None else None
            ctx.inventory.update(tid, last_scan=utcnow())
            finish("done", findings=findings)
            return findings
        except Exception as e:  # noqa: BLE001
            log.exception("scan of %s failed", tid)
            res.errors.append(f"collect: {e}")
            finish("error", outcome="error")
            return None
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                log.warning("transport close failed for %s", tid)

    def _apply_known_good(self, target, findings: list[Finding], actor: str) -> list[str]:
        """Mark Kubernetes findings covered by persistent site exceptions before summaries/proposals."""
        if target.asset_type != "kubernetes" or not findings:
            return []
        matched = KubernetesKnownGoodState(self.ctx.store, ctx=self.ctx).apply(findings)
        if matched:
            ids = sorted(set(matched))
            self.ctx.audit.append("known_good.apply", actor, {"target": target.id, "exceptions": ids,
                                                              "findings": len(matched)},
                                  subject=target.id, outcome="ok")
        return matched

    @staticmethod
    def _filter(findings: list[Finding], rule_filter: list[str] | None) -> list[Finding]:
        """A targeted rescan reports only the requested rules, whatever the adapter returned."""
        if not rule_filter:
            return findings
        wanted = set(rule_filter)
        return [f for f in findings if wanted & {f.rule_id, f.rule_version, f.group_id, *f.citations}]

    # -- queries -----------------------------------------------------------------------
    def get(self, scan_id: str) -> ScanRun | None:
        with self._lock:
            d = self._active.get(scan_id)
        if d is None:
            d = self.ctx.store.load_scan_run(scan_id)
        return ScanRun.from_dict(d) if d else None

    def list(self) -> list[ScanRun]:
        return [ScanRun.from_dict(d) for d in self.ctx.store.list_scan_runs()]

    def latest(self) -> ScanRun | None:
        runs = self.list()
        return runs[0] if runs else None
