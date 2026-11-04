"""Scan orchestration: for each in-scope target, open its transport, run the adapter's collect and detection,
persist findings per scan run, audit everything, then (optionally) auto-propose fixes and precompute
explanations in the background.

ScanRun lives at store.scans/<id>/run.json; findings at findings.json; raw artifacts under raw/<target_id>/.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Iterable

from cyberthunder.findings.schema import utcnow

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

STATUSES = ("pending", "running", "done", "error", "skipped", "cancelled")


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
        done = sum(1 for r in self.results.values() if r.status in ("done", "error", "skipped"))
        return {"done": done, "total": len(self.targets)}


class Scanner:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx

    def start(self, target_ids: Iterable[str] | None = None, *, modules: Iterable[str] | None = None,
              rule_filter: list[str] | None = None, trigger: str = "manual", requested_by: str = "operator",
              background: bool = True) -> ScanRun:
        """Create the run, persist it, and run it (in a daemon thread when background=True). Returns at once."""
        raise NotImplementedError("scanner not built yet")

    def run(self, run: ScanRun) -> ScanRun:
        """Execute synchronously: per target -> assert_in_scope -> transport -> adapter.collect -> run_detection
        -> persist. Audit: scan.start, scan.target (per target, with counts/errors), scan.finish."""
        raise NotImplementedError

    def get(self, scan_id: str) -> ScanRun | None:
        d = self.ctx.store.load_scan_run(scan_id)
        return ScanRun.from_dict(d) if d else None

    def list(self) -> list[ScanRun]:
        return [ScanRun.from_dict(d) for d in self.ctx.store.list_scan_runs()]

    def latest(self) -> ScanRun | None:
        runs = self.list()
        return runs[0] if runs else None
