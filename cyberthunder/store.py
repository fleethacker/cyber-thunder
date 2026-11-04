"""On-disk state. Plain files so the whole state of a node can be copied, diffed and synced over a slow link.

Layout under <state_dir>:
  audit.jsonl              hash-chained audit log (append-only)
  proposals.json           approval gate store
  killswitch.json / KILL   kill switch state file / sentinel
  policy.json              standing-approval (automation) policy
  targets.yaml             asset inventory
  link.json                emulated-link state (kbps, latency, connected)
  scans/<scan_id>/run.json, findings.json, raw/<target_id>/...
  explanations/<finding_id>.json
  snapshots/<proposal_id>/...     before-state captured prior to apply
  outbox/ , synced/               sync-on-reconnect queue
  ingest/catalog/ , ingest/deltas/ , ingest/bulletins/
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

from cyberthunder.findings.schema import Finding, dump_findings, load_findings, utcnow


class StateStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        for sub in ("scans", "explanations", "snapshots", "outbox", "synced",
                    "ingest/catalog", "ingest/deltas", "ingest/bulletins"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    # -- well-known paths -----------------------------------------------------
    @property
    def audit_log(self) -> Path: return self.root / "audit.jsonl"
    @property
    def proposals(self) -> Path: return self.root / "proposals.json"
    @property
    def policy(self) -> Path: return self.root / "policy.json"
    @property
    def targets(self) -> Path: return self.root / "targets.yaml"
    @property
    def link_state(self) -> Path: return self.root / "link.json"
    @property
    def scans_dir(self) -> Path: return self.root / "scans"
    @property
    def explanations_dir(self) -> Path: return self.root / "explanations"
    @property
    def snapshots_dir(self) -> Path: return self.root / "snapshots"
    @property
    def outbox_dir(self) -> Path: return self.root / "outbox"
    @property
    def synced_dir(self) -> Path: return self.root / "synced"
    @property
    def ingest_dir(self) -> Path: return self.root / "ingest"

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def new_id(prefix: str = "") -> str:
        return f"{prefix}{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"

    @staticmethod
    def read_json(path: str | Path, default: Any = None) -> Any:
        p = Path(path)
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(path: str | Path, data: Any) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, p)

    # -- scans -----------------------------------------------------------------
    def scan_dir(self, scan_id: str) -> Path:
        d = self.scans_dir / scan_id
        (d / "raw").mkdir(parents=True, exist_ok=True)
        return d

    def save_scan_run(self, run: dict) -> None:
        self.write_json(self.scan_dir(run["id"]) / "run.json", run)

    def load_scan_run(self, scan_id: str) -> dict | None:
        return self.read_json(self.scans_dir / scan_id / "run.json")

    def list_scan_runs(self) -> list[dict]:
        runs = [r for r in (self.read_json(p) for p in self.scans_dir.glob("*/run.json")) if r]
        return sorted(runs, key=lambda r: r.get("started_at", ""), reverse=True)

    def latest_scan_id(self) -> str | None:
        runs = self.list_scan_runs()
        return runs[0]["id"] if runs else None

    def save_findings(self, scan_id: str, findings: Iterable[Finding], meta: dict | None = None) -> None:
        dump_findings(findings, self.scan_dir(scan_id) / "findings.json", meta=meta)

    def load_findings(self, scan_id: str | None = None) -> list[Finding]:
        scan_id = scan_id or self.latest_scan_id()
        if not scan_id:
            return []
        p = self.scans_dir / scan_id / "findings.json"
        return load_findings(p) if p.exists() else []

    def get_finding(self, finding_id: str, scan_id: str | None = None) -> Finding | None:
        for f in self.load_findings(scan_id):
            if f.id == finding_id:
                return f
        if scan_id is None:
            for run in self.list_scan_runs()[1:]:
                for f in self.load_findings(run["id"]):
                    if f.id == finding_id:
                        return f
        return None

    # -- explanations ----------------------------------------------------------
    def save_explanation(self, finding_id: str, data: dict) -> None:
        data = dict(data, saved_at=utcnow())
        self.write_json(self.explanations_dir / f"{finding_id}.json", data)

    def load_explanation(self, finding_id: str) -> dict | None:
        return self.read_json(self.explanations_dir / f"{finding_id}.json")

    # -- snapshots -------------------------------------------------------------
    def snapshot_dir(self, proposal_id: str) -> Path:
        d = self.snapshots_dir / proposal_id
        d.mkdir(parents=True, exist_ok=True)
        return d
