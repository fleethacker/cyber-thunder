"""Node state. Documents live in a backend (json files or sqlite, CT_STATE_BACKEND); files stay files, so the
whole state of a node can still be copied, diffed and synced over a slow link.

Layout under <state_dir>:
  audit.jsonl              hash-chained audit log (append-only)              file
  proposals.json           approval gate store                               file (its own cross-process lock)
  killswitch.json / KILL   kill switch state file / sentinel                 file
  policy.json              standing-approval (automation) policy             file
  targets.yaml             asset inventory                                   file (its own cross-process lock)
  link.json                emulated-link state (kbps, latency, connected)    document
  demo.json                presenter switch                                  document
  scans/<scan_id>/run.json, findings.json                                    documents
  scans/<scan_id>/raw/<target_id>/...   scanner working directory            files
  explanations/<finding_id>.json                                             documents
  snapshots/<proposal_id>/...     before-state captured prior to apply       files
  outbox/ , synced/               sync-on-reconnect queue                    files
  ingest/catalog/ (xml)                                                      files
  ingest/deltas/ , ingest/bulletins/                                         documents
  discovery/ (scopes, assets, ignored, runs/)                                documents
  content/files/ , content/scap/ , content/quarantine/ , content/manifest.json   files
  content/index.json , content/last_check.json , content/source.json , content/jobs/   documents
  state.db                 the documents, when CT_STATE_BACKEND=sqlite

A document is JSON the application reads and writes only through this class; a file is read from disk by
other programs, people or transports as well. cyberthunder/state/ holds the routing list and the backends;
docs/STATE.md the operator's view, including the migration commands.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

from cyberthunder.findings.schema import Finding, findings_doc, findings_from_doc, utcnow
from cyberthunder.state import Backend, backend_from_env, is_document, open_backend, validate_backend
from cyberthunder.state.json_files import JsonFilesBackend, read_json_file, write_json_file

log = logging.getLogger(__name__)

# Runs that re-evaluate only part of the picture; they overlay the latest full scan instead of replacing it.
PARTIAL_TRIGGERS = {"bulletin", "stig_delta", "verify"}


def is_partial_run(run: dict) -> bool:
    return run.get("trigger") in PARTIAL_TRIGGERS or bool(run.get("rule_filter"))


class StateStore:
    def __init__(self, root: str | Path, backend: str | None = None):
        self.root = Path(root)
        for sub in ("scans", "explanations", "snapshots", "outbox", "synced",
                    "ingest/catalog", "ingest/deltas", "ingest/bulletins"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        self._abs_root = os.path.abspath(os.fspath(self.root))
        self.backend_name = validate_backend(backend) if backend else backend_from_env()
        self.docs: Backend = open_backend(self.backend_name, self.root)
        # JSON paths that are files rather than documents are always files on disk
        self.files: Backend = self.docs if self.backend_name == "json" else JsonFilesBackend(self.root)
        self._warn_if_unmigrated()

    def _warn_if_unmigrated(self) -> None:
        """A directory whose documents sit in the backend that is not configured looks empty. Say so once."""
        try:
            if self.backend_name == "sqlite" and getattr(self.docs, "created", False):
                n = len(self.files.documents())
                if n:
                    log.warning("%s holds %d JSON documents that are not in state.db yet; run "
                                "'cyberthunder state migrate --to sqlite' (CT_STATE_BACKEND=sqlite)", self.root, n)
            elif self.backend_name == "json" and (self.root / "state.db").is_file():
                log.warning("%s has a state.db that CT_STATE_BACKEND=json ignores; run "
                            "'cyberthunder state info --backend sqlite' to see what it holds", self.root)
        except Exception as e:  # noqa: BLE001  advisory only
            log.debug("state check skipped: %s", e)

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

    def logical_path(self, path: str | Path) -> str | None:
        """The path relative to the state directory in POSIX form, or None when it lies outside it."""
        try:
            rel = os.path.relpath(os.path.abspath(os.fspath(path)), self._abs_root)
        except ValueError:            # another drive on Windows
            return None
        if rel == os.pardir or rel.startswith(os.pardir + os.sep) or rel.startswith("../"):
            return None
        return "" if rel == os.curdir else rel.replace("\\", "/")

    def _backend_for(self, logical: str) -> Backend:
        return self.docs if is_document(logical) else self.files

    def read_json(self, path: str | Path, default: Any = None) -> Any:
        """A document from the backend, a file from disk for file paths and paths outside the state
        directory; `default` when there is none."""
        key = self.logical_path(path)
        if key is None:
            return read_json_file(Path(path), default)
        doc = self._backend_for(key).get(key)
        return default if doc is None else doc

    def write_json(self, path: str | Path, data: Any) -> None:
        key = self.logical_path(path)
        if key is None:
            write_json_file(Path(path), data)
            return
        self._backend_for(key).put(key, data)

    def delete_json(self, path: str | Path) -> bool:
        key = self.logical_path(path)
        if key is None:
            p = Path(path)
            try:
                p.unlink()
                return True
            except FileNotFoundError:
                return False
        return self._backend_for(key).delete(key)

    def list_json(self, directory: str | Path, pattern: str = "*.json") -> list[Path]:
        """Absolute paths of the JSON documents and files under a directory of the state directory that
        match the glob, whichever backend holds them. Replaces `directory.glob(pattern)` for callers."""
        prefix = self.logical_path(directory)
        if prefix is None:
            return sorted(p for p in Path(directory).glob(pattern) if p.is_file())
        if self.files is self.docs:
            found = dict(self.docs.list(prefix, pattern))
        else:
            found = {rel: m for rel, m in self.docs.list(prefix, pattern) if is_document(rel)}
            found.update((rel, m) for rel, m in self.files.list(prefix, pattern) if not is_document(rel))
        return [self.root.joinpath(*rel.split("/")) for rel in sorted(found)]

    def lock(self, name: str):
        """Cross-process lock on the document backend (see cyberthunder.state.Backend.lock)."""
        return self.docs.lock(name)

    def close(self) -> None:
        self.docs.close()
        if self.files is not self.docs:
            self.files.close()

    def info(self) -> dict:
        return {"backend": self.backend_name, "location": self.docs.location(), "documents": self.docs.count()}

    # -- scans -----------------------------------------------------------------
    def scan_dir(self, scan_id: str) -> Path:
        d = self.scans_dir / scan_id
        (d / "raw").mkdir(parents=True, exist_ok=True)
        return d

    def save_scan_run(self, run: dict) -> None:
        from cyberthunder.findings.review import save_observation_document
        save_observation_document(self, run["id"], run, kind="run")

    def load_scan_run(self, scan_id: str) -> dict | None:
        return self.read_json(self.scans_dir / scan_id / "run.json")

    def list_scan_runs(self) -> list[dict]:
        runs = [r for r in (self.read_json(p) for p in self.list_json(self.scans_dir, "*/run.json")) if r]
        return sorted(runs, key=lambda r: r.get("started_at", ""), reverse=True)

    def latest_scan_id(self, *, full_only: bool = True) -> str | None:
        """Newest scan run. By default partial runs (bulletin matches, targeted rescans after a STIG
        delta, verification rescans) are skipped, so a bulletin never hides the last full picture."""
        runs = self.list_scan_runs()
        for run in runs:
            if full_only and is_partial_run(run):
                continue
            return run["id"]
        return runs[0]["id"] if runs else None

    def save_findings(self, scan_id: str, findings: Iterable[Finding], meta: dict | None = None) -> None:
        from cyberthunder.findings.review import save_observation_document
        save_observation_document(self, scan_id, findings_doc(findings, meta=meta), kind="findings")

    def _run_findings(self, scan_id: str) -> list[Finding]:
        doc = self.read_json(self.scans_dir / scan_id / "findings.json")
        return findings_from_doc(doc) if doc else []

    def load_findings(self, scan_id: str | None = None) -> list[Finding]:
        """Findings of one run, or (default) the current picture: see current_findings()."""
        if scan_id:
            return self._run_findings(scan_id)
        return self.current_findings()

    def current_findings(self) -> list[Finding]:
        """The latest full scan's findings with every newer partial run overlaid by finding id.

        Finding ids are stable per (host, source, rule), so a targeted rescan replaces the findings it
        re-evaluated and a bulletin match adds its findings, while everything else from the full scan stays."""
        runs = self.list_scan_runs()
        base_id = self.latest_scan_id(full_only=True)
        if not base_id:
            return []
        base_run = next(r for r in runs if r["id"] == base_id)
        merged = {f.id: f for f in self._run_findings(base_id)}
        newer = [r for r in runs if r["id"] != base_id and r.get("started_at", "") >= base_run.get("started_at", "")]
        for run in reversed(newer):          # oldest first, so the newest result wins
            for f in self._run_findings(run["id"]):
                merged[f.id] = f
        return list(merged.values())

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
