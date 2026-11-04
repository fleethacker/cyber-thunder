"""Content store: DISA files this node holds, under <state_dir>/content/.

  files/<name>              the files as downloaded or imported (zips are kept whole)
  scap/<product>/<name>.xml SCAP datastreams extracted from benchmark zips, for the scanners
  quarantine/               files that failed a check, each with a .why.json note
  index.json                one record per held file
  last_check.json           the most recent update check
  jobs/<id>.json            pull jobs with per-file progress
  source.json               the cached Apex class id of the cyber.mil index
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyberthunder.findings.schema import utcnow

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.store import StateStore

RECORD_KEYS = ("filename", "product_key", "kind", "version", "version_label", "sha256", "etag", "bytes", "url",
               "fetched_at", "fetched_by", "source", "ingest", "upload_date", "disk_name")


class ContentStore:
    def __init__(self, store: "StateStore"):
        self.state = store
        self._lock = threading.RLock()

    # -- paths ------------------------------------------------------------------------------------
    @property
    def root(self) -> Path:
        return self.state.root / "content"

    @property
    def files_dir(self) -> Path:
        return self.root / "files"

    @property
    def scap_dir(self) -> Path:
        return self.root / "scap"

    @property
    def quarantine_dir(self) -> Path:
        return self.root / "quarantine"

    @property
    def jobs_dir(self) -> Path:
        return self.root / "jobs"

    @property
    def index_path(self) -> Path:
        return self.root / "index.json"

    @property
    def last_check_path(self) -> Path:
        return self.root / "last_check.json"

    @property
    def source_path(self) -> Path:
        return self.root / "source.json"

    # -- held files -------------------------------------------------------------------------------
    def records(self) -> list[dict]:
        doc = self.state.read_json(self.index_path, {}) or {}
        recs = doc.get("files", {}) if isinstance(doc, dict) else {}
        return sorted(recs.values(), key=lambda r: (r.get("product_key") or "", r.get("kind") or "",
                                                    r.get("filename") or ""))

    def get(self, filename: str) -> dict | None:
        doc = self.state.read_json(self.index_path, {}) or {}
        return (doc.get("files") or {}).get(filename)

    def put(self, record: dict) -> dict:
        rec = {k: record.get(k) for k in RECORD_KEYS}
        rec["ingest"] = dict(record.get("ingest") or {})
        with self._lock:
            doc = self.state.read_json(self.index_path, {}) or {}
            files = doc.setdefault("files", {})
            files[rec["filename"]] = rec
            doc["updated_at"] = utcnow()
            self.state.write_json(self.index_path, doc)
        return rec

    def by_product(self) -> list[dict]:
        """Held content grouped per product, newest version first within each kind."""
        groups: dict[str, dict] = {}
        for r in self.records():
            key = r.get("product_key") or r.get("filename")
            g = groups.setdefault(key, {"product_key": key, "files": []})
            g["files"].append(r)
        for g in groups.values():
            g["files"].sort(key=lambda r: (r.get("kind") or "", tuple(r.get("version") or ())), reverse=True)
        return [groups[k] for k in sorted(groups)]

    # -- check, jobs, source ---------------------------------------------------------------------
    def last_check(self) -> dict | None:
        return self.state.read_json(self.last_check_path)

    def save_check(self, doc: dict) -> None:
        self.state.write_json(self.last_check_path, doc)

    def job_path(self, job_id: str) -> Path:
        from cyberthunder.ingest.delta import safe_name
        return self.jobs_dir / f"{safe_name(job_id)}.json"

    def save_job(self, job: dict) -> None:
        with self._lock:
            self.state.write_json(self.job_path(job["id"]), job)

    def load_job(self, job_id: str) -> dict | None:
        # The pull thread replaces this file several times a second; on Windows a read that lands on the
        # replace fails for a moment, so retry briefly instead of answering 500 to a polling client.
        for attempt in range(20):
            try:
                return self.state.read_json(self.job_path(job_id))
            except (PermissionError, ValueError):
                if attempt == 19:
                    raise
                time.sleep(0.05)
        return None

    def jobs(self) -> list[dict]:
        out = [self.state.read_json(p) for p in self.jobs_dir.glob("*.json")] if self.jobs_dir.is_dir() else []
        return sorted((j for j in out if j), key=lambda j: j.get("created_at", ""), reverse=True)

    def source(self) -> dict:
        return self.state.read_json(self.source_path, {}) or {}

    def save_source(self, **changes: Any) -> dict:
        d = self.source()
        d.update(changes)
        d["updated_at"] = utcnow()
        self.state.write_json(self.source_path, d)
        return d
