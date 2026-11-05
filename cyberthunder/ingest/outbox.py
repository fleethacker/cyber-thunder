"""Sync-on-reconnect outbox.

Reports, POA&Ms, audit extracts and scan summaries for shore are queued here while the link is down and
staged locally when attempts are permitted. Each entry is two files in <state_dir>/outbox/:

  <stamp>-<rand>-<name>      the payload, exactly as it will be sent
  <stamp>-<rand>-<name>.meta.json   kind, name, size, sha256, when and by whom it was queued, caller metadata

sync() moves both files to <state_dir>/synced/. This is local staging, not network
delivery. Optional test estimates never become network observations.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyberthunder.findings.schema import utcnow
from cyberthunder.ingest.link import transfer_seconds

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.audit.chain import AuditLog
    from cyberthunder.ingest.link import Link
    from cyberthunder.store import StateStore

META_SUFFIX = ".meta.json"


class LinkDisconnected(RuntimeError):
    pass


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")[:100] or "item"


class Outbox:
    def __init__(self, store: "StateStore", link: "Link", audit: "AuditLog | None" = None):
        self.store = store
        self.link = link
        self.audit = audit
        self._lock = threading.Lock()

    @property
    def pending_dir(self) -> Path:
        return self.store.outbox_dir

    @property
    def synced_dir(self) -> Path:
        return self.store.synced_dir

    def enqueue(self, kind: str, name: str, data: bytes, meta: dict | None = None, *, actor: str = "operator") -> dict:
        if isinstance(data, str):
            data = data.encode("utf-8")
        with self._lock:
            self.pending_dir.mkdir(parents=True, exist_ok=True)
            # time_ns() can repeat between calls on Windows, so the id carries a random part and the payload
            # is created exclusively: an existing entry is never overwritten.
            while True:
                stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"{time.time_ns() % 1_000_000_000:09d}"
                fname = f"{stamp}-{uuid.uuid4().hex[:8]}-{_safe(name)}"
                path = self.pending_dir / fname
                try:
                    with open(path, "xb") as fh:
                        fh.write(data)
                    break
                except FileExistsError:
                    continue
            entry = {"id": fname, "kind": kind, "name": name, "bytes": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(), "enqueued_at": utcnow(), "enqueued_by": actor,
                     "meta": meta or {}, "status": "pending"}
            self.store.write_json(self.pending_dir / (fname + META_SUFFIX), entry)
        if self.audit is not None:
            self.audit.append("outbox.enqueue", actor, {k: entry[k] for k in ("id", "kind", "name", "bytes", "sha256")})
        return entry

    def _entries(self, d: Path) -> list[dict]:
        out = []
        for m in sorted(d.glob("*" + META_SUFFIX)):
            e = self.store.read_json(m)
            if e:
                out.append(e)
        return out

    def list(self) -> dict[str, list[dict]]:
        return {"pending": self._entries(self.pending_dir), "synced": self._entries(self.synced_dir)}

    def sync(self, force: bool = False, *, actor: str = "operator") -> dict[str, Any]:
        """Stage pending files locally. force=True permits manual courier staging while offline."""
        state = self.link.state()
        self.link.kill.guard("outbox.sync", actor)
        if not state.connected and not force:
            if self.audit is not None:
                self.audit.append("outbox.sync", actor, {"pending": len(self._entries(self.pending_dir))},
                                  outcome="blocked")
            raise LinkDisconnected("link is disconnected; entries stay queued until it reconnects")
        sent: list[dict] = []
        total = 0
        seconds = 0.0
        started = time.monotonic()
        with self._lock:
            self.synced_dir.mkdir(parents=True, exist_ok=True)
            for entry in self._entries(self.pending_dir):
                self.link.kill.guard("outbox.sync", actor)
                src = self.pending_dir / entry["id"]
                if not src.exists():
                    continue
                n = src.stat().st_size
                secs = transfer_seconds(n, state)
                entry.update(status="synced", synced_at=utcnow(), synced_by=actor, transfer_seconds=None,
                             transfer_kind="local_move", test_estimate_seconds=secs,
                             forced=bool(force and not state.connected),
                             link={"kbps": state.kbps, "latency_ms": state.latency_ms})
                os.replace(src, self.synced_dir / entry["id"])
                self.store.write_json(self.synced_dir / (entry["id"] + META_SUFFIX), entry)
                (self.pending_dir / (entry["id"] + META_SUFFIX)).unlink(missing_ok=True)
                sent.append(entry)
                total += n
                seconds += secs or 0
        result = {"sent": len(sent), "bytes": total, "seconds": round(time.monotonic() - started, 6),
                  "transfer_kind": "local_move", "test_estimate_seconds": round(seconds, 3) if state.mode == "test" else None,
                  "forced": bool(force),
                  "entries": [e["id"] for e in sent]}
        if self.audit is not None:
            self.audit.append("outbox.sync", actor, result)
        return result
