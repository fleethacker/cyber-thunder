"""Append-only, hash-chained audit log (tamper-evident).

One JSON object per line. Each record carries the SHA-256 of the previous record and its own
SHA-256 over its canonical JSON. Editing, deleting or reordering any line breaks verification
from that point on. The agent writes here for every scan, finding, proposal, approval/denial,
apply, verify, rollback and kill-switch event (docs/CONTEXT.md section 5 guardrails).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from acd.findings.schema import utcnow

GENESIS = "0" * 64


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    count: int
    head: str
    bad_seq: int | None = None
    reason: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"OK  {self.count} records, head {self.head[:16]}"
        return f"TAMPERED at seq {self.bad_seq}: {self.reason} ({self.count} records read)"


class AuditLog:
    def __init__(self, path: str | Path, node: str | None = None):
        self.path = Path(path)
        self.node = node or platform.node() or "unknown"
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._tail()

    # -- reading -----------------------------------------------------------
    def records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def _tail(self) -> tuple[int, str]:
        seq, head = 0, GENESIS
        for rec in self.records():
            seq, head = rec["seq"], rec["hash"]
        return seq, head

    def __len__(self) -> int:
        return self._seq

    def __bool__(self) -> bool:
        # An empty log must still be truthy; callers write `if audit:` and must never skip logging.
        return True

    @property
    def head(self) -> str:
        return self._head

    # -- writing -----------------------------------------------------------
    def append(self, action: str, actor: str, details: dict | None = None, *,
               outcome: str = "ok", subject: str | None = None) -> dict:
        """Append one event. `actor` is a human (sailor id) or 'agent'."""
        with self._lock:
            rec = {
                "seq": self._seq + 1,
                "ts": utcnow(),
                "node": self.node,
                "actor": actor,
                "action": action,
                "subject": subject,
                "outcome": outcome,
                "details": details or {},
                "prev_hash": self._head,
            }
            rec["hash"] = record_hash(rec)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq, self._head = rec["seq"], rec["hash"]
            return rec

    # -- verification --------------------------------------------------------
    def verify(self) -> VerifyResult:
        return verify_file(self.path)


def verify_file(path: str | Path) -> VerifyResult:
    path = Path(path)
    prev, count, expected_seq = GENESIS, 0, 1
    if not path.exists():
        return VerifyResult(True, 0, GENESIS)
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError as e:
                return VerifyResult(False, count, prev, expected_seq, f"unparseable line: {e}")
            count += 1
            if rec.get("seq") != expected_seq:
                return VerifyResult(False, count, prev, expected_seq, f"sequence gap: got {rec.get('seq')}")
            if rec.get("prev_hash") != prev:
                return VerifyResult(False, count, prev, expected_seq, "prev_hash mismatch (record removed/reordered)")
            if record_hash(rec) != rec.get("hash"):
                return VerifyResult(False, count, prev, expected_seq, "hash mismatch (record modified)")
            prev, expected_seq = rec["hash"], expected_seq + 1
    return VerifyResult(True, count, prev)
