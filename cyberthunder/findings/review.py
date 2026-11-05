"""Scoped human reviews, independent of immutable scanner observations."""
from __future__ import annotations

import hashlib
import json
import re
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.identity import require_human
from cyberthunder.findings.lifecycle import (
    LifecycleReentry, ReviewConflict, finding_key, finding_lifecycle_lock, review_coordination_lock,
)
from cyberthunder.findings.schema import Finding, findings_from_doc

if TYPE_CHECKING:
    from cyberthunder.context import AppContext

DISPOSITIONS = frozenset({"unreviewed", "confirmed", "false_positive", "not_applicable", "needs_investigation"})
SUPPRESSING = frozenset({"false_positive", "not_applicable"})
MAX_REASON_LENGTH = 4000
MAX_SUPPORTING_EVIDENCE_LENGTH = 16000
MAX_HISTORY_EVENTS = 1000
FINGERPRINT_VERSION = "1"
PUBLICATION_LOCK_TIMEOUT = 15.0

# Observation bookkeeping and derived display data cannot extend or invalidate a review.
# Unknown provenance is retained conservatively: new relevant facts must reopen a decision.
_EXCLUDED_PROVENANCE = frozenset({
    "scan_id", "collected_at", "observed_at", "assessed_at", "generated_at", "saved_at",
    "started_at", "finished_at", "completed_at", "collection_time", "observation_time",
    "timestamp", "raw_ref", "raw_path", "raw_file", "raw_file_path", "artifact_path",
    "confidence", "review", "review_metadata", "explanation", "model", "model_fields",
    "model_output", "model_name", "model_version",
})
_ISO_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _provenance(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _provenance(v) for k, v in value.items()
                if k.casefold() not in _EXCLUDED_PROVENANCE
                and not k.casefold().startswith(("model_", "llm_"))}
    if isinstance(value, list):
        return [_provenance(v) for v in value]
    return value


def review_scope(finding: Finding) -> dict:
    return {key: getattr(finding, key) for key in (
        "host", "source", "rule_id", "rule_version", "group_id", "benchmark", "benchmark_release", "asset_type"
    )}


def _evidence_fingerprint(finding: Finding) -> str:
    """SHA-256 over canonical scope, scanner facts and relevant collection provenance."""
    facts = {key: getattr(finding, key) for key in (
        "status", "severity", "evidence", "title", "description", "check_text", "fix_text",
        "fix_script", "fix_ansible",
    )}
    facts["tags"] = sorted(set(finding.tags))
    facts["references"] = sorted({(r.system, r.id) for r in finding.references})
    facts["collection_provenance"] = _provenance(getattr(finding, "collection_provenance", None) or {})
    return hashlib.sha256(_canonical({"version": FINGERPRINT_VERSION,
                                      "scope": review_scope(finding), "facts": facts})).hexdigest()


evidence_fingerprint = _evidence_fingerprint


def parse_timestamp(value: str) -> datetime:
    """Require an explicit ISO date, time, seconds and UTC offset; never accept epoch numbers."""
    if not isinstance(value, str) or not _ISO_TIMESTAMP.fullmatch(value):
        raise ValueError("expires_at must be an ISO timestamp with seconds and timezone, e.g. 2026-12-01T12:00:00Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # fromisoformat normalizes an offset such as +01:60; reject it explicitly.
        if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
            raise ValueError("invalid offset")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("expires_at is not a valid ISO timestamp") from exc


def _now(value: datetime | str | None = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        return parse_timestamp(value)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must include a timezone")
    return value.astimezone(timezone.utc)


def _text(value: str, name: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"{name} must be text of at most {limit} characters")
    if required and not value.strip():
        raise ValueError(f"{name} is required for every decision and reversal")
    return value.strip()


class ReviewService:
    def __init__(self, ctx: AppContext):
        self.ctx = ctx

    def _path(self, finding: Finding):
        # Custom imported finding IDs are untrusted path components.
        key = finding_key(finding.id)
        return self.ctx.store.root / "finding_reviews" / f"{key}.json"

    def _document(self, finding: Finding) -> dict:
        doc = self.ctx.store.read_json(self._path(finding))
        if doc is None:
            return {"version": 2, "finding_id": finding.id, "revision": 0, "history": [], "invalidations": []}
        if (not isinstance(doc, dict) or doc.get("version") not in {1, 2} or doc.get("finding_id") != finding.id
                or not isinstance(doc.get("history"), list)
                or not isinstance(doc.get("invalidations", []), list)
                or (doc.get("version") == 2 and ("invalidations" not in doc or type(doc.get("revision")) is not int))):
            raise ValueError("invalid review history; refusing to replace it")
        doc.setdefault("invalidations", [])
        events = doc["history"]
        previous_revision = 0
        for event in events:
            if (not isinstance(event, dict) or type(event.get("revision")) is not int
                    or event["revision"] <= previous_revision
                    or event.get("disposition") not in DISPOSITIONS
                    or not isinstance(event.get("scope"), dict)
                    or not isinstance(event.get("evidence_fingerprint"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", event["evidence_fingerprint"])
                    or not event.get("id") or event.get("identity_verified") is not False):
                raise ValueError("invalid review event; refusing to replace history")
            previous_revision = event["revision"]
            parse_timestamp(event.get("reviewed_at"))
            require_human(event.get("reviewed_by"))
            _text(event.get("reason"), "reason", MAX_REASON_LENGTH, required=True)
            _text(event.get("supporting_evidence"), "supporting_evidence", MAX_SUPPORTING_EVIDENCE_LENGTH)
            expiry = event.get("expires_at")
            if expiry is not None:
                parse_timestamp(expiry)
            elif event["disposition"] in SUPPRESSING:
                raise ValueError("invalid review event: suppression requires an expiry")
        seen = set()
        event_by_id = {event["id"]: event for event in events}
        if len(event_by_id) != len(events):
            raise ValueError("duplicate review event identity")
        for invalidation in doc["invalidations"]:
            if not isinstance(invalidation, dict):
                raise ValueError("invalid review invalidation ledger")
            target = event_by_id.get(invalidation.get("review_event_id"))
            receipt = invalidation.get("audit", {})
            source = invalidation.get("source", {})
            if (target is None or target["id"] in seen
                    or type(invalidation.get("revision")) is not int
                    or invalidation["revision"] <= target["revision"]
                    or not isinstance(receipt, dict) or type(receipt.get("seq")) is not int or receipt["seq"] < 1
                    or not isinstance(receipt.get("hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", receipt["hash"])
                    or not isinstance(source, dict) or not isinstance(source.get("scan_id"), str)
                    or not source["scan_id"]):
                raise ValueError("invalid review invalidation provenance")
            parse_timestamp(invalidation.get("recorded_at"))
            seen.add(target["id"])
        revisions = sorted(e["revision"] for e in [*events, *doc["invalidations"]])
        if revisions != list(range(1, len(revisions) + 1)):
            raise ValueError("invalid review revision sequence")
        if doc["version"] == 2 and doc["revision"] != len(revisions):
            raise ValueError("review invalidation ledger is incomplete")
        return doc

    @staticmethod
    def _summary(finding: Finding, doc: dict, now: datetime) -> dict:
        events = doc["history"]
        fingerprint = evidence_fingerprint(finding)
        current = events[-1] if events else None
        reopened = None
        active = False
        disposition = "unreviewed"
        if current is not None:
            invalidated = next((entry for entry in doc["invalidations"]
                                if entry["review_event_id"] == current["id"]), None)
            if invalidated is not None:
                reopened = ("Relevant finding evidence changed; the prior review was durably reopened by scan "
                            + invalidated["source"]["scan_id"] + ". A new review is required.")
            elif current["scope"] != review_scope(finding) or current["evidence_fingerprint"] != fingerprint:
                reopened = "Finding scope, evidence or content changed; a new review is required."
            elif current["expires_at"] is not None and parse_timestamp(current["expires_at"]) <= now:
                reopened = "Review expired; a new review is required."
            else:
                disposition = current["disposition"]
                active = disposition != "unreviewed"
        return {"disposition": disposition, "active": active,
                "suppressed": active and disposition in SUPPRESSING,
                "revision": len(events) + len(doc["invalidations"]), "evidence_fingerprint": fingerprint,
                "current": current, "history_count": len(events), "reopened_reason": reopened,
                "identity_verified": False}

    def summary(self, finding: Finding, *, now=None) -> dict:
        return self._summary(finding, self._document(finding), _now(now))

    def history(self, finding: Finding) -> dict:
        doc = self._document(finding)
        return {**self._summary(finding, doc, _now()), "history": doc["history"]}

    @contextmanager
    def remediation_guard(self, finding: Finding):
        """Hold across final current-review checks, kill guard and apply/runbook issuance.

        Release before verification/rescan publication. A competing save fails immediately.
        This lock is intentionally non-reentrant, including callbacks in the applying thread.
        """
        with finding_lifecycle_lock(self.ctx.store.root, finding.id):
            yield

    def save(self, finding: Finding, *, actor, disposition, reason, supporting_evidence="",
             expires_at=None, expected_revision, evidence_fingerprint) -> dict:
        actor = require_human(actor)
        if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
            raise ValueError("invalid review disposition")
        reason = _text(reason, "reason", MAX_REASON_LENGTH, required=True)
        supporting_evidence = _text(supporting_evidence, "supporting_evidence", MAX_SUPPORTING_EVIDENCE_LENGTH)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a nonnegative integer")
        if not isinstance(evidence_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_fingerprint):
            raise ValueError("evidence_fingerprint must be a SHA-256 hex digest")
        expiry = parse_timestamp(expires_at) if expires_at is not None else None
        if disposition in SUPPRESSING and expiry is None:
            raise ValueError("false_positive and not_applicable require a future expires_at")

        # The filesystem lock serializes review writers for either backend. The backend lock
        # additionally gives SQLite a consistent read/write transaction.
        store = self.ctx.store
        with (finding_lifecycle_lock(store.root, finding.id),
              review_coordination_lock(store.root), store.lock("finding-review-documents")):
            current = next((f for f in store.current_findings() if f.id == finding.id), None)
            if current is None:
                raise KeyError(f"finding {finding.id!r} is not in the current findings")
            doc = self._document(current)
            events = doc["history"]
            now = _now()
            summary = self._summary(current, doc, now)
            if expected_revision != summary["revision"]:
                raise ReviewConflict("review revision changed; reload before saving")
            if evidence_fingerprint != summary["evidence_fingerprint"]:
                raise ReviewConflict("finding evidence changed; reload before saving")
            if expiry is not None and expiry <= now:
                raise ValueError("expires_at must be in the future")
            if len(events) >= MAX_HISTORY_EVENTS:
                raise ValueError(f"review history limit ({MAX_HISTORY_EVENTS}) reached; existing events are preserved")
            if len(events) == MAX_HISTORY_EVENTS - 1 and disposition != "unreviewed":
                raise ValueError("last review history slot is reserved for reversal to unreviewed")
            event = {"id": uuid4().hex, "revision": summary["revision"] + 1,
                     "disposition": disposition, "reason": reason, "supporting_evidence": supporting_evidence,
                     "expires_at": expiry.isoformat() if expiry is not None else None,
                     "reviewed_at": now.isoformat(), "reviewed_by": actor, "identity_verified": False,
                     "scope": review_scope(current), "evidence_fingerprint": summary["evidence_fingerprint"]}
            self.ctx.killswitch.guard("finding.review", actor)
            # Record the complete decision before persistence: an audit failure must never
            # activate an unaudited dismissal. Pending records also expose interrupted writes.
            self.ctx.audit.append("finding.review", actor, {"finding_id": current.id, "event": event},
                                  subject=current.id, outcome="pending")
            self.ctx.killswitch.guard("finding.review", actor)
            # Check again before committing; scan publication uses the same lifecycle locks.
            latest = next((f for f in store.current_findings() if f.id == current.id), None)
            if latest is None or _evidence_fingerprint(latest) != summary["evidence_fingerprint"]:
                self.ctx.audit.append("finding.review", actor, {"event_id": event["id"], "reason": "finding changed"},
                                      subject=current.id, outcome="rejected")
                raise ReviewConflict("finding evidence changed; reload before saving")
            updated = dict(doc, version=2, revision=event["revision"], history=[*events, event])
            store.write_json(self._path(current), updated)
        self.ctx.audit.append("finding.review", actor, {"event_id": event["id"], "revision": event["revision"]},
                              subject=current.id, outcome="ok")
        return {**self._summary(current, updated, now), "history": updated["history"]}


def _projected_observations(store, scan_id: str, document: dict, kind: str):
    """Share current-view precedence so publication locks cover the same observations."""
    return store.projected_observations(scan_id, document, kind)


def save_observation_document(store, scan_id: str, document: dict, *, kind: str) -> None:
    """Publish with bounded retry, releasing all coordination before every retry.

    Ordinary concurrent scan workers serialize instead of receiving ReviewConflict. Neither
    a SQLite transaction nor other finding locks are held while waiting for apply to finish.
    Reentrant publication from inside a review/apply callback must fail immediately.
    """
    deadline = time.monotonic() + PUBLICATION_LOCK_TIMEOUT
    while True:
        try:
            _publish_observation_once(store, scan_id, document, kind=kind)
            return
        except LifecycleReentry:
            raise
        except ReviewConflict as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError("finding publication busy; retry after the active operation finishes") from exc
            time.sleep(0.01)


def _publish_observation_once(store, scan_id: str, document: dict, *, kind: str) -> None:
    path = store.scan_dir(scan_id) / ("findings.json" if kind == "findings" else "run.json")
    with review_coordination_lock(store.root), ExitStack() as stack:
        service = ReviewService(SimpleNamespace(store=store))
        reviewed = []
        for review_path in store.list_json(store.root / "finding_reviews"):
            raw = store.read_json(review_path)
            if not isinstance(raw, dict) or not isinstance(raw.get("finding_id"), str):
                raise ValueError("invalid review document; refusing observation publication")
            identity = SimpleNamespace(id=raw["finding_id"])
            doc = service._document(identity)
            if not doc["history"]:
                continue
            event = doc["history"][-1]
            if event["disposition"] == "unreviewed" or any(
                    entry["review_event_id"] == event["id"] for entry in doc["invalidations"]):
                continue
            reviewed.append((identity, doc, event))
        prior, _ = _projected_observations(store, "", {}, "current")
        projected, can_remove = _projected_observations(store, scan_id, document, kind)
        prior_fingerprints = {fid: evidence_fingerprint(finding) for fid, finding in prior.items()}
        next_fingerprints = {fid: evidence_fingerprint(finding) for fid, finding in projected.items()}
        # Policy evidence can change even when nobody has reviewed the finding. Protect
        # every changed observation, addition and removal against final checks + apply.
        changed_ids = {fid for fid in prior.keys() | projected.keys()
                       if prior_fingerprints.get(fid) != next_fingerprints.get(fid)}
        changed = []
        for identity, doc, event in reviewed:
            finding = projected.get(identity.id)
            if finding is None and not can_remove:
                continue
            fingerprint = evidence_fingerprint(finding) if finding is not None else None
            if fingerprint != event["evidence_fingerprint"]:
                changed.append((identity, doc, event, fingerprint))
                changed_ids.add(identity.id)
        # Acquire in a stable order. Contention unwinds all locks before publication retries;
        # unchanged or unrelated observations never require the held finding's lock.
        for finding_id in sorted(changed_ids):
            stack.enter_context(finding_lifecycle_lock(store.root, finding_id))
        if not changed:
            # No review ledger needs updating, but all changed observation locks remain held
            # through the write even when there are no review documents at all.
            store.write_json(path, document)
            return
        with store.lock("finding-review-documents"):
            source_run = document if kind == "run" else (store.load_scan_run(scan_id) or {})
            publication_hash = hashlib.sha256(_canonical(document)).hexdigest()
            audit = AuditLog(store.audit_log)
            for identity, doc, event, fingerprint in changed:
                invalidation = {"id": uuid4().hex, "revision": len(doc["history"]) + len(doc["invalidations"]) + 1,
                                "review_event_id": event["id"], "recorded_at": _now().isoformat(),
                                "previous_fingerprint": event["evidence_fingerprint"],
                                "observed_fingerprint": fingerprint,
                                "source": {"scan_id": scan_id, "publication": kind,
                                           "started_at": source_run.get("started_at"),
                                           "trigger": source_run.get("trigger"),
                                           "requested_by": source_run.get("requested_by"),
                                           "document_sha256": publication_hash}}
                receipt = audit.append("finding.review_invalidated", "system", invalidation,
                                       subject=identity.id, outcome="pending")
                invalidation["audit"] = {"seq": receipt["seq"], "hash": receipt["hash"]}
                updated = dict(doc, version=2, revision=invalidation["revision"],
                               invalidations=[*doc["invalidations"], invalidation])
                store.write_json(service._path(identity), updated)
            store.write_json(path, document)
