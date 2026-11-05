"""Current finding interpretation over immutable scanner observations and change history."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import re

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.schema import Finding, Status
from cyberthunder.remediation import snapshot

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")
_TERMINAL = {"denied", "cancelled", "verified", "rolled_back", "failed"}


def timestamp(value) -> datetime | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def state_time(proposal: Proposal, state: ProposalState) -> str | None:
    if not isinstance(proposal.history, list):
        return None
    for event in reversed(proposal.history):
        if isinstance(event, dict) and event.get("state") == state.value:
            value = event.get("ts")
            return value if isinstance(value, str) else None
    return None


def verified_closure(finding: Finding, proposal: Proposal | None) -> bool:
    if (not finding.is_open or proposal is None or proposal.state != ProposalState.VERIFIED
            or proposal.finding_id != finding.id or proposal.host != finding.host):
        return False
    verified = timestamp(state_time(proposal, ProposalState.VERIFIED))
    observed = timestamp(finding.collected_at)
    return verified is not None and observed is not None and verified >= observed


@dataclass(frozen=True)
class CurrentFinding:
    finding: Finding
    remediated: dict | None = None
    rollback: dict | None = None
    needs_rescan: bool = False


class CurrentFindings:
    """One read of proposals/results per view; no detector output is written or invented.

    All attempts matter, including an old proposal rolled back after a newer verification.
    Failed restores may have changed part of the host and therefore also invalidate old passes.
    Proposal state still distinguishes successful rollback from a failed attempt.
    """

    def __init__(self, proposals=(), results=None):
        self.proposals = {}
        self.rollbacks = {}
        for p in proposals:
            key = (p.finding_id, p.host)
            self.proposals.setdefault(key, []).append(p)
            result = (results or {}).get(p.id)
            if isinstance(result, dict):
                event = {"proposal_id": p.id, "finished_at": result.get("finished_at"),
                         "ok": result.get("ok") is True}
            elif p.state == ProposalState.ROLLED_BACK:
                event = {"proposal_id": p.id, "finished_at": state_time(p, ProposalState.ROLLED_BACK), "ok": True}
            else:
                continue
            self.rollbacks.setdefault(key, []).append(event)

    @classmethod
    def for_context(cls, ctx):
        proposals = list(ctx.gate.list())
        records = list(ctx.audit.records())
        completed = [(r.get("subject"), r.get("details", {})) for r in records
                     if r.get("action") == "remediation.rollback"]
        completed_by_proposal = dict(completed)
        completed_attempts = {(pid, result.get("attempt_id"), result.get("finding_id"), result.get("target_id"))
                              for pid, result in completed if result.get("attempt_id")}
        saved = {}

        def saved_result(pid):
            # Read only: rendering must not create snapshot directories.
            if pid in saved:
                return saved[pid]
            try:
                result = snapshot.load_result(ctx.store.snapshots_dir / pid, "rollback")
            except (OSError, ValueError):
                # An unreadable attempt cannot establish a current pass or rollback success.
                result = {"ok": False, "finished_at": None}
            saved[pid] = result if isinstance(result, dict) or result is None else {"ok": False, "finished_at": None}
            return saved[pid]

        results = {}
        for p in proposals:
            result = completed_by_proposal.get(p.id) or saved_result(p.id)
            if result is not None:
                results[p.id] = result
        current = cls(proposals, results)

        def add_event(pid, result, *, uncertain=False):
            key = (result.get("finding_id"), result.get("target_id"))
            if not all(isinstance(value, str) and value for value in key):
                return
            event = {"proposal_id": pid, "finished_at": None if uncertain else result.get("finished_at"),
                     "ok": None if uncertain else result.get("ok") is True}
            if uncertain:
                event.update(uncertain=True, attempt_id=result.get("attempt_id"), started_at=result.get("started_at"))
            if event not in current.rollbacks.get(key, []):
                current.rollbacks.setdefault(key, []).append(event)

        # The audit result survives a lost result file or proposal row. It is durable change
        # evidence in its own right, not a reason to rewrite the original scan observation.
        for pid, result in completed:
            add_event(pid, result)
        for record in records:
            if record.get("action") != "remediation.rollback_mutation":
                continue
            result = record.get("details", {})
            pid, attempt = record.get("subject"), result.get("attempt_id")
            if attempt and (pid, attempt, result.get("finding_id"), result.get("target_id")) in completed_attempts:
                continue
            receipt = saved_result(pid) if isinstance(pid, str) else None
            if (receipt and attempt and receipt.get("attempt_id") == attempt
                    and all(receipt.get(k) == result.get(k) for k in ("finding_id", "target_id"))):
                add_event(pid, receipt)
            else:
                add_event(pid, result, uncertain=True)
        return current

    def assess(self, finding: Finding) -> CurrentFinding:
        key = (finding.id, finding.host)
        rollbacks = self.rollbacks.get(key, [])
        # Unknown ordering is conservative; equal second-resolution times cannot prove freshness.
        pending = []
        provenance = finding.collection_provenance or {}
        observed = timestamp(provenance.get("observed_at", finding.collected_at))
        collected = timestamp(finding.collected_at)
        for event in rollbacks:
            at = timestamp(event["finished_at"])
            if at is None or observed is None or collected is None or min(observed, collected) <= at:
                pending.append(event)
        rollback = max(pending or rollbacks, key=lambda r: (
            timestamp(r["finished_at"]) is None, timestamp(r["finished_at"]) or datetime.min.replace(tzinfo=timezone.utc),
            bool(r.get("uncertain"))
        ), default=None)
        # A subsequent verified fix can close an older open observation, but cannot reinstate a
        # pre-rollback scanner pass. That requires fresh scanner evidence.
        proposals = self.proposals.get(key, [])
        live = [p for p in proposals if p.state.value not in _TERMINAL]
        p = (live or proposals or [None])[-1]
        if p is not None:
            verified = timestamp(state_time(p, ProposalState.VERIFIED))
            if verified_closure(finding, p) and all(
                timestamp(r["finished_at"]) is not None and verified > timestamp(r["finished_at"])
                for r in rollbacks
            ):
                return CurrentFinding(replace(finding, status=Status.NOT_A_FINDING),
                                      {"proposal_id": p.id, "verified_at": state_time(p, ProposalState.VERIFIED),
                                       "scan_status": finding.status.value}, rollback)
        current = finding
        if pending and finding.status in (Status.NOT_A_FINDING, Status.NOT_APPLICABLE):
            current = replace(finding, status=Status.NOT_REVIEWED)
        return CurrentFinding(current, rollback=rollback, needs_rescan=bool(pending))


def policy_block_reason(ctx, finding: Finding) -> str | None:
    """Assess the caller's selected observation without falling back to historical scans."""
    if CurrentFindings.for_context(ctx).assess(finding).needs_rescan:
        return "rollback invalidated prior evidence; rescan before standing approval"
    return None
