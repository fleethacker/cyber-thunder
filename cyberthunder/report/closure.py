"""Conservative verification timing for reports, independent of API views."""
from __future__ import annotations

from datetime import datetime, timezone
import re

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.schema import Finding

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")


def state_time(proposal: Proposal, state: ProposalState) -> str | None:
    """Read the last matching event; missing timestamps never fall back to other events."""
    if not isinstance(proposal.history, list):
        return None
    for event in reversed(proposal.history):
        if isinstance(event, dict) and event.get("state") == state.value:
            value = event.get("ts")
            return value if isinstance(value, str) else None
    return None


def _timestamp(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def verified_closure(finding: Finding, proposal: Proposal | None) -> bool:
    """Only a matching verified change at/after the raw-open observation closes it.

    Equal timestamps are accepted because stored observation/event times have second precision.
    Missing, malformed or timezone-free times do not establish closure. Approval and creation
    timestamps cannot stand in for verification. This never mutates the scanner observation.
    """
    if (not finding.is_open or proposal is None or proposal.state != ProposalState.VERIFIED
            or proposal.finding_id != finding.id or proposal.host != finding.host):
        return False
    verified = _timestamp(state_time(proposal, ProposalState.VERIFIED))
    observed = _timestamp(finding.collected_at)
    return verified is not None and observed is not None and verified >= observed
