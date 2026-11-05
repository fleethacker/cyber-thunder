"""Read-only assurance views shared by commander and POA&M reports.

Review decisions are evaluated against each supplied observation, including historical scans.
They never replace scanner status or constitute a verified remediation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cyberthunder.findings.schema import Finding, Status

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

IDENTITY_LABEL = "Unverified (self-asserted)"


def build_assurance(ctx: "AppContext", findings: list[Finding]) -> dict:
    """Assess without mutating observations or reading review files outside the service.

    Confirmed, unreviewed, suppressed and needs_investigation count raw-open observations only.
    Scanner passes, unchecked results and errors are counted independently of human review.
    """
    from cyberthunder.findings.confidence import assess_for_context
    from cyberthunder.findings.review import ReviewService

    now = datetime.now(timezone.utc)
    reviews = ReviewService(ctx)
    rows = []
    counts = dict.fromkeys(("total", "raw_open", "confirmed", "unreviewed", "suppressed",
                            "needs_investigation", "scanner_pass", "scanner_not_applicable",
                            "scanner_not_reviewed", "scanner_error"), 0)
    status_counts = {s.value: 0 for s in Status}
    for finding in findings:
        confidence = assess_for_context(ctx, finding, now=now)
        review = reviews.summary(finding, now=now)
        status_counts[finding.status.value] += 1
        if finding.is_open:
            counts["raw_open"] += 1
            if review["suppressed"]:
                counts["suppressed"] += 1
            elif review["disposition"] == "unreviewed":
                counts["unreviewed"] += 1
            elif review["active"] and review["disposition"] in ("confirmed", "needs_investigation"):
                counts[review["disposition"]] += 1
        rows.append({
            "id": finding.id, "host": finding.host, "title": finding.title,
            "source": finding.source, "rule_id": finding.rule_id,
            "severity": finding.severity.value, "status": finding.status.value,
            "evidence": finding.evidence or "", "citations": finding.citations,
            "confidence": confidence, "review": review, "identity_label": IDENTITY_LABEL,
        })
    counts.update(total=len(findings), scanner_pass=status_counts[Status.NOT_A_FINDING.value],
                  scanner_not_applicable=status_counts[Status.NOT_APPLICABLE.value],
                  scanner_not_reviewed=status_counts[Status.NOT_REVIEWED.value],
                  scanner_error=status_counts[Status.ERROR.value])
    return {"assessed_at": now.isoformat(timespec="seconds"), "counts": counts,
            "by_status": status_counts, "findings": rows, "identity_label": IDENTITY_LABEL}
