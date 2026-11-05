"""Plan of Action and Milestones, including suppressed and incomplete observations.

Open findings of the latest finished discovery sweep (an unknown device, a new listener) are rows too, with
source `discovery`: they are not in any scan, but someone has to own and close them.
"""
from __future__ import annotations

import csv
import io
from datetime import date, timedelta
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import ProposalState
from cyberthunder.findings.schema import Severity, Status
from cyberthunder.report.assurance import build_assurance
from cyberthunder.report.closure import verified_closure
from cyberthunder.report.onepager import discovery_open, latest_proposals, resolve_scan

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

COLUMNS = ["Host", "Asset Type", "STIG ID", "Rule ID", "Title", "Severity (CAT)", "Status", "Finding ID",
           "Proposed Fix", "Proposal State", "Source", "Citations", "Milestone", "Resources Required",
           "Scheduled Completion", "Comments", "Scanner Status", "Scanner Evidence",
           "Confidence Grade", "Confidence Reason", "Review Disposition", "Review Active", "Review Suppressed",
           "Last Review Disposition", "Reviewed By", "Review Reason", "Review Supporting Evidence",
           "Review Expires At", "Reviewed At", "Review Reopened Reason", "Review Evidence Fingerprint",
           "Reviewer Identity"]

# Days allowed to close a finding, by severity. A planning default, not policy: the owner edits the CSV.
SCHEDULE_DAYS = {Severity.HIGH: 30, Severity.MEDIUM: 90, Severity.LOW: 180}

_STATUS = {
    ProposalState.APPROVED: "Ongoing", ProposalState.APPLYING: "Ongoing", ProposalState.APPLIED: "Ongoing",
}
_MILESTONE = {
    ProposalState.PROPOSED: "Approve or deny proposal",
    ProposalState.APPROVED: "Apply approved fix and verify",
    ProposalState.ROLLED_BACK: "Investigate rollback, re-propose",
    ProposalState.FAILED: "Investigate failed apply",
    ProposalState.DENIED: "Denied: decide on risk acceptance or an alternative",
}


def _resources(ctx: "AppContext", fix_ref: str | None) -> str:
    base = "Approver (IT Sailor) time"
    if not fix_ref:
        return base + "; manual remediation"
    entry = ctx.library.get(fix_ref)
    if entry is None:
        return base
    extra = [f"{entry.disruption} disruption"]
    if entry.reboot:
        extra.append("reboot window")
    if entry.restarts_services:
        extra.append("restart " + "/".join(entry.restarts_services))
    return "; ".join([base, *extra])


def poam_rows(ctx: "AppContext", scan_id: str | None = None) -> list[dict]:
    sid, _run, findings = resolve_scan(ctx, scan_id)
    props = latest_proposals(ctx)
    today = date.today()
    rows = []
    disc = [f for f in discovery_open(ctx) if f.id not in {x.id for x in findings}]
    findings = sorted([*findings, *disc], key=lambda f: (-f.severity.rank, f.host, f.rule_version or f.rule_id))
    assurance = build_assurance(ctx, findings)
    for f, assessed in zip(findings, assurance["findings"]):
        review = assessed["review"]
        event = review["current"] or {}
        p = props.get(f.id)
        incomplete = f.status in (Status.NOT_REVIEWED, Status.ERROR)
        if not f.is_open and not incomplete and not review["suppressed"] and not (p and p.state == ProposalState.VERIFIED):
            continue
        if p is None:
            status, fix, pstate = "Open", f.fix_ref or "", "none"
            milestone = "Propose, approve and apply library fix" if f.fix_ref else "Determine and approve a remediation"
        else:
            status, fix, pstate = _STATUS.get(p.state, "Open"), p.fix_ref, p.state.value
            milestone = _MILESTONE.get(p.state, "Apply and verify fix")
            if p.state == ProposalState.VERIFIED:
                if verified_closure(f, p):
                    status, milestone = "Completed", "Closed: fix verified"
                elif f.status == Status.NOT_A_FINDING:
                    status, milestone = "Completed", "Scanner reports not_a_finding"
                else:
                    milestone = "Reassess observation; prior verification does not establish closure"
        if review["suppressed"]:
            status = "Suppressed (review)"
            milestone = "Reassess before review expiry; suppression is not remediation"
        elif incomplete:
            status = "Needs investigation"
            milestone = "Resolve scanner error and rerun check" if f.status == Status.ERROR else "Run or complete the missing check"
        due = "" if status == "Completed" else (today + timedelta(days=SCHEDULE_DAYS.get(f.severity, 180))).isoformat()
        comments = "Discovery sweep" if f.source == "discovery" else f"Scan {sid}"
        if p and p.decided_by:
            comments += f"; {p.state.value} by {p.decided_by}"
        if not f.rule_version:
            comments += "; no STIG ID, see citations"
        rows.append({
            "Host": f.host, "Asset Type": f.asset_type or "", "STIG ID": f.rule_version or "",
            "Rule ID": f.rule_id, "Title": f.title,
            "Severity (CAT)": f.severity.cat if f.severity.cat != "-" else f.severity.value,
            "Status": status, "Finding ID": f.id, "Proposed Fix": fix, "Proposal State": pstate,
            "Source": f.source, "Citations": "; ".join(f.citations), "Milestone": milestone,
            "Resources Required": _resources(ctx, fix or None), "Scheduled Completion": due, "Comments": comments,
            "Scanner Status": f.status.value, "Scanner Evidence": f.evidence or "",
            "Confidence Grade": assessed["confidence"]["grade"], "Confidence Reason": assessed["confidence"]["reason"],
            "Review Disposition": review["disposition"], "Review Active": "yes" if review["active"] else "no",
            "Review Suppressed": "yes" if review["suppressed"] else "no",
            "Last Review Disposition": event.get("disposition", ""), "Reviewed By": event.get("reviewed_by", ""),
            "Review Reason": event.get("reason", ""), "Review Supporting Evidence": event.get("supporting_evidence", ""),
            "Review Expires At": event.get("expires_at") or "", "Reviewed At": event.get("reviewed_at", ""),
            "Review Reopened Reason": review["reopened_reason"] or "",
            "Review Evidence Fingerprint": review["evidence_fingerprint"], "Reviewer Identity": assessed["identity_label"],
        })
    return rows


def poam_csv(ctx: "AppContext", scan_id: str | None = None) -> str:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(poam_rows(ctx, scan_id))
    return buf.getvalue()
