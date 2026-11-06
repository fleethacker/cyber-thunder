"""Plan of Action and Milestones, including suppressed and incomplete observations.

Open findings of the latest finished discovery sweep (an unknown device, a new listener) are rows too, with
source `discovery`: they are not in any scan, but someone has to own and close them.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import date, timedelta
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import ProposalState
from cyberthunder.report import access, approvals
from cyberthunder.findings.schema import Severity, Status
from cyberthunder.report.assurance import build_assurance
from cyberthunder.report.onepager import discovery_open, latest_proposals, resolve_scan

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

COLUMNS = ["Host", "Asset Type", "STIG ID", "Rule ID", "Title", "Severity (CAT)", "Status", "Finding ID",
           "Proposed Fix", "Proposal State", "Source", "Citations", "Milestone", "Resources Required",
           "Scheduled Completion", "Comments", "Scanner Status", "Scanner Evidence",
           "Confidence Grade", "Confidence Reason", "Review Disposition", "Review Active", "Review Suppressed",
           "Last Review Disposition", "Reviewed By", "Review Reason", "Review Supporting Evidence",
           "Review Expires At", "Reviewed At", "Review Reopened Reason", "Review Evidence Fingerprint",
           "Reviewer Identity", "Proposed By", "Proposer Identity", "Approval Quorum",
           "Approval Validation", "Approval Evidence"]

# Days allowed to close a finding, by severity. A planning default, not policy: the owner edits the CSV.
SCHEDULE_DAYS = {Severity.HIGH: 30, Severity.MEDIUM: 90, Severity.LOW: 180}

_STATUS = {
    ProposalState.APPROVED: "Ongoing", ProposalState.APPLYING: "Ongoing", ProposalState.APPLIED: "Ongoing",
}
_MILESTONE = {
    ProposalState.PROPOSED: "Approve or deny proposal",
    ProposalState.APPROVED: "Revalidate approvals and authorization before apply",
    ProposalState.ROLLED_BACK: "Investigate rollback, re-propose",
    ProposalState.FAILED: "Investigate failed apply",
    ProposalState.DENIED: "Denied: decide on risk acceptance or an alternative",
    ProposalState.CANCELLED: "Cancelled: create a new proposal before requesting approval",
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
    approval_evidence = {}
    for proposal in access.proposals(ctx):
        approval_evidence.setdefault((proposal.finding_id, proposal.host), []).append(approvals.evidence(ctx, proposal))
    today = date.today()
    rows = []
    disc = [f for f in discovery_open(ctx) if f.id not in {x.id for x in findings}]
    findings = sorted([*findings, *disc], key=lambda f: (-f.severity.rank, f.host, f.rule_version or f.rule_id))
    assurance = build_assurance(ctx, findings)
    lifecycle = access.lifecycle(ctx)
    for f, assessed in zip(findings, assurance["findings"]):
        current = lifecycle.assess(f)
        review = assessed["review"]
        event = review["current"] or {}
        p = props.get(f.id)
        incomplete = current.finding.status in (Status.NOT_REVIEWED, Status.ERROR)
        if not f.is_open and not incomplete and not review["suppressed"] and not (p and p.state == ProposalState.VERIFIED):
            continue
        if p is None:
            status, fix, pstate = "Open", f.fix_ref or "", "none"
            milestone = "Propose, approve and apply library fix" if f.fix_ref else "Determine and approve a remediation"
        else:
            status, fix, pstate = _STATUS.get(p.state, "Open"), p.fix_ref, p.state.value
            milestone = _MILESTONE.get(p.state, "Apply and verify fix")
            if p.state == ProposalState.PROPOSED and getattr(p, "approvals", None):
                milestone = "Complete the independent approval quorum or deny the proposal"
            if p.state == ProposalState.VERIFIED:
                if current.remediated:
                    status, milestone = "Completed", "Closed: fix verified"
                elif current.finding.status == Status.NOT_A_FINDING:
                    status, milestone = "Completed", "Scanner reports not_a_finding"
                else:
                    milestone = "Reassess observation; prior verification does not establish closure"
        if review["suppressed"]:
            status = "Suppressed (review)"
            milestone = "Reassess before review expiry; suppression is not remediation"
        elif incomplete:
            status = "Needs investigation"
            milestone = "Resolve scanner error and rerun check" if f.status == Status.ERROR else "Run or complete the missing check"
        if current.needs_rescan:
            milestone = "Rescan after rollback; prior scanner evidence does not establish current compliance"
        due = "" if status == "Completed" else (today + timedelta(days=SCHEDULE_DAYS.get(f.severity, 180))).isoformat()
        comments = "Discovery sweep" if f.source == "discovery" else f"Scan {sid}"
        recorded = approval_evidence.get((f.id, f.host), [])
        approval = next((item for item in recorded if p and item["proposal_id"] == p.id), None)
        for item in recorded:
            comments += "; " + item["text"]
        if current.rollback:
            comments += f"; rollback attempt {current.rollback['proposal_id']} ok={current.rollback['ok']}"
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
            "Review Evidence Fingerprint": review["evidence_fingerprint"],
            "Reviewer Identity": (assessed["reviewer_identity"]["text"] if review["identity_verified"]
                                  else assessed["identity_label"]),
            "Proposed By": (approval["proposed_by"] or "") if approval else "",
            "Proposer Identity": approval["proposer_identity"]["text"] if approval else "",
            "Approval Quorum": "\n".join(f"{item['proposal_id']}: {item['summary']}" for item in recorded),
            "Approval Validation": "\n".join(f"{item['proposal_id']}: {item['validation_text']}" for item in recorded),
            "Approval Evidence": json.dumps([json.loads(item["recorded_json"]) for item in recorded],
                                            ensure_ascii=False, sort_keys=True) if recorded else "",
        })
    return rows


def poam_csv(ctx: "AppContext", scan_id: str | None = None) -> str:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows({key: _csv_cell(value) for key, value in row.items()} for row in poam_rows(ctx, scan_id))
    return buf.getvalue()


def _csv_cell(value):
    """Quote formula-like cells as spreadsheet text, including prefixed whitespace/control characters."""
    if not isinstance(value, str):
        return value
    probe = value
    while probe and (probe[0].isspace() or ord(probe[0]) < 32 or probe[0] == "\ufeff"):
        probe = probe[1:]
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value
