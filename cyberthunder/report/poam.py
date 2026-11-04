"""Plan of Action and Milestones as CSV, one row per open finding (plus findings whose fix is verified)."""
from __future__ import annotations

import csv
import io
from datetime import date, timedelta
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import ProposalState
from cyberthunder.findings.schema import Severity
from cyberthunder.report.onepager import latest_proposals, resolve_scan

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

COLUMNS = ["Host", "Asset Type", "STIG ID", "Rule ID", "Title", "Severity (CAT)", "Status", "Finding ID",
           "Proposed Fix", "Proposal State", "Source", "Citations", "Milestone", "Resources Required",
           "Scheduled Completion", "Comments"]

# Days allowed to close a finding, by severity. A planning default, not policy: the owner edits the CSV.
SCHEDULE_DAYS = {Severity.HIGH: 30, Severity.MEDIUM: 90, Severity.LOW: 180}

_STATUS = {
    ProposalState.VERIFIED: "Completed",
    ProposalState.APPROVED: "Ongoing", ProposalState.APPLYING: "Ongoing", ProposalState.APPLIED: "Ongoing",
}
_MILESTONE = {
    ProposalState.PROPOSED: "Approve or deny proposal",
    ProposalState.APPROVED: "Apply approved fix and verify",
    ProposalState.VERIFIED: "Closed: fix verified",
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
    for f in sorted(findings, key=lambda f: (-f.severity.rank, f.host, f.rule_version or f.rule_id)):
        p = props.get(f.id)
        if not f.is_open and not (p and p.state == ProposalState.VERIFIED):
            continue
        if p is None:
            status, fix, pstate = "Open", f.fix_ref or "", "none"
            milestone = "Propose, approve and apply library fix" if f.fix_ref else "Determine and approve a remediation"
        else:
            status, fix, pstate = _STATUS.get(p.state, "Open"), p.fix_ref, p.state.value
            milestone = _MILESTONE.get(p.state, "Apply and verify fix")
        due = "" if status == "Completed" else (today + timedelta(days=SCHEDULE_DAYS.get(f.severity, 180))).isoformat()
        comments = f"Scan {sid}"
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
        })
    return rows


def poam_csv(ctx: "AppContext", scan_id: str | None = None) -> str:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\r\n")
    w.writeheader()
    w.writerows(poam_rows(ctx, scan_id))
    return buf.getvalue()
