"""Portable approval receipts, separate from present permission to apply a change."""
from copy import deepcopy
import json

from cyberthunder.control import separation
from cyberthunder.findings.schema import utcnow
from cyberthunder.report import access
from cyberthunder.report.identity import attribution

LIMITATION = ("Recorded identity is attribution at decision time. Current permission to apply is not "
              "established by this report; the gate must recheck authorization and assessments before application.")


def _disputed_identity(identity):
    if not identity["verified"]:
        return identity
    label = ("Recorded identity claim; receipt validation not established; "
             f"iss={identity['issuer']}; sub={identity['subject']}")
    return {**identity, "verified": False, "recorded_verified": True, "label": label,
            "text": f"{identity['display_name']}; {label}; audit actor={identity['actor']}"}


def evidence(ctx, proposal) -> dict:
    """Retain every receipt and check its audit/source association without executing a gate transition.

    Ownership and audit access failures propagate. Validation failures only qualify
    the retained evidence; they must never upgrade it into a current authorization.
    ``ctx=None`` supports legacy, purely local checklist comment formatting.
    """
    proposal = deepcopy(proposal)
    if ctx is not None:
        access.artifact(ctx, getattr(proposal, "authorization_scope", None), targets=[proposal.host])
        access.audit(ctx)
    state = getattr(proposal.state, "value", proposal.state)
    recorded = {"proposal_id": proposal.id, "host": proposal.host, "state": state}
    for name in ("proposed_by", "proposed_principal", "required_approvals", "approval_requirements",
                 "approvals", "decided_by", "decided_principal", "decided_at", "decision_note"):
        recorded[name] = deepcopy(getattr(proposal, name, [] if name == "approvals" else None))
    required = recorded["required_approvals"]
    receipts = recorded["approvals"]
    rows = []
    for vote in receipts if isinstance(receipts, list) else []:
        vote = vote if isinstance(vote, dict) else {}
        rows.append({"id": vote.get("id"), "approved_at": vote.get("approved_at"), "note": vote.get("note"),
                     "identity": attribution(vote.get("actor"), vote.get("principal"))})
    count = len(rows)
    valid_count = type(required) is int and required > 0 and isinstance(receipts, list)
    quorum = ("partial" if count < required else "recorded_complete" if count == required else "invalid_count"
              ) if valid_count else "not_recorded"
    quorum_text = (f"{count}/{required} recorded approvals ({quorum.replace('_', ' ')})" if valid_count
                   else f"{count} recorded approval receipt(s); required quorum not recorded")
    validation = {"status": "not_checked", "checked_at": None,
                  "scope": "receipt audit, proposal lifecycle and current finding/fix requirements"}
    if recorded["approval_requirements"] is None:
        validation["status"] = "legacy_unavailable"
    elif ctx is not None:
        validation["checked_at"] = utcnow()
        try:
            separation.validate(ctx.gate, proposal)
        except (PermissionError, OSError, ValueError, TypeError, KeyError, AttributeError):
            # Do not export raw validator errors containing paths or unrelated source details.
            validation["status"] = "not_established"
        else:
            validation["status"] = "checked"
    if ctx is not None:
        # A validator's PermissionError may describe a source ownership change rather
        # than a disputed vote. Such a change must not downgrade into readable evidence.
        access.artifact(ctx, getattr(proposal, "authorization_scope", None), targets=[proposal.host])
        access.audit(ctx)
    proposer = attribution(recorded["proposed_by"], recorded["proposed_principal"], human=False)
    decision = attribution(recorded["decided_by"], recorded["decided_principal"])
    if validation["status"] == "not_established":
        proposer, decision = _disputed_identity(proposer), _disputed_identity(decision)
        for row in rows:
            row["identity"] = _disputed_identity(row["identity"])
    approvers = "\n".join(
        f"Receipt {row['id'] or 'not recorded'}: {row['identity']['text']}; "
        f"at {row['approved_at'] or 'not recorded'}; note: {row['note'] or 'none'}" for row in rows)
    if not rows:
        approvers = (f"Legacy decision ({state}): {decision['text']}" if recorded["decided_by"]
                     else "No approval receipts recorded")
    summary = f"{quorum_text}; recorded state: {state}"
    validation_text = {"checked": "Receipt audit, lifecycle and current finding/fix requirements checked at export",
                       "not_established": "Receipt audit, lifecycle or current finding/fix requirements could not be established",
                       "legacy_unavailable": "Legacy decision; separated approval evidence unavailable",
                       "not_checked": "Receipt audit, lifecycle and current finding/fix requirements not checked"}[validation["status"]]
    if validation["checked_at"]:
        validation_text += f" ({validation['checked_at']})"
    text = (f"Proposal {proposal.id}: {summary}. Proposer: {proposer['text']}. "
            f"Recorded decisions: {approvers}. {validation_text}. {LIMITATION}")
    return {**recorded, "proposer_identity": proposer, "approval_identities": rows,
            "recorded_count": count, "quorum_status": quorum,
            "quorum_evidence_checked": validation["status"] == "checked" and quorum == "recorded_complete",
            "validation": validation, "validation_text": validation_text,
            "current_apply_authorization": "not_established_by_report", "limitation": LIMITATION,
            "summary": summary, "approver_text": approvers, "text": text,
            "recorded_json": json.dumps(recorded, ensure_ascii=False, sort_keys=True)}
