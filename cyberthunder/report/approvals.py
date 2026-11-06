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


def _association_text(association):
    if not isinstance(association, dict) or not isinstance(association.get("source"), dict):
        return "No recorded person association"
    source = association["source"]
    return (f"Recorded person association: {source.get('namespace', '?')}/{association.get('person_id', '?')}; "
            f"iss={association.get('issuer', '?')}; sub={association.get('subject', '?')}; "
            f"policy v{source.get('policy_version', '?')}, association v{source.get('version', '?')}, "
            f"revision {source.get('revision', '?')}; policy SHA-256={source.get('policy_sha256', '?')}")


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
                     "identity": attribution(vote.get("actor"), vote.get("principal")),
                     "person_association": deepcopy(vote.get("person_association")),
                     "association_text": _association_text(vote.get("person_association"))})
    requirements = recorded["approval_requirements"] if isinstance(recorded["approval_requirements"], dict) else {}
    basis = ("mapped_person" if separation.person_bound(requirements) else
             "account" if requirements.get("version") == 1 and requirements.get("ruleset") == separation.RULESET
             else "unavailable")
    basis_text = {"mapped_person": "Mapped-person quorum (protected association)",
                  "account": "Account quorum; distinct people are not established",
                  "unavailable": "Quorum identity basis unavailable"}[basis]
    if requirements.get("mode") == "unverified_dev":
        basis_text = "Unverified local account quorum; typed names do not authenticate people"
    proposer_association = _association_text(requirements.get("proposer_association"))
    count = len(rows)
    valid_count = type(required) is int and required > 0 and isinstance(receipts, list)
    quorum = ("partial" if count < required else "recorded_complete" if count == required else "invalid_count"
              ) if valid_count else "not_recorded"
    quorum_text = (f"{count}/{required} recorded approvals ({quorum.replace('_', ' ')})" if valid_count
                   else f"{count} recorded approval receipt(s); required quorum not recorded")
    validation = {"status": "not_checked", "checked_at": None,
                  "scope": "receipt audit, proposal lifecycle, current finding/fix and association policy; no apply authorization"}
    historical = {"status": "not_checked", "checked_at": None,
                  "scope": "audited creation, lifecycle, payload and recorded account/person receipts only"}
    if recorded["approval_requirements"] is None:
        historical["status"] = validation["status"] = "legacy_unavailable"
    elif ctx is not None:
        historical["checked_at"] = validation["checked_at"] = utcnow()
        try:
            separation.validate_history(ctx.gate, proposal)
        except (PermissionError, OSError, ValueError, TypeError, KeyError, AttributeError):
            historical["status"] = "not_established"
        else:
            historical["status"] = "checked"
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
    if historical["status"] == "not_established":
        proposer, decision = _disputed_identity(proposer), _disputed_identity(decision)
        for row in rows:
            row["identity"] = _disputed_identity(row["identity"])
    approvers = "\n".join(
        f"Receipt {row['id'] or 'not recorded'}: {row['identity']['text']}; "
        f"at {row['approved_at'] or 'not recorded'}; note: {row['note'] or 'none'}; {row['association_text']}" for row in rows)
    if not rows:
        approvers = (f"Legacy decision ({state}): {decision['text']}" if recorded["decided_by"]
                     else "No approval receipts recorded")
    summary = f"{quorum_text}; recorded state: {state}; {basis_text}"
    validation_text = {"checked": "Receipt audit, lifecycle, current finding/fix and association policy checked at export",
                       "not_established": "Receipt audit, lifecycle, current finding/fix or association policy could not be established",
                       "legacy_unavailable": "Legacy decision; separated approval evidence unavailable",
                       "not_checked": "Current finding/fix and association policy not checked"}[validation["status"]]
    if validation["checked_at"]:
        validation_text += f" ({validation['checked_at']})"
    validation_text = f"Historical audit-bound receipt validation: {historical['status']}. {validation_text}"
    text = (f"Proposal {proposal.id}: {summary}. Proposer: {proposer['text']}. {proposer_association}. "
            f"Recorded decisions: {approvers}. {validation_text}. {LIMITATION}")
    return {**recorded, "proposer_identity": proposer, "approval_identities": rows,
            "recorded_count": count, "quorum_status": quorum,
            "identity_basis": basis, "identity_basis_text": basis_text,
            "proposer_association_text": proposer_association,
            "historical_validation": historical,
            "historical_quorum_evidence_checked": historical["status"] == "checked" and quorum == "recorded_complete",
            "quorum_evidence_checked": validation["status"] == "checked" and quorum == "recorded_complete",
            "validation": validation, "validation_text": validation_text,
            "current_apply_authorization": "not_established_by_report", "limitation": LIMITATION,
            "summary": summary, "approver_text": approvers, "text": text,
            "recorded_json": json.dumps(recorded, ensure_ascii=False, sort_keys=True)}
