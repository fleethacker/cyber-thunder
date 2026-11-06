"""Server-derived approval requirements and immutable decision associations.

Local state and the audit checkpoint remain part of the node's trust boundary.
These checks do not implement policy signing, step-up authentication or an
external tamper-proof ledger.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from cyberthunder.audit.chain import file_lock
from cyberthunder.control.access import ApprovalIdentitySource, person_identifier
from cyberthunder.control.identity import is_machine, normalize_actor, require_human
from cyberthunder.control.principal import current_principal, require_current

RULESET = "cat-i-two-person-v1"
PERSON_RULESET = "cat-i-person-association-v1"
RESERVED_FIELDS = frozenset({"proposed_by", "proposed_principal", "required_approvals",
                             "approval_requirements", "approvals"})
PAYLOAD_FIELDS = ("id", "finding_id", "host", "title", "fix_ref", "fix_preview", "rollback_plan", "risk",
                  "citations", "created_at", "authorization_scope", "proposed_by", "proposed_principal")


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def required_count(severity: str) -> int:
    if severity not in {"high", "medium", "low", "info", "unknown"}:
        raise PermissionError("server finding severity is unavailable")
    return 2 if severity in {"high", "unknown"} else 1


def enforced(gate, proposal=None) -> bool:
    principal = current_principal()
    return bool(gate.authorizer or gate.unverified_separation or getattr(principal, "verified", False)
                or (proposal is not None and proposal.approval_requirements is not None))


def verified_mode(gate, proposal=None) -> bool:
    principal = current_principal()
    return bool(gate.authorizer or getattr(principal, "verified", False)
                or (proposal is not None and (proposal.approval_requirements or {}).get("mode") == "verified"))


def identity(evidence: dict, *, verified: bool, human: bool = False) -> tuple[str, str]:
    if (not isinstance(evidence, dict) or not isinstance(evidence.get("iss"), str) or not evidence["iss"]
            or not isinstance(evidence.get("sub"), str) or not evidence["sub"]):
        raise PermissionError("approval identity is unavailable")
    if verified and (evidence.get("verified") is not True or evidence.get("via") not in {"oidc", "mesh"}
                     or (human and evidence.get("kind") != "human")):
        raise PermissionError("a verified human approval is required")
    if not verified and (evidence.get("verified") is not False or evidence.get("via") != "dev"):
        raise PermissionError("development approval identity is invalid")
    return evidence["iss"], evidence["sub"]


def actor_evidence(gate, action: str, actor: str, proposal=None) -> tuple[str, dict]:
    if verified_mode(gate, proposal):
        if gate.authorizer is None:
            raise PermissionError("verified approvals require target authorization wiring")
        # Internal proposal workers retain the initiating account, including when their
        # service label is used. That label can never hide the proposer from this rule.
        principal = require_current(action, None if action == "propose" and is_machine(actor) else actor)
        return principal.actor, deepcopy(principal.evidence())
    name = normalize_actor(actor) if action == "propose" else require_human(actor)
    if not name:
        raise PermissionError("a proposer identity is required")
    return name, {"iss": "local-development", "sub": name.casefold(), "name": name,
                  "kind": "dev", "via": "dev", "verified": False}


def source_for(ctx, proposal) -> dict:
    """Read authoritative persisted finding/target facts and the current vetted fix.

    Called at creation, each approval and start_apply. No API metadata or in-memory
    finding fallback can supply the severity. This function grants no permission.
    """
    from cyberthunder.inventory.host import persisted_target
    from cyberthunder.security.resources import target_scope
    from cyberthunder.remediation.engine import fix_digest

    finding = ctx.store.get_finding(proposal.finding_id)
    if finding is None or finding.host != proposal.host:
        raise PermissionError("persisted proposal finding is unavailable")
    target = persisted_target(ctx.inventory, proposal.host)
    if proposal.authorization_scope != target_scope(target):
        raise PermissionError("proposal target ownership changed")
    if (getattr(ctx.settings, "auth_mode", "dev") != "dev"
            and finding.authorization_scope != proposal.authorization_scope):
        raise PermissionError("proposal finding ownership is unavailable or changed")
    fix = ctx.library.get(proposal.fix_ref)
    if fix is None or fix.preview_text() != proposal.fix_preview:
        raise PermissionError("proposal fix differs from the current vetted payload")
    return {"finding_id": finding.id, "finding_sha256": digest(finding.to_dict()),
            "severity": finding.severity.value, "fix_sha256": fix_digest(fix),
            "target_scope": target_scope(target)}


def _source(gate, proposal) -> dict:
    if not callable(gate.separation_source):
        raise PermissionError("server approval requirements are unavailable")
    try:
        source = deepcopy(gate.separation_source(proposal))
        if (set(source) != {"finding_id", "finding_sha256", "severity", "fix_sha256", "target_scope"}
                or source["finding_id"] != proposal.finding_id
                or source["target_scope"] != proposal.authorization_scope):
            raise ValueError
        required_count(source["severity"])
        for key in ("finding_sha256", "fix_sha256"):
            if not isinstance(source[key], str) or len(source[key]) != 64:
                raise ValueError
        return source
    except (KeyError, TypeError, ValueError, OSError):
        raise PermissionError("server approval requirements are unavailable") from None


def payload_digest(proposal) -> str:
    return digest({name: getattr(proposal, name) for name in PAYLOAD_FIELDS})


def _policy(gate) -> ApprovalIdentitySource:
    callback = getattr(gate, "separation_policy", None)
    if not callable(callback):
        raise PermissionError("protected approval identity policy wiring is unavailable")
    source = callback()
    if (not isinstance(source, ApprovalIdentitySource) or type(source.policy_version) is not int
            or source.policy_version not in {1, 2}):
        raise PermissionError("protected approval identity policy is unavailable")
    return source


def person_bound(requirements) -> bool:
    return (isinstance(requirements, dict) and type(requirements.get("version")) is int
            and requirements["version"] == 2 and requirements.get("ruleset") == PERSON_RULESET)


def _person_key(evidence, association, basis):
    """Check a recorded association without consulting today's policy or login."""
    account = identity(evidence, verified=True, human=True)
    if (not isinstance(basis, dict)
            or set(basis) != {"mode", "policy_version", "version", "namespace", "revision", "policy_sha256"}
            or basis["mode"] != "person" or type(basis["policy_version"]) is not int or basis["policy_version"] != 2
            or type(basis["version"]) is not int or basis["version"] != 1
            or type(basis["revision"]) is not int or not 1 <= basis["revision"] <= 2**53 - 1
            or not isinstance(basis["policy_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", basis["policy_sha256"]) is None
            or not isinstance(association, dict)
            or set(association) != {"issuer", "subject", "person_id", "source"}
            or (association["issuer"], association["subject"]) != account
            or digest(association["source"]) != digest(basis)):
        raise PermissionError("recorded person association is unavailable or inconsistent")
    return person_identifier(basis["namespace"]), person_identifier(association["person_id"])


def check_current_policy(gate, proposal, evidence=None):
    """Re-read policy at an operation boundary; never used to authenticate old receipts."""
    requirements = proposal.approval_requirements
    if requirements["mode"] != "verified":
        return None
    source = _policy(gate)
    if not person_bound(requirements):
        if source.policy_version != 1:
            raise PermissionError("account-only approvals cannot become person-bound; create a new proposal")
        return None
    if digest(source.basis) != digest(requirements["identity_basis"]):
        raise PermissionError("person association policy changed; create a new proposal")
    recorded = [(proposal.proposed_principal, requirements["proposer_association"])]
    recorded.extend((v["principal"], v["person_association"]) for v in proposal.approvals)
    for principal, association in recorded:
        account = identity(principal, verified=True, human=True)
        if digest(source.association(*account)) != digest(association):
            raise PermissionError("person association changed; create a new proposal")
    if evidence is not None:
        return source.association(*identity(evidence, verified=True, human=True))
    return None


def participation(gate, proposal, evidence):
    """Return this vote's source-bound association after excluding proposer/duplicates."""
    requirements = proposal.approval_requirements
    association = check_current_policy(gate, proposal, evidence)
    if person_bound(requirements):
        basis = requirements["identity_basis"]
        candidate = _person_key(evidence, association, basis)
        proposer = _person_key(proposal.proposed_principal, requirements["proposer_association"], basis)
        seen = {_person_key(v["principal"], v["person_association"], basis) for v in proposal.approvals}
    else:
        verified = requirements["mode"] == "verified"
        candidate = identity(evidence, verified=verified, human=True)
        proposer = identity(proposal.proposed_principal, verified=verified)
        seen = {identity(v["principal"], verified=verified, human=True) for v in proposal.approvals}
    if candidate == proposer:
        raise PermissionError("the proposer cannot approve their own change")
    if candidate in seen:
        raise PermissionError("this person or account has already approved the proposal")
    return association


def initialize(gate, proposal, actor: str) -> str:
    actor, evidence = actor_evidence(gate, "propose", actor)
    proposal.proposed_by, proposal.proposed_principal = actor, evidence
    source = _source(gate, proposal)
    proposal.required_approvals = required_count(source["severity"])
    proposal.approval_requirements = {
        "version": 1, "ruleset": RULESET, "mode": "verified" if verified_mode(gate) else "unverified_dev",
        "source": source, "required_approvals": proposal.required_approvals,
        "payload_sha256": payload_digest(proposal),
    }
    if verified_mode(gate):
        policy = _policy(gate)
        if policy.policy_version == 2:
            association = policy.association(*identity(evidence, verified=True, human=True))
            proposal.approval_requirements.update(version=2, ruleset=PERSON_RULESET,
                                                 identity_basis=policy.basis, proposer_association=association)
    return actor


def assessment_association(assessment: dict) -> dict:
    if not isinstance(assessment, dict) or assessment.get("status") not in {"reviewed", "not_assessed"}:
        raise PermissionError("approval assessment association is unavailable")
    # Each reviewer retains their own acknowledgement; the reviewed receipt itself
    # must be the same for every counted approval.
    return {k: deepcopy(v) for k, v in assessment.items() if k != "note"}


def _audit_records(gate, pid: str) -> list[dict]:
    try:
        with file_lock(gate.audit.path.with_name(gate.audit.path.name + ".lock")):
            verification = gate.audit.verify()
            if not verification.ok or verification.checkpoint == "missing":
                raise PermissionError("approval audit integrity cannot be established")
            return [r for r in gate.audit.records() if r.get("subject") == pid]
    except (OSError, ValueError, TypeError):
        raise PermissionError("approval audit integrity cannot be established") from None


def _validate_lifecycle(proposal, records) -> None:
    """A valid old vote cannot revive a cancelled or already consumed proposal."""
    state, votes = "proposed", []
    outcomes = {"applying": "ok", "applied": "ok", "verified": "ok", "cancelled": "ok",
                "denied": "ok", "failed": "failed", "rolled_back": "reverted"}
    for record in records:
        action = record.get("action", "")
        if action in {"proposal.approval_recorded", "proposal.approved"} and record.get("outcome") == "ok":
            vote = record.get("details", {}).get("approval")
            if not isinstance(vote, dict):
                raise PermissionError("audited approval receipt is unavailable")
            votes.append(vote)
            state = "approved" if action == "proposal.approved" else "proposed"
        elif action.startswith("proposal."):
            edge = action.removeprefix("proposal.")
            if edge in outcomes and record.get("outcome") == outcomes[edge]:
                state = edge
    if proposal.state.value != state or proposal.approvals != votes:
        raise PermissionError("proposal state or receipts differ from the audited lifecycle")
    if votes and len(votes) == proposal.required_approvals:
        last = votes[-1]
        if (proposal.decided_by != last["actor"] or proposal.decided_principal != last["principal"]
                or proposal.decided_at != last["approved_at"] or proposal.decision_note != last["note"]):
            raise PermissionError("final decision differs from its audited approval")


def validate_history(gate, proposal, *, quorum: bool = False) -> dict:
    """Check audit-bound receipts only. This never establishes current permission or mappings."""
    requirements = proposal.approval_requirements
    if not isinstance(requirements, dict):
        raise PermissionError("legacy proposal has no separation requirements; create a new proposal")
    if requirements.get("mode") not in {"verified", "unverified_dev"}:
        raise PermissionError("invalid recorded approval mode")
    verified = requirements["mode"] == "verified"
    records = _audit_records(gate, proposal.id)
    creations = [r["details"].get("proposal", {}) for r in records
                 if r.get("action") == "proposal.create" and r.get("outcome") == "ok"]
    if (len(creations) != 1 or digest(creations[0].get("approval_requirements")) != digest(requirements)
            or any(creations[0].get(name) != getattr(proposal, name) for name in PAYLOAD_FIELDS)):
        raise PermissionError("proposal requirements differ from the creation record")
    try:
        _validate_lifecycle(proposal, records)
        source = requirements["source"]
        bound = person_bound(requirements)
        if (type(requirements["version"]) is not int
                or not (bound and verified or requirements["version"] == 1 and requirements["ruleset"] == RULESET)
                or type(proposal.required_approvals) is not int
                or proposal.required_approvals != requirements["required_approvals"]
                or proposal.required_approvals != required_count(source["severity"])
                or requirements["payload_sha256"] != payload_digest(proposal)):
            raise PermissionError("proposal requirements or payload changed; create a new proposal")
        proposer = identity(proposal.proposed_principal, verified=verified)
        if bound:
            proposer = _person_key(proposal.proposed_principal, requirements["proposer_association"],
                                   requirements["identity_basis"])
        elif "identity_basis" in requirements or "proposer_association" in requirements:
            raise PermissionError("account-only requirements cannot carry person associations")
        seen = set()
        if not isinstance(proposal.approvals, list) or len(proposal.approvals) > proposal.required_approvals:
            raise PermissionError("invalid approval count")
        for vote in proposal.approvals:
            person = identity(vote["principal"], verified=verified, human=True)
            if bound:
                person = _person_key(vote["principal"], vote["person_association"], requirements["identity_basis"])
            elif "person_association" in vote:
                raise PermissionError("account-only votes cannot carry person associations")
            if person == proposer or person in seen:
                raise PermissionError("approvals must be distinct people other than the proposer")
            seen.add(person)
            audited = [r for r in records if r.get("action") in {"proposal.approval_recorded", "proposal.approved"}
                       and r.get("outcome") == "ok" and r["details"].get("approval") == vote]
            if (len(audited) != 1 or audited[0]["actor"] != vote["actor"]
                    or (verified and audited[0].get("principal") != vote["principal"])
                    or vote["requirements_sha256"] != digest(requirements)
                    or vote["payload_sha256"] != requirements["payload_sha256"]
                    or vote["assessment_sha256"] != digest(assessment_association(vote["assessment"]))
                    or assessment_association(vote["assessment"]) != assessment_association(proposal.assessment)):
                raise PermissionError("approval differs from its audited payload or assessment association")
        if quorum and len(seen) != proposal.required_approvals:
            raise PermissionError("the required distinct human approvals are incomplete")
        return requirements
    except (KeyError, TypeError, ValueError):
        raise PermissionError("proposal separation evidence is incomplete or invalid") from None


def validate(gate, proposal, *, quorum: bool = False) -> dict:
    """Validate historical evidence, then current facts and protected association policy."""
    requirements = validate_history(gate, proposal, quorum=quorum)
    verified = verified_mode(gate, proposal)
    if requirements["mode"] != ("verified" if verified else "unverified_dev"):
        raise PermissionError("unverified proposal cannot become a verified decision; create a new proposal")
    if verified and gate.authorizer is None:
        raise PermissionError("verified approvals require target authorization wiring")
    if _source(gate, proposal) != requirements["source"]:
        raise PermissionError("proposal requirements or payload changed; create a new proposal")
    check_current_policy(gate, proposal)
    return requirements
