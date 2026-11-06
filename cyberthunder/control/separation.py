"""Server-derived approval requirements and immutable decision associations.

Local state and the audit checkpoint remain part of the node's trust boundary.
These checks do not implement policy signing, step-up authentication or an
external tamper-proof ledger.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from cyberthunder.audit.chain import file_lock
from cyberthunder.control.identity import is_machine, normalize_actor, require_human
from cyberthunder.control.principal import current_principal, require_current

RULESET = "cat-i-two-person-v1"
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


def validate(gate, proposal, *, quorum: bool = False) -> dict:
    """Check the immutable creation record, current facts, and each persisted vote."""
    requirements = proposal.approval_requirements
    if not isinstance(requirements, dict):
        raise PermissionError("legacy proposal has no separation requirements; create a new proposal")
    verified = verified_mode(gate, proposal)
    if requirements.get("mode") != ("verified" if verified else "unverified_dev"):
        raise PermissionError("unverified proposal cannot become a verified decision; create a new proposal")
    if verified and gate.authorizer is None:
        raise PermissionError("verified approvals require target authorization wiring")
    records = _audit_records(gate, proposal.id)
    creations = [r["details"].get("proposal", {}) for r in records
                 if r.get("action") == "proposal.create" and r.get("outcome") == "ok"]
    if len(creations) != 1 or digest(creations[0].get("approval_requirements")) != digest(requirements):
        raise PermissionError("proposal requirements differ from the creation record")
    try:
        source = requirements["source"]
        if (requirements["version"] != 1 or requirements["ruleset"] != RULESET
                or type(proposal.required_approvals) is not int
                or proposal.required_approvals != requirements["required_approvals"]
                or proposal.required_approvals != required_count(source["severity"])
                or requirements["payload_sha256"] != payload_digest(proposal)
                or _source(gate, proposal) != source):
            raise PermissionError("proposal requirements or payload changed; create a new proposal")
        proposer = identity(proposal.proposed_principal, verified=verified)
        seen = set()
        if not isinstance(proposal.approvals, list) or len(proposal.approvals) > proposal.required_approvals:
            raise PermissionError("invalid approval count")
        for vote in proposal.approvals:
            person = identity(vote["principal"], verified=verified, human=True)
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
