"""Pure receipt checks for the approval gate: no store, audit, transport or model I/O.

validate_receipt_binding(receipt, current_bindings, *, now) returns the same
readiness shape as ImpactService.readiness(). `ready` means a current, intact,
time-bound receipt is available for human review. It does not mean operational
safety, complete dependencies, successful model use, or approval authority.
Unknowns and deterministic fallback still require the parent's explicit UI ack.
The caller must supply current bindings and enforce its own actor/scope/kill gates.
"""
from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from .packet import TTL_SECONDS, evidence_digest, timestamp

BINDING_FIELDS = ("proposal_id", "target_id", "fix_sha256", "target_binding_sha256", "finding_id",
                  "finding_fingerprint", "finding_binding_sha256", "proposal_binding_sha256", "config_sha256")


def evidence_times(packet, now):
    values = [timestamp(packet["generated_at"]), *[timestamp(e["observed_at"]) for e in packet["evidence"]]]
    if any(v is None or v > now + timedelta(seconds=5) for v in values):
        return now, "evidence_time_invalid"
    expiry = min(values) + timedelta(seconds=TTL_SECONDS)
    return expiry, "evidence_stale" if expiry <= now else None


def validate_receipt_binding(receipt, current_bindings, *, now):
    """Compare an explicit receipt to a caller-supplied current local snapshot.

    current_bindings contains BINDING_FIELDS, including the full current finding
    hash (not merely its stable ID). Missing finding evidence cannot be ready.
    The packet hash covers every retained fact, edge, risk, unknown and timestamp.
    """
    reasons, unknowns = [], []
    result = {"ready": False, "status": "unknown", "stale": True, "age_seconds": None,
              "assessment_id": None, "proposal_id": None, "valid_until": None,
              "reasons": reasons, "unknowns": unknowns, "approval_authority": False}
    if not isinstance(receipt, dict):
        reasons.append("assessment_missing")
        unknowns.append("missing_evidence")
        return result
    result.update(assessment_id=receipt.get("id"), proposal_id=receipt.get("proposal_id"),
                  valid_until=receipt.get("valid_until"))
    try:
        if str(UUID(receipt["id"])) != receipt["id"]:
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        reasons.append("invalid_receipt_id")
    generated, expiry = timestamp(receipt.get("generated_at")), timestamp(receipt.get("valid_until"))
    if generated:
        result["age_seconds"] = round(max(0, (now - generated).total_seconds()), 3)
    if not generated or not expiry or generated > now + timedelta(seconds=5):
        reasons.append("invalid_receipt_time")
    elif expiry <= now:
        reasons.append("expired")
    elif expiry > generated + timedelta(seconds=TTL_SECONDS):
        reasons.append("invalid_receipt_ttl")
    if not isinstance(current_bindings, dict) or not set(BINDING_FIELDS) <= current_bindings.keys():
        reasons.append("binding_unavailable")
    else:
        if not set(BINDING_FIELDS) <= receipt.keys():
            reasons.append("receipt_binding_missing")
        for key in BINDING_FIELDS:
            if receipt.get(key) != current_bindings[key]:
                reason = "model_config_changed" if key == "config_sha256" else "binding_changed"
                reasons.append(reason)
        if current_bindings["finding_binding_sha256"] is None:
            reasons.append("current_finding_unavailable")
            unknowns.append("current_finding_unavailable")
    packet = receipt.get("evidence_packet")
    try:
        if (evidence_digest(packet) != receipt.get("evidence_sha256")
                or packet["evidence_sha256"] != receipt["evidence_sha256"]):
            reasons.append("evidence_hash_mismatch")
        for key in ("proposal_id", "target_id", "fix_sha256", "target_binding_sha256"):
            if packet[key] != receipt.get(key):
                reasons.append("evidence_binding_changed")
        evidence_expiry, time_reason = evidence_times(packet, now)
        if time_reason:
            reasons.append(time_reason)
        if expiry and expiry > evidence_expiry:
            reasons.append("invalid_evidence_ttl")
        if generated and any(timestamp(v) and timestamp(v) > generated + timedelta(seconds=5)
                             for v in [packet["generated_at"], *[e["observed_at"] for e in packet["evidence"]]]):
            reasons.append("evidence_after_receipt")
        if not packet["complete"]:
            unknowns.append("incomplete_evidence")
        if not packet["evidence"]:
            reasons.append("missing_evidence")
            unknowns.append("missing_evidence")
        if packet["mode"] != "live":
            unknowns.append("stored_evidence")
        if packet["unknowns"]:
            unknowns.append("unresolved_unknowns")
    except (KeyError, ValueError, TypeError, AttributeError, RecursionError):
        reasons.append("invalid_evidence_packet")
    return finish_readiness(result)


def finish_readiness(result):
    """Normalize after a service adds local control state; never grants authority."""
    result["reasons"] = list(dict.fromkeys(result["reasons"]))
    result["unknowns"] = list(dict.fromkeys(result["unknowns"]))
    result["ready"] = not result["reasons"]
    result["stale"] = bool(result["reasons"])
    result["status"] = "stale" if result["stale"] else ("unknown" if result["unknowns"] else "fresh")
    return result
