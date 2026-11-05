"""Positive input allowlists shared by persistence and the advisory prompt."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re

MAX_PACKET_BYTES = 65536
TTL_SECONDS = 900
LEVELS = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:/+\-]{0,255}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
SECRET = re.compile(r"-{5}BEGIN|\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=]|Bearer\s+", re.I)
RELATIONS = {"requires", "wants", "references", "selector-matches", "observed", "matched-by-budget"}
FACT_KEYS = {
    "declared-fix": {"disruption", "reboot", "reversible", "rollback_kind", "patch", "services",
                     "possible_management_impact", "declared_files_exhaustive"},
    "declared-critical-service": {"critical"},
    "systemd": {"requested_unit", "unit", "load_state", "active_state", "Requires", "Wants", "RequiredBy", "WantedBy"},
    "windows-service": {"name", "status", "required", "dependents"},
    "kubernetes-workload": {"kind", "namespace", "name", "desired_replicas", "ready_replicas", "available_replicas"},
    "kubernetes-references": {"references", "host_path_present"},
    "kubernetes-pod": {"name", "ready", "match_basis"},
    "kubernetes-service-selector": {"name", "selector_matches_template", "selector_key_count"},
    "kubernetes-pdb": {"name", "selector_matches_template", "disruptions_allowed"},
    "kubernetes-namespace-coverage": {"pod_list_complete", "service_list_complete", "pdb_list_complete",
                                      "matching_pods", "matching_services", "matching_pdbs"},
}
PACKET_KEYS = {"version", "generated_at", "proposal_id", "target_id", "fix_sha256", "target_binding_sha256",
               "evidence_sha256", "mode", "complete", "evidence", "dependencies", "risks", "unknowns",
               "required_checks", "rollback_limits"}


class PacketError(ValueError):
    """Fixed diagnostics only: never echo rejected target data."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def evidence_digest(packet):
    return digest({key: value for key, value in packet.items() if key != "evidence_sha256"})


def dependency_id(edge):
    """Collector-compatible content ID over the four original edge fields."""
    return "d-" + digest({k: edge[k] for k in ("from", "to", "relation", "evidence_ids")})[:24]


def timestamp(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def text(value, limit=600):
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value) or SECRET.search(value)):
        raise PacketError("invalid_text")
    return value


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise PacketError("invalid_identifier")
    return value


def rows(value, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise PacketError("invalid_list")
    return value


def references(value, ids, *, nonempty=True):
    values = rows(value, 128)
    if (nonempty and not values) or any(not isinstance(v, str) or v not in ids for v in values):
        raise PacketError("invalid_evidence_reference")
    return list(dict.fromkeys(values))


def _fact(value, depth=0):
    if depth > 3:
        raise PacketError("invalid_fact")
    if value is None or type(value) is bool:
        return value
    if type(value) is int and 0 <= value <= 1000000:
        return value
    if isinstance(value, str):
        return identifier(value)
    if isinstance(value, list):
        return [_fact(v, depth + 1) for v in rows(value, 64)]
    if isinstance(value, dict) and set(value) <= {"name", "status", "kind"}:
        return {key: _fact(v, depth + 1) for key, v in value.items()}
    raise PacketError("invalid_fact")


def sanitize_packet(raw):
    """Check the collector hash first, then bind the entire sanitized packet anew.

    Unknown fact keys are removed and explicitly degrade completeness. Unsupported
    kinds or broken graph references fail closed; deterministic floors are never truncated.
    """
    if not isinstance(raw, dict) or not PACKET_KEYS <= set(raw):
        raise PacketError("missing_packet_fields")
    if len(canonical(raw).encode("utf-8")) > MAX_PACKET_BYTES:
        raise PacketError("packet_too_large")
    if raw["evidence_sha256"] != evidence_digest(raw):
        raise PacketError("evidence_hash_mismatch")
    out = {key: deepcopy(raw[key]) for key in PACKET_KEYS}
    removed = set(raw) != PACKET_KEYS
    if type(out["version"]) is not int or out["version"] != 1:
        raise PacketError("unsupported_packet_version")
    if out["mode"] not in {"live", "stored"} or type(out["complete"]) is not bool:
        raise PacketError("invalid_packet_mode")
    for key in ("proposal_id", "target_id"):
        identifier(out[key])
    for key in ("fix_sha256", "target_binding_sha256", "evidence_sha256"):
        if not isinstance(out[key], str) or not HASH.fullmatch(out[key]):
            raise PacketError("invalid_binding")
    text(out["generated_at"], 64)
    ids = set()
    evidence = []
    for item in rows(out["evidence"], 128):
        keys = {"id", "kind", "source", "observed_at", "subject", "facts"}
        if not isinstance(item, dict) or not keys <= set(item):
            raise PacketError("invalid_evidence")
        eid = identifier(item["id"])
        if eid in ids or item["kind"] not in FACT_KEYS or not isinstance(item["facts"], dict):
            raise PacketError("invalid_evidence_kind")
        ids.add(eid)
        removed |= set(item) != keys or bool(set(item["facts"]) - FACT_KEYS[item["kind"]])
        evidence.append({"id": eid, "kind": item["kind"], "source": identifier(item["source"]),
                         "subject": identifier(item["subject"]), "observed_at": text(item["observed_at"], 64),
                         "facts": {k: _fact(v) for k, v in item["facts"].items() if k in FACT_KEYS[item["kind"]]}})
    out["evidence"] = evidence
    for edge in rows(out["dependencies"], 512):
        keys = {"from", "to", "relation", "evidence_ids"}
        if not isinstance(edge, dict) or not keys <= set(edge) or set(edge) - keys - {"id"}:
            raise PacketError("invalid_dependency")
        identifier(edge["from"])
        identifier(edge["to"])
        if edge["relation"] not in RELATIONS:
            raise PacketError("invalid_relation")
        expected_id = dependency_id(edge)
        if edge.get("id", expected_id) != expected_id:
            raise PacketError("invalid_dependency_id")
        edge["evidence_ids"] = references(edge["evidence_ids"], ids)
        edge["id"] = expected_id
    risk_ids = set()
    for risk in rows(out["risks"], 128):
        if not isinstance(risk, dict) or set(risk) != {"id", "severity", "summary", "evidence_ids", "deterministic"}:
            raise PacketError("invalid_risk")
        identifier(risk["id"])
        if risk["id"] in risk_ids or risk["severity"] not in LEVELS or risk["deterministic"] is not True:
            raise PacketError("invalid_risk_floor")
        risk_ids.add(risk["id"])
        text(risk["summary"])
        risk["evidence_ids"] = references(risk["evidence_ids"], ids, nonempty=False)
    for key in ("unknowns", "required_checks", "rollback_limits"):
        out[key] = [text(v) for v in rows(out[key], 128)]
    if removed:
        out["complete"] = False
        out["unknowns"].append("Unrecognized input fields were omitted; their operational effects remain unknown.")
    out["evidence_sha256"] = evidence_digest(out)
    return out


def fix_allowlist(fix, fix_sha256):
    """Exact bound metadata only; scripts, configs, steps and arbitrary maps stay local."""
    return {"fix_ref": identifier(fix.fix_ref), "fix_sha256": fix_sha256,
            "asset_type": identifier(fix.asset_type), "kind": fix.kind, "disruption": fix.disruption,
            "reboot": bool(fix.reboot), "reversible": bool(fix.reversible), "patch": bool(fix.patch),
            "rollback_kind": fix.rollback_kind,
            "restarts_services": [identifier(v) for v in rows(fix.restarts_services, 32)]}
