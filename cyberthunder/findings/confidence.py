"""Versioned, deterministic evidence-strength rules. No collection or state changes.

Pass an aware ``now`` for reproducible assessments. The default reads only the
UTC clock. Recorded provenance is input, not independently verified identity.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import re
from typing import Any

from .schema import Finding

RULES_VERSION = "1.1"
MAX_EVIDENCE_AGE = timedelta(days=7)

# These mappings classify existing producers, never supply missing provenance.
DIRECT_SOURCES = frozenset({
    "native", "windows-stig", "windows-scap", "kubernetes", "containers", "cisco_ios",
    "openscap", "scc", "evaluate-stig", "powerstig", "xccdf", "cklb",
})
SCANNER_SOURCES = frozenset({"acas", "nessus"})
VERSION_SOURCES = frozenset({"trivy", "cve", "iavm"})
DIRECT_METHODS = frozenset({"direct", "scanner", "command", "configuration"})
VERSION_METHODS = frozenset({"version", "version_only", "package_version", "cpe", "banner"})
GUESS_METHODS = frozenset({"discovery", "heuristic", "inferred"})
_PLACEHOLDERS = frozenset({"", "unknown", "unavailable", "n/a", "none", "not collected", "not checked"})


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _known(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _PLACEHOLDERS


def _token(value: Any) -> str:
    return _text(value).lower().replace("-", "_").replace(" ", "_")


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _observation(value: Any) -> bool:
    """Empty containers, placeholders and bare result labels are not observations."""
    if isinstance(value, dict):
        return any(_observation(v) for v in value.values())
    if isinstance(value, list):
        return any(_observation(v) for v in value)
    if isinstance(value, (bool, int)):
        return True  # Explicit false/zero measurements are still observations.
    if isinstance(value, float):
        return math.isfinite(value)
    return (_known(value) and _token(value) not in
            {"pass", "fail", "open", "not_a_finding", "not_applicable", "not_reviewed", "error"}
            and not re.fullmatch(r"\[\d+/(?:tcp|udp)\]", value.strip(), re.IGNORECASE))


def _legacy_conflict(text: str, status: str) -> bool:
    """Recognize only the explicit disagreement formats emitted by native merges."""
    native = re.search(r"native check: (\w+) \(", text)
    scanner = re.search(r"; openscap: (\w+) \(", text)
    if native and scanner and native[1] != scanner[1]:
        return True
    checklist = re.search(r"checklist status was (\w+); this scan's own check of the live state "
                          r"\((\w+)\) is used", text)
    if checklist and checklist[1] != checklist[2]:
        return True
    scap_native = re.search(r"\| native check said (\w+):", text)
    return bool(text.startswith("SCAP benchmark (OVAL):") and scap_native and scap_native[1] != status)


def _legacy_inference_markers(text: str) -> list[str]:
    """Recognize observation formats, never plugin IDs, titles or scanner credentials.

    Apply to stored finding text as well as newly parsed exports. Version fields
    remain a restriction even when accompanied by other prose: that prose alone
    cannot establish applicability, backport state, or a direct vulnerability test.
    """
    markers = []
    if re.search(r"\b(?:(?:installed|running|detected|remote|current|reported|fixed|patched|required)"
                 r"\s+(?:software\s+)?)?version(?:\s+number)?\s*[:=]\s*\S", text, re.IGNORECASE):
        markers.append("version_field")
    if (re.search(r"\b(?:banner|server|x-powered-by)\s*[:=]\s*\S", text, re.IGNORECASE)
            or re.search(r"\bSSH-\d+\.\d+-\S+", text, re.IGNORECASE)):
        markers.append("banner")
    # Only whole observations made of port/service presence qualify here; a port
    # suffix on substantive scanner output must not weaken that observation.
    port = (r"(?:\d+/(?:tcp|udp)(?:\s+(?:open|listening|filtered|closed)(?:\s+[\w.-]+)?)?"
            r"|(?:(?:tcp|udp)\s+)?port\s+\d+(?:\s+is)?\s+(?:open|listening|filtered|closed))")
    if re.fullmatch(r"\s*(?:open\s+ports?\s*:\s*)?(?:[\s\[\],;|]*" + port + r")+[\s\[\],;|]*",
                    text, re.IGNORECASE):
        markers.append("port_only")
    return markers


def _timestamp(value: Any) -> tuple[datetime | None, str]:
    if value is None or value == "":
        return None, "missing"
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        else:
            return None, "invalid"
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None, "timezone_missing"
        return parsed.astimezone(timezone.utc), "valid"
    except (TypeError, ValueError, OverflowError):
        return None, "invalid"


def assess(finding: Finding | Mapping[str, Any], *, now: datetime | str | None = None) -> dict:
    """Assess evidence, never severity, approval or scanner correctness.

    ``finding`` may be a Finding or a serialized finding. Unknown/malformed
    collection metadata cannot qualify for High. Invalid explicit ``now`` raises
    ValueError; invalid observation time is reported and caps the grade at Low.
    """
    assessed, time_state = _timestamp(datetime.now(timezone.utc) if now is None else now)
    if time_state != "valid":
        raise ValueError("now must be a valid timezone-aware datetime or ISO timestamp")
    data = finding.to_dict() if isinstance(finding, Finding) else deepcopy(dict(finding))
    supplied = data.get("collection_provenance")
    provenance = supplied if isinstance(supplied, dict) else {}
    source = _text(data.get("source")).lower()
    status = _text(data.get("status")).lower()
    tags = data.get("tags") or []
    tags = tags if isinstance(tags, list) else []
    tag_tokens = {_token(t) for t in tags if isinstance(t, str)}
    method = _token(provenance.get("method"))
    transport = _token(provenance.get("transport"))
    collection_status = _token(provenance.get("collection_status"))
    kind = ("direct" if source in DIRECT_SOURCES else "scanner" if source in SCANNER_SOURCES
            else "version_match" if source in VERSION_SOURCES
            else "discovery" if source in {"discovery", "nmap"}
            else "heuristic" if source == "hunt" or source.startswith("hunt-") else "unclassified")

    # Never infer authenticated access or effective privilege from source or transport.
    authenticated = _bool(provenance.get("authenticated"))
    privilege_sufficient = _bool(provenance.get("privilege_sufficient"))
    complete = _bool(provenance.get("complete"))
    applicable = _bool(provenance.get("applicable"))
    simulated = _bool(provenance.get("simulated"))
    detector = provenance.get("detector")
    detector = detector if isinstance(detector, dict) else {}
    content = provenance.get("content")
    content = content if isinstance(content, dict) else {}
    content_id = content.get("id", data.get("benchmark"))
    content_version = content.get("version", data.get("benchmark_release"))

    time_source = "collection_provenance.observed_at" if "observed_at" in provenance else "collected_at"
    observed_raw = provenance.get("observed_at") if "observed_at" in provenance else data.get("collected_at")
    observed, timestamp_state = _timestamp(observed_raw)
    age = (assessed - observed).total_seconds() if observed is not None else None
    if age is not None:
        timestamp_state = "future" if age < 0 else "stale" if age > MAX_EVIDENCE_AGE.total_seconds() else "fresh"

    observation = data.get("evidence")
    structured = provenance.get("observations")
    # Port-only Nessus fallback and status labels do not constitute an observation.
    has_observation = ((isinstance(observation, str) and _observation(observation))
                       or (isinstance(structured, (dict, list)) and _observation(structured)))
    simulation_markers = (transport in {"simulated", "fixture", "replay"}
                          or bool(tag_tokens & {"simulated", "simulation", "demo", "fixture", "replay"})
                          or source in {"simulated", "simulation", "fixture"}
                          or "simulated sweep:" in _text(observation).lower())
    is_simulated = simulated is True or simulation_markers
    inference_markers = _legacy_inference_markers(_text(observation))
    version_only = (kind == "version_match" or method in VERSION_METHODS
                    or provenance.get("version_only") is True
                    or bool(set(inference_markers) & {"version_field", "banner"})
                    or bool(tag_tokens & {"version_only", "version_match", "banner", "cpe_match"})
                    or bool(re.search(r"\bversion[- ]only\b", _text(observation), re.IGNORECASE)))
    if version_only:
        kind = "version_match"
    elif "port_only" in inference_markers:
        kind = "network_indicator"
    conflicts = provenance.get("conflicts")
    has_conflicts = (conflicts is True or (isinstance(conflicts, (list, str, dict)) and bool(conflicts))
                    or provenance.get("conflicting") is True
                    or bool(tag_tokens & {"conflict", "conflicting"})
                    or _legacy_conflict(_text(observation), status))
    partial = (provenance.get("partial") is True or collection_status == "partial"
               or bool(tag_tokens & {"partial", "partial_evidence", "scap:undecided"}))
    invalid_markers = [name for name in ("partial", "version_only", "conflicting")
                       if name in provenance and not isinstance(provenance[name], bool)]
    if "conflicts" in provenance and not isinstance(conflicts, (bool, list, str, dict)):
        invalid_markers.append("conflicts")

    requirements = {
        "method": method in DIRECT_METHODS,
        "authenticated": authenticated is True,
        "privilege": _known(provenance.get("privilege")),
        "privilege_sufficient": privilege_sufficient is True,
        "complete": complete is True,
        "applicable": applicable is True,
        "simulated": simulated is False,
        "detector.name": _known(detector.get("name")),
        "detector.version": _known(detector.get("version")),
        "content.id": _known(content_id),
        "content.version": _known(content_version),
        "observed_at": time_source == "collection_provenance.observed_at" and timestamp_state == "fresh",
    }
    unknowns = []
    for name, value in {
        "method": provenance.get("method"), "authenticated": authenticated,
        "privilege": provenance.get("privilege"), "privilege_sufficient": privilege_sufficient,
        "complete": complete, "applicable": applicable, "simulated": simulated,
        "detector.name": detector.get("name"), "detector.version": detector.get("version"),
        "content.id": content_id, "content.version": content_version,
    }.items():
        if value is None or (not isinstance(value, bool) and not _known(value)):
            unknowns.append(name)
    if observed is None:
        unknowns.append("observed_at")
    if time_source == "collected_at":
        unknowns.append("observation_time_origin")

    evidence = {
        "host": data.get("host"), "source": data.get("source"), "source_kind": kind,
        "rule_id": data.get("rule_id"), "rule_version": data.get("rule_version"),
        "status": data.get("status"), "benchmark": data.get("benchmark"),
        "benchmark_release": data.get("benchmark_release"), "raw_ref": data.get("raw_ref"),
        "observation": observation, "collected_at": data.get("collected_at"), "tags": tags,
        "collection_provenance": supplied, "authenticated": authenticated,
        "privilege": provenance.get("privilege"), "privilege_sufficient": privilege_sufficient,
        "detector": detector, "content": {"id": content_id, "version": content_version},
        "complete": complete, "applicable": applicable, "simulated": True if is_simulated else simulated,
        "timestamp_source": time_source, "timestamp_status": timestamp_state, "age_seconds": age,
        "version_only": version_only, "partial": partial, "conflicting": bool(has_conflicts),
        "inference_markers": inference_markers,
        "invalid_markers": invalid_markers,
        "unknowns": unknowns, "high_requirements_unmet": [k for k, met in requirements.items() if not met],
    }
    reasons: list[str] = []
    unknown_reasons: list[str] = []
    if status not in {"open", "not_a_finding", "not_applicable"}:
        unknown_reasons.append("Scanner status is unresolved or errored; no completed determination is available.")
    if (complete is False or collection_status in {"incomplete", "error", "failed", "not_reviewed", "unknown"}
            or bool(tag_tokens & {"incomplete", "collection_error"})
            or bool(provenance.get("errors"))):
        unknown_reasons.append("Collection is incomplete or failed; the determination cannot be assessed.")
    if not has_observation:
        unknown_reasons.append("No usable observation was recorded; a source name or result label is insufficient.")
    if not _known(data.get("host")) or not _known(data.get("rule_id")):
        unknown_reasons.append("Host or rule identity is missing; the observation has no definite scope.")

    low_reasons: list[str] = []
    if is_simulated:
        low_reasons.append("Simulated or replayed evidence describes a demonstration, not a current target observation.")
    if version_only:
        low_reasons.append("Version-only evidence matches an advisory or banner; applicability and backports remain unverified.")
    if "port_only" in inference_markers:
        low_reasons.append("Port/service presence alone does not verify a vulnerability or configuration defect.")
    if kind in {"discovery", "heuristic"} or method in GUESS_METHODS:
        low_reasons.append("Discovery or heuristic evidence is an indicator requiring direct verification.")
    if has_conflicts:
        low_reasons.append("Conflicting evidence is recorded and must be reconciled.")
    if partial:
        low_reasons.append("Only partial evidence is available for this determination.")
    if applicable is False:
        low_reasons.append("Provenance records the evidence as inapplicable to this target or rule.")
    if privilege_sufficient is False:
        low_reasons.append("Recorded collection privilege was insufficient for the check.")
    if timestamp_state != "fresh":
        low_reasons.append({
            "missing": "Observation timestamp is missing; freshness is unknown.",
            "invalid": "Observation timestamp is invalid; freshness is unknown.",
            "timezone_missing": "Observation timestamp has no timezone; freshness is unknown.",
            "future": "Observation timestamp is in the future; freshness cannot be established.",
            "stale": "Evidence is older than the seven-day freshness limit.",
        }[timestamp_state])
    if supplied is not None and not isinstance(supplied, dict):
        low_reasons.append("Collection provenance is malformed; explicit collection facts are unavailable.")
    if invalid_markers:
        low_reasons.append("Collection restriction markers are malformed: " + ", ".join(invalid_markers) + ".")
    if kind not in {"direct", "scanner"} and method not in DIRECT_METHODS:
        low_reasons.append("The collection method is not established as direct observation.")

    if unknown_reasons:
        grade = "unknown"
        reasons.extend(unknown_reasons)
    elif low_reasons:
        grade = "low"
    elif all(requirements.values()):
        grade = "high"
        reasons.append("Fresh direct evidence has explicit applicable, complete collection, authentication, "
                       "sufficient privilege, detector and content provenance.")
    else:
        grade = "medium"
        label = "Scanner observation" if kind == "scanner" else "Direct observation"
        reasons.append(label + " supports the scanner result, but sufficient explicit provenance for High is missing.")
    reasons.extend(low_reasons)
    if unknowns:
        reasons.append("Unknown provenance: " + ", ".join(unknowns) + ".")
    if grade == "medium":
        reasons.append("High requirements not met: " + ", ".join(evidence["high_requirements_unmet"]) + ".")
    reason = reasons[0]
    if is_simulated and grade == "unknown":
        reason += " Simulated or replayed evidence is explicitly marked."
    return {
        "grade": grade, "reason": reason, "reasons": reasons, "version": RULES_VERSION,
        "assessed_at": assessed.isoformat(), "observed_at": observed.isoformat() if observed else None,
        "evidence": evidence,
    }


def assess_for_context(ctx: Any, finding: Finding | Mapping[str, Any], *,
                       now: datetime | str | None = None) -> dict:
    """Use one normal inventory lookup for a missing legacy simulation flag.

    Explicit simulation metadata (including an invalid/null value) takes
    precedence. Inventory context can downgrade a legacy finding, never promote
    it to High or stand in for historical collection provenance. No writes.
    """
    data = finding.to_dict() if isinstance(finding, Finding) else deepcopy(dict(finding))
    result = assess(data, now=now)
    supplied = data.get("collection_provenance")
    if supplied is not None and (not isinstance(supplied, dict) or "simulated" in supplied):
        return result
    try:
        target = ctx.inventory.get(data.get("host"))
    except (KeyError, OSError, ValueError):
        return result
    simulated = _bool(getattr(target, "simulated", None))
    if simulated is None:
        return result
    if simulated:
        contextual = dict(data, collection_provenance={**(supplied or {}), "simulated": True})
        result = assess(contextual, now=result["assessed_at"])
        # Preserve exactly what the collector supplied; identify the added fact separately.
        result["evidence"]["collection_provenance"] = supplied
    note = (f"Simulation flag ({str(simulated).lower()}) comes from current inventory context; "
            "simulation at collection time was not recorded.")
    result["reason"] += " " + note
    result["reasons"].append(note)
    result["evidence"]["simulation_context"] = {"source": "inventory", "simulated": simulated}
    result["evidence"]["unknowns"].append("simulation_at_collection")
    return result
