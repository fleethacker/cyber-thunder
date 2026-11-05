"""Updated STIG checklist (CKLB, the STIG Viewer 3 JSON format) for one host.

If the scan kept an input .cklb in its raw directory, that file is reused and only status, finding details
and comments are rewritten per rule, so the reviewer's own text and the benchmark content survive.
Otherwise a checklist is built from the findings for the host.
"""
from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.control.approvals import Proposal, ProposalState
from cyberthunder.findings.current import CurrentFindings
from cyberthunder.findings.schema import Finding, Status, utcnow
from cyberthunder.report.onepager import latest_proposals, resolve_scan
from cyberthunder.report.render import ReportError

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

CKLB_STATUS = {
    Status.OPEN: "open", Status.NOT_A_FINDING: "not_a_finding", Status.NOT_APPLICABLE: "not_applicable",
    Status.NOT_REVIEWED: "not_reviewed", Status.ERROR: "not_reviewed",
}
_NS = uuid.UUID("6f1c2e0a-5b0e-4c55-9a53-3d6f3c1a7b10")
CKLB_SEVERITIES = ("high", "medium", "low")      # the only rule severities STIG Viewer 3 accepts


def _cklb_severity(f: Finding) -> str:
    """unknown reads as medium (assume it matters until reviewed); info and anything else as low."""
    v = f.severity.value
    if v in CKLB_SEVERITIES:
        return v
    return "medium" if v == "unknown" else "low"


def _status_for(f: Finding, p: Proposal | None, lifecycle: CurrentFindings | None = None) -> tuple[str, str]:
    """(cklb status, comment). Only a dated verification covering the observation closes it."""
    current = (lifecycle or CurrentFindings([p] if p else [])).assess(f)
    if current.needs_rescan:
        attempt = current.rollback
        return CKLB_STATUS[current.finding.status], (
            f"Rollback attempt {attempt['proposal_id']} ok={attempt['ok']} at {attempt['finished_at'] or 'unknown time'}; "
            f"{'rolled_back' if attempt['ok'] else 'restore failed'}; rescan required. "
            f"Original scanner status: {f.status.value}.")
    if current.remediated:
        p = next(candidate for candidate in (lifecycle.proposals[(f.id, f.host)] if lifecycle else [p])
                 if candidate.id == current.remediated["proposal_id"])
        when = current.remediated["verified_at"]
        return "not_a_finding", f"Fixed by approved change {p.id} ({p.fix_ref}), approved by {p.decided_by}, verified {when}."
    status = CKLB_STATUS[f.status]
    note = ""
    if f.is_open and p:
        note = f"Fix {p.fix_ref} is {p.state.value} (proposal {p.id})."
        if p.state == ProposalState.VERIFIED:
            note += " Prior verification does not establish closure of this observation; reassess and verify."
    elif f.is_open and f.fix_ref:
        note = f"Library fix {f.fix_ref} available; not yet proposed."
    return status, note


def _details(f: Finding, sid: str) -> str:
    return (f.evidence or "").strip() or f"Cyber Thunder scan {sid}: {f.status.value}."


def _rule_keys(rule: dict) -> list[str]:
    return [k for k in (rule.get("rule_id_src"), rule.get("rule_id"), rule.get("rule_version"), rule.get("group_id")) if k]


def _find_input(raw_dir: Path, host: str | None) -> tuple[Path, dict] | None:
    candidates = sorted(raw_dir.rglob("*.cklb")) if raw_dir.exists() else []
    parsed = []
    for c in candidates:
        try:
            parsed.append((c, json.loads(c.read_text(encoding="utf-8-sig"))))
        except (OSError, json.JSONDecodeError):
            continue
    if host:
        for c, doc in parsed:
            td = doc.get("target_data") or {}
            if host in (td.get("host_name"), td.get("fqdn"), td.get("ip_address")) or host in c.parts:
                return c, doc
        return None
    return parsed[0] if parsed else None


def _update_existing(doc: dict, by_key: dict[str, Finding], props: dict[str, Proposal], sid: str,
                     lifecycle: CurrentFindings) -> int:
    touched = 0
    for stig in doc.get("stigs", []):
        for rule in stig.get("rules", []):
            f = next((by_key[k] for k in _rule_keys(rule) if k in by_key), None)
            if f is None:
                continue
            status, note = _status_for(f, props.get(f.id), lifecycle)
            rule["status"] = status
            rule["finding_details"] = _details(f, sid)
            old = (rule.get("comments") or "").strip()
            rule["comments"] = old if (not note or note in old) else f"{old}\n{note}".strip()
            touched += 1
    return touched


def _synthesise(host: str, findings: list[Finding], props: dict[str, Proposal], sid: str,
                lifecycle: CurrentFindings) -> dict:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.benchmark or f"{f.source} findings", []).append(f)
    stigs = []
    for name, fl in sorted(groups.items()):
        rules = []
        stig_uuid = str(uuid.uuid5(_NS, name))
        stig_id = name.lower().replace(" ", "_")
        release = next((f.benchmark_release for f in fl if f.benchmark_release), "") or ""
        for f in sorted(fl, key=lambda f: (f.rule_version or "", f.rule_id)):
            status, note = _status_for(f, props.get(f.id), lifecycle)
            group_id = f.group_id or f.rule_version or f.id
            rules.append({
                # the fields STIG Viewer 3 writes for every rule; stig_uuid links the rule to its STIG
                "uuid": str(uuid.uuid5(_NS, f.id)), "stig_uuid": stig_uuid, "target_key": None, "stig_id": stig_id,
                "group_id": group_id, "group_id_src": group_id, "group_title": f.title,
                "group_tree": [{"id": group_id, "title": f.title, "description": "<GroupDescription></GroupDescription>"}],
                "rule_id": f.rule_id, "rule_id_src": f.rule_id, "rule_version": f.rule_version or "",
                "rule_title": f.title, "weight": "10.0", "classification": "UNCLASSIFIED",
                "severity": _cklb_severity(f),
                "discussion": f.description, "check_content": f.check_text or "", "fix_text": f.fix_text or "",
                "check_content_ref": {"href": "", "name": "M"},
                "false_positives": "", "false_negatives": "", "documentable": "false", "mitigations": "",
                "potential_impacts": "", "third_party_tools": "", "mitigation_control": "", "responsibility": "",
                "security_override_guidance": "", "ia_controls": "", "legacy_ids": [],
                "ccis": f.ref_ids("cci"), "reference_identifier": "", "status": status,
                "finding_details": _details(f, sid), "comments": note, "overrides": {},
            })
        stigs.append({"stig_name": name, "display_name": name, "stig_id": stig_id, "version": "",
                      "release_info": release, "uuid": stig_uuid, "reference_identifier": "",
                      "size": len(rules), "rules": rules})
    return {
        "title": f"{host} checklist", "id": str(uuid.uuid5(_NS, f"{host}|{sid}")), "active": True, "mode": 2,
        "has_path": True, "cklb_version": "1.0",
        "target_data": {"target_type": "Computing", "host_name": host, "ip_address": "", "mac_address": "",
                        "fqdn": "", "comments": f"Generated from Cyber Thunder scan {sid}", "role": "None",
                        "is_web_database": False, "technology_area": "", "web_db_site": "", "web_db_instance": ""},
        "stigs": stigs,
    }


def build_checklist(ctx: "AppContext", scan_id: str | None = None, host: str | None = None) -> dict:
    sid, _run, findings = resolve_scan(ctx, scan_id)
    hosts = sorted({f.host for f in findings})
    if host is None:
        if len(hosts) > 1:
            raise ReportError(f"scan {sid} covers {len(hosts)} hosts ({', '.join(hosts)}); pass a host")
        host = hosts[0] if hosts else None
    if host is None:
        raise ReportError(f"scan {sid} has no findings, so there is no host to build a checklist for")
    mine = [f for f in findings if f.host == host]
    if not mine:
        raise ReportError(f"no findings for host {host!r} in scan {sid}; hosts: {', '.join(hosts)}")
    props = latest_proposals(ctx)
    lifecycle = CurrentFindings.for_context(ctx)
    found = _find_input(ctx.store.scans_dir / sid / "raw", host)
    if found:
        _path, doc = found
        doc = copy.deepcopy(doc)
        by_key: dict[str, Finding] = {}
        for f in mine:
            for k in (f.rule_id, f.rule_version, f.group_id):
                if k:
                    by_key.setdefault(k, f)
        _update_existing(doc, by_key, props, sid, lifecycle)
        doc.setdefault("target_data", {}).setdefault("host_name", host)
        doc["target_data"]["comments"] = (doc["target_data"].get("comments") or "") + f" Updated by Cyber Thunder {utcnow()} from scan {sid}."
        return doc
    return _synthesise(host, mine, props, sid, lifecycle)
