"""CKLB (STIG Viewer 3 / Evaluate-STIG JSON checklist) parser."""
from __future__ import annotations

import json
from pathlib import Path

from acd.findings.schema import (Finding, Reference, Severity, Status,
                                 extract_references, utcnow)


def parse_cklb(path: str | Path, host: str | None = None, source: str = "evaluate-stig") -> list[Finding]:
    path = str(path)
    doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    td = doc.get("target_data") or {}
    tgt_host = host or td.get("host_name") or td.get("fqdn") or td.get("ip_address") or "unknown"
    findings: list[Finding] = []
    for stig in doc.get("stigs", []):
        bench = stig.get("display_name") or stig.get("stig_name") or stig.get("stig_id")
        release = stig.get("release_info")
        for r in stig.get("rules", []):
            rid = r.get("rule_id_src") or r.get("rule_id") or ""
            if rid.startswith("SV-") and not rid.endswith("_rule"):
                rid += "_rule"
            refs = extract_references([rid, r.get("group_id") or "", r.get("rule_version") or "",
                                       " ".join(r.get("ccis") or []), " ".join(r.get("legacy_ids") or [])])
            for cci in r.get("ccis") or []:
                if all(x.id != cci for x in refs):
                    refs.append(Reference("cci", cci))
            findings.append(Finding(
                host=tgt_host, source=source, rule_id=rid,
                title=r.get("rule_title") or r.get("group_title") or rid,
                severity=Severity.parse(r.get("severity")), status=Status.from_cklb(r.get("status")),
                rule_version=r.get("rule_version"), group_id=r.get("group_id"),
                benchmark=bench, benchmark_release=release,
                description=r.get("discussion") or "", check_text=r.get("check_content"),
                fix_text=r.get("fix_text"), references=refs,
                evidence=(r.get("finding_details") or None),
                collected_at=r.get("updatedAt") or r.get("createdAt") or utcnow(), raw_ref=path,
            ))
    return findings
