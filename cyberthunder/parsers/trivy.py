"""Trivy JSON parser (trivy rootfs / image / fs with --format json, schema version 2).

One Finding per (vulnerability, package). Trivy runs offline in the enclave with a database delivered
over the link (--skip-db-update), so the parser never looks anything up.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.adapters.base import make_finding
from cyberthunder.findings.schema import Finding

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.inventory.targets import Target

SEVERITY = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
_CWE = re.compile(r"^CWE-\d+$")


def _trim(text: str | None, limit: int = 600) -> str:
    t = " ".join((text or "").split())
    return t if len(t) <= limit else t[: limit - 3].rstrip() + "..."


def parse_trivy(path: str | Path, *, target: "Target", source: str = "trivy") -> list[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(doc, list):                      # Trivy v1 / older schema: a bare list of results
        doc = {"Results": doc}
    if not isinstance(doc, dict):
        raise ValueError("unsupported Trivy report shape")
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for res in doc.get("Results") or []:
        res_target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            pkg = v.get("PkgName") or ""
            if not vid or not pkg or (vid, pkg) in seen:
                continue
            seen.add((vid, pkg))
            installed = v.get("InstalledVersion") or ""
            fixed = v.get("FixedVersion") or ""
            title = v.get("Title") or ""
            desc = _trim(". ".join(x.strip().rstrip(".") for x in (title, v.get("Description") or "") if x.strip()))
            cwes = [c for c in v.get("CweIDs") or [] if _CWE.match(c)]
            findings.append(make_finding(
                target=target, source=source, rule_id=f"cve:{vid}:{pkg}", title=f"{vid} in {pkg} {installed}".strip(),
                severity=SEVERITY.get(str(v.get("Severity", "UNKNOWN")).upper(), "info"), description=desc,
                evidence=f"trivy {res_target}: {pkg} {installed} installed"
                         + (f", fixed in {fixed}" if fixed else ", no fixed version")
                         + (f" ({v['Status']})" if v.get("Status") else ""),
                fix_text=f"update {pkg} to {fixed}" if fixed else "no fixed version",
                references=[vid, *cwes], tags=[f"pkg:{pkg}", f"installed:{installed}", f"fixed:{fixed}"],
                fix_ref=f"patch:{pkg}", raw_ref=str(path)))
    return findings
