"""Minimal Trivy image-report parser.

Used only when cyberthunder.parsers.trivy is not installed. Reads `trivy image --format json` output
(schema version 2: Results[].Vulnerabilities[]) and returns one Finding per vulnerability and package.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberthunder.adapters.base import make_finding
from cyberthunder.findings.schema import Finding

SEVERITY = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown"}


def _load(source: Any) -> dict:
    if isinstance(source, dict):
        return source
    if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith("{")):
        return json.loads(Path(source).read_text(encoding="utf-8"))
    return json.loads(source)


def parse_trivy(source: Any, target=None, *, image: str | None = None) -> list[Finding]:
    """source: path, JSON text or parsed dict. target: the inventory Target the image runs on."""
    doc = _load(source)
    if target is None:
        raise ValueError("parse_trivy needs the target the image belongs to")
    image = image or doc.get("ArtifactName") or "unknown-image"
    out: list[Finding] = []
    seen: set[str] = set()
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            rule_id = f"containers:cve:{vid}:{pkg}:{image}"
            if not vid or rule_id in seen:
                continue
            seen.add(rule_id)
            fixed = v.get("FixedVersion") or ""
            out.append(make_finding(
                target=target, source="trivy", rule_id=rule_id, rule_version=vid,
                title=f"{vid} in {pkg} ({image})", severity=SEVERITY.get(str(v.get("Severity", "")).upper(), "unknown"),
                description=(v.get("Title") or v.get("Description") or "")[:500],
                evidence=f"{image}: {pkg} {v.get('InstalledVersion', '?')} installed"
                         + (f", fixed in {fixed}" if fixed else ", no fixed version published")
                         + f" ({res.get('Target', '')})",
                references=[vid, *[r for r in v.get("CweIDs", []) or []]],
                fix_text=(f"Rebuild or update the image so {pkg} is at {fixed} or later." if fixed else None),
                tags=["containers", "cve", f"image:{image}"]))
    return out
