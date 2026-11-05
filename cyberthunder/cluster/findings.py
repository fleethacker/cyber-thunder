"""Normalize image evidence without implying target remediation or unobserved coverage."""
from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy

from cyberthunder.findings.schema import Finding, Reference, Status, utcnow

PRODUCER = "cluster_vulnerabilities"


def _key(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def database_provenance(snapshot: dict | None) -> dict:
    """Copy public metadata only; a scan's internal cache path must never leave the service."""
    snapshot = snapshot or {}
    return {key: deepcopy(snapshot.get(key)) for key in (
        "generation", "state", "updated_at", "imported_at", "source", "provenance",
        "integrity_verified", "databases", "warnings", "engine",
    )}


def is_stale(snapshot: dict) -> bool:
    return (snapshot.get("state") == "stale"
            or any(db.get("stale") is True for db in (snapshot.get("databases") or []) if isinstance(db, dict)))


def parse_report(report: dict) -> dict:
    """Retain valid positives, but never interpret absent/unsupported results as a clean image.

    Trivy omits Vulnerabilities on a successfully assessed section with no matches. The section's
    target, class and type still have to be present before its omission of matches is authoritative.
    """
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list) or not report["Results"]:
        return {"vulnerabilities": [], "sections": [], "errors": ["Trivy supplied no assessed result sections"]}
    vulnerabilities, sections, errors = [], [], []
    invalid_sections = set()
    for result in report["Results"]:
        if not isinstance(result, dict):
            errors.append("Trivy supplied a malformed result section")
            continue
        section = {k.lower(): result.get(k) for k in ("Target", "Class", "Type")}
        if (not all(isinstance(value, str) and value.strip() for value in section.values())
                or section["class"] not in {"os-pkgs", "lang-pkgs"}):
            errors.append("Trivy result section has unsupported or missing coverage metadata")
            continue
        rows = result.get("Vulnerabilities")
        rows = [] if rows is None else rows
        if not isinstance(rows, list):
            errors.append("Trivy supplied a malformed vulnerability list")
            invalid_sections.add(_key(section))
            continue
        valid = True
        for row in rows:
            if (not isinstance(row, dict)
                    or not all(isinstance(row.get(k), str) and row[k].strip()
                               for k in ("VulnerabilityID", "PkgName", "InstalledVersion"))):
                valid = False
                errors.append("Trivy supplied a vulnerability without package/version/advisory identity")
                continue
            scores = []
            cvss = row.get("CVSS")
            for source in cvss.values() if isinstance(cvss, dict) else []:
                if isinstance(source, dict):
                    for key in ("V3Score", "V40Score"):
                        try:
                            score = float(source[key])
                            if math.isfinite(score) and 0 <= score <= 10:
                                scores.append(score)
                        except (KeyError, TypeError, ValueError):
                            pass
            severity = str(row.get("Severity") or "UNKNOWN").upper()
            vulnerabilities.append({
                "id": row["VulnerabilityID"], "package": row["PkgName"],
                "installed_version": row["InstalledVersion"], "fixed_version": row.get("FixedVersion"),
                "package_id": row.get("PkgID"), "package_path": row.get("PkgPath"),
                "severity": severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN",
                "cvss": max(scores) if scores else None, "status": row.get("Status"),
                "title": row.get("Title") or row.get("Description") or "",
                "target": section["target"], "section": section,
                "data_source": deepcopy(row.get("DataSource")), "primary_url": row.get("PrimaryURL"),
            })
        if valid:
            sections.append(section)
        else:
            invalid_sections.add(_key(section))
    sections = [section for section in sections if _key(section) not in invalid_sections]
    metadata = report.get("Metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    os_info = metadata.get("OS")
    if isinstance(os_info, dict) and os_info.get("EOSL") is True:
        errors.append("Image operating system is end of support; vulnerability coverage is incomplete")
        sections = []
    digests = metadata.get("RepoDigests")
    return {"vulnerabilities": vulnerabilities, "sections": sections, "errors": sorted(set(errors)),
            "repo_digests": [d for d in digests if isinstance(d, str)] if isinstance(digests, list) else [],
            "image_id": metadata.get("ImageID"), "os": deepcopy(os_info)}


def observation_scope(target_id: str, workload: dict, image: str, section=None, binding=None) -> str:
    return _key([target_id, binding, workload.get("namespace"), workload.get("kind"), workload.get("name"),
                 workload.get("uid"), image, section])


def _image_digest(image: str, report: dict) -> str | None:
    candidates = [image.split("@", 1)[1]] if "@" in image else [
        value.rsplit("@", 1)[-1] for value in report.get("repo_digests", [])]
    digests = {value for value in candidates if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value)}
    return next(iter(digests)) if len(digests) == 1 else None


def mark_missing_sections(previous: list[Finding], target_id: str, survey: dict, reports: dict,
                          target_binding: dict) -> list[str]:
    """Expose lost coverage for an image/workload that was observed again, without clearing it."""
    binding = _key(target_binding)
    observed = {observation_scope(target_id, workload, image, binding=binding)
                for workload in survey.get("workloads", []) for image in workload.get("images", [])}
    missing = set()
    for finding in previous:
        provenance = finding.collection_provenance or {}
        if (finding.host != target_id or finding.source != "trivy" or provenance.get("producer") != PRODUCER
                or provenance.get("target_binding") != binding or not provenance.get("result")):
            continue
        image = (provenance.get("image") or {}).get("reference")
        scope = observation_scope(target_id, provenance.get("workload") or {}, image, binding=binding)
        report = reports.get(image)
        if scope in observed and report and provenance["result"] not in report.get("sections", []):
            missing.add(image)
    errors = []
    for image in sorted(missing):
        report = reports[image]
        if not report.get("error"):
            report["error"] = "Previously observed package result section was not assessed"
            errors.append(f"{image}: {report['error']}")
        report["complete"] = False
    return errors


def normalize_findings(target_id: str, survey: dict, reports: dict, snapshot: dict | None,
                       scan_id: str, *, target_binding: dict | None = None) -> tuple[list[Finding], list[str]]:
    database = database_provenance(snapshot)
    stale = is_stale(snapshot or {})
    collected_at = utcnow()
    findings, assessed = {}, set()
    binding = _key(target_binding) if target_binding is not None else None
    for workload in survey.get("workloads", []):
        for image in workload.get("images", []):
            report = reports.get(image) or {}
            status_scope = observation_scope(target_id, workload, image, binding=binding)
            complete = report.get("complete") is True and not stale
            common = {
                "producer": PRODUCER, "method": "package_version", "version_only": True,
                "transport": "kubeconfig", "complete": complete,
                "collection_status": "complete" if complete else "partial", "partial": not complete,
                "detector": {"name": "trivy", "version": (database.get("engine") or {}).get("version")},
                "content": {"id": "trivy-db", "version": database.get("generation")},
                "database": database, "target_id": target_id, "target_binding": binding,
                "workload": {key: workload.get(key) for key in ("namespace", "kind", "name", "uid")},
                "image": {"reference": image, "repo_digests": report.get("repo_digests", []),
                          "id": report.get("image_id"), "digest": _image_digest(image, report)},
            }
            # Valid sections may be assessed even when a different section failed. Stale data,
            # however, cannot authoritatively clear any previously observed vulnerability.
            if not stale:
                for section in report.get("sections", []):
                    assessed.add(observation_scope(target_id, workload, image, section, binding))
            if complete:
                assessed.add(status_scope)
            for row in report.get("vulnerabilities", []):
                scope = observation_scope(target_id, workload, image, row["section"], binding)
                identity = _key([scope, row["id"], row["package"], row.get("package_path"), row.get("package_id")])
                package = {"name": row["package"], "version": row["installed_version"],
                           "fixed_version": row.get("fixed_version"), "id": row.get("package_id"),
                           "path": row.get("package_path")}
                provenance = {**deepcopy(common), "observation_scope": scope,
                              "package": package, "advisory": {"id": row["id"], "source": row.get("data_source"),
                                                               "url": row.get("primary_url")},
                              "result": deepcopy(row["section"]), "reported_severity": row["severity"],
                              "cvss": row.get("cvss"), "vendor_status": row.get("status")}
                finding = Finding(
                    host=target_id, source="trivy", rule_id=f"{row['id']}:{identity[:24]}",
                    title=f"{row['id']} in {row['package']} ({workload['namespace']}/{workload['name']})",
                    severity=row["severity"], status=Status.OPEN, asset_type="kubernetes",
                    description=str(row.get("title") or ""),
                    references=[Reference("cve" if row["id"].startswith("CVE-") else "advisory", row["id"])],
                    evidence=json.dumps({"image": image, "package": package, "advisory": row["id"],
                                         "result": row["section"]}, sort_keys=True),
                    fix_text=(f"Review vendor guidance and rebuild or replace the affected image; reported fixed "
                              f"version: {row['fixed_version']}" if row.get("fixed_version") else None),
                    raw_ref=report.get("raw"), scan_id=scan_id, collected_at=collected_at,
                    collection_provenance=provenance, tags=[PRODUCER, "version_only"],
                )
                findings[finding.id] = finding
            if not complete:
                reason = report.get("error") or ("Managed vulnerability database is stale" if stale else
                                                 "Image vulnerability coverage is unavailable")
                finding = Finding(
                    host=target_id, source="trivy", rule_id=f"cluster-coverage:{status_scope[:24]}",
                    title=f"Image coverage unavailable ({workload['namespace']}/{workload['name']})",
                    severity="unknown", status=Status.ERROR if report.get("failed") else Status.NOT_REVIEWED,
                    evidence=str(reason), asset_type="kubernetes", scan_id=scan_id, collected_at=collected_at,
                    collection_provenance={**deepcopy(common), "observation_scope": status_scope,
                                           "errors": [str(reason)]}, tags=[PRODUCER, "partial"],
                )
                findings[finding.id] = finding
    # A failed workload listing must remain visible even when it yielded no image identities.
    survey_scope = _key([target_id, binding, "survey"])
    if survey.get("errors"):
        finding = Finding(
            host=target_id, source="trivy", rule_id=f"cluster-survey:{survey_scope[:24]}",
            title="Cluster image inventory is incomplete", severity="unknown", status=Status.ERROR,
            evidence="; ".join(survey["errors"]), asset_type="kubernetes", scan_id=scan_id,
            collection_provenance={"producer": PRODUCER, "observation_scope": survey_scope,
                                   "target_id": target_id, "complete": False, "partial": True,
                                   "collection_status": "error", "database": database},
            tags=[PRODUCER, "partial"],
        )
        findings[finding.id] = finding
    else:
        assessed.add(survey_scope)
    database_scope = _key([target_id, binding, "database"])
    if not snapshot or stale:
        reason = "Managed vulnerability database is stale" if stale else "Managed vulnerability database is unavailable"
        finding = Finding(
            host=target_id, source="trivy", rule_id=f"cluster-database:{database_scope[:24]}",
            title=reason, severity="unknown", status=Status.NOT_REVIEWED, evidence=reason,
            asset_type="kubernetes", scan_id=scan_id, collection_provenance={
                "producer": PRODUCER, "observation_scope": database_scope, "target_id": target_id,
                "complete": False, "partial": True, "collection_status": "not_reviewed", "database": database},
            tags=[PRODUCER, "partial"],
        )
        findings[finding.id] = finding
    else:
        assessed.add(database_scope)
    return list(findings.values()), sorted(assessed)
