"""Unified findings schema.

Every scanner, hunt module and CVE matcher normalizes into `Finding`.
Downstream stages (explain, approve, apply, verify, report) only ever see this shape.
Stdlib only: must run on an offline enclave with nothing installed.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"

# Identifier patterns shared by every parser (DISA / ComplianceAsCode / NVD conventions).
RE_STIG_RULE = re.compile(r"\bSV-\d+r\d+_rule\b")
RE_GROUP_ID = re.compile(r"\bV-\d{4,7}\b")
RE_STIG_ID = re.compile(r"\b[A-Z][A-Z0-9]{1,15}-[A-Z0-9]{2}-\d{6}\b")   # RHEL-09-211010, WN11-SO-000010, CISC-ND-000010, CNTR-K8-000360
RE_CCI = re.compile(r"\bCCI-\d{6}\b")
RE_CCE = re.compile(r"\bCCE-\d{4,6}-\d\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
RE_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")          # MITRE ATT&CK technique, e.g. T1053.003
RE_IAVM = re.compile(r"\b\d{4}-[AB]-\d{4}\b")               # IAVA/IAVB notice, e.g. 2026-A-0123


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Severity(str, Enum):
    HIGH = "high"        # CAT I
    MEDIUM = "medium"    # CAT II
    LOW = "low"          # CAT III
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def cat(self) -> str:
        return {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}.get(self.value, "-")

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}[self.value]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        v = ("" if value is None else str(value)).strip().lower()
        table = {
            "high": cls.HIGH, "critical": cls.HIGH, "cat i": cls.HIGH, "cat1": cls.HIGH, "1": cls.HIGH,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "cat ii": cls.MEDIUM, "cat2": cls.MEDIUM, "2": cls.MEDIUM,
            "low": cls.LOW, "cat iii": cls.LOW, "cat3": cls.LOW, "3": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO,
        }
        return table.get(v, cls.UNKNOWN)


class Status(str, Enum):
    OPEN = "open"                       # fail
    NOT_A_FINDING = "not_a_finding"     # pass
    NOT_APPLICABLE = "not_applicable"
    NOT_REVIEWED = "not_reviewed"
    ERROR = "error"

    @classmethod
    def from_xccdf(cls, result: Any) -> "Status | None":
        """XCCDF 1.2 rule-result values. Returns None for notselected (caller skips it)."""
        v = ("" if result is None else str(result)).strip().lower()
        if v == "notselected":
            return None
        table = {
            "pass": cls.NOT_A_FINDING, "fixed": cls.NOT_A_FINDING,
            "fail": cls.OPEN,
            "error": cls.ERROR,
            "notapplicable": cls.NOT_APPLICABLE,
            "unknown": cls.NOT_REVIEWED, "notchecked": cls.NOT_REVIEWED, "informational": cls.NOT_REVIEWED,
        }
        return table.get(v, cls.NOT_REVIEWED)

    @classmethod
    def from_cklb(cls, status: Any) -> "Status":
        v = ("" if status is None else str(status)).strip().lower().replace(" ", "_")
        table = {
            "open": cls.OPEN,
            "not_a_finding": cls.NOT_A_FINDING, "notafinding": cls.NOT_A_FINDING, "pass": cls.NOT_A_FINDING,
            "not_applicable": cls.NOT_APPLICABLE, "notapplicable": cls.NOT_APPLICABLE,
            "not_reviewed": cls.NOT_REVIEWED, "notreviewed": cls.NOT_REVIEWED, "": cls.NOT_REVIEWED,
        }
        return table.get(v, cls.NOT_REVIEWED)


@dataclass
class Reference:
    system: str   # stig_rule | group | stig_id | cci | cce | cve | url | <ident system>
    id: str

    def to_dict(self) -> dict:
        return {"system": self.system, "id": self.id}


@dataclass
class Finding:
    host: str
    source: str                      # openscap | scc | evaluate-stig | powerstig | hunt | cve
    rule_id: str                     # SV-257777r925318_rule or xccdf_org.ssgproject.content_rule_...
    title: str
    severity: Severity
    status: Status
    id: str = ""                     # stable: sha256(host|source|rule_id)[:16]
    rule_version: str | None = None  # STIG ID, e.g. RHEL-09-211010
    group_id: str | None = None      # V-257777
    benchmark: str | None = None     # benchmark id or STIG title
    benchmark_release: str | None = None
    description: str = ""
    check_text: str | None = None
    fix_text: str | None = None
    fix_script: str | None = None    # bash from ComplianceAsCode <fix system="urn:xccdf:fix:script:sh">
    fix_ansible: str | None = None
    references: list[Reference] = field(default_factory=list)
    evidence: str | None = None      # scanner finding_details / message
    collected_at: str = field(default_factory=utcnow)
    raw_ref: str | None = None       # path of the raw scanner artifact
    tags: list[str] = field(default_factory=list)
    asset_type: str | None = None    # linux | windows | cisco_ios | kubernetes | containers
    fix_ref: str | None = None       # resolved remediation-library entry, set by the engine
    scan_id: str | None = None       # scan run that produced this finding

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.parse(self.severity)
        if not isinstance(self.status, Status):
            self.status = Status(self.status)
        if not self.id:
            self.id = self.make_id(self.host, self.source, self.rule_id)

    @staticmethod
    def make_id(host: str, source: str, rule_id: str) -> str:
        return hashlib.sha256(f"{host}|{source}|{rule_id}".encode()).hexdigest()[:16]

    @property
    def is_open(self) -> bool:
        return self.status == Status.OPEN

    def ref_ids(self, system: str) -> list[str]:
        return [r.id for r in self.references if r.system == system]

    @property
    def citations(self) -> list[str]:
        """Every identifier the explain layer is allowed to cite for this finding."""
        out: list[str] = [v for v in (self.rule_id, self.rule_version, self.group_id) if v]
        out.extend(r.id for r in self.references)
        seen: set[str] = set()
        return [c for c in out if not (c in seen or seen.add(c))]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["references"] = [r.to_dict() for r in self.references]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["references"] = [Reference(**r) for r in d.get("references", [])]
        return cls(**d)


def extract_references(texts: Iterable[str]) -> list[Reference]:
    """Pull every known identifier out of free text / reference fields. Deterministic, deduped."""
    found: list[Reference] = []
    seen: set[tuple[str, str]] = set()
    patterns = (("stig_rule", RE_STIG_RULE), ("group", RE_GROUP_ID), ("stig_id", RE_STIG_ID),
                ("cci", RE_CCI), ("cce", RE_CCE), ("cve", RE_CVE), ("attack", RE_ATTACK), ("iavm", RE_IAVM))
    for t in texts:
        if not t:
            continue
        for system, rx in patterns:
            for m in rx.findall(t):
                key = (system, m)
                if key not in seen:
                    seen.add(key)
                    found.append(Reference(system, m))
    return found


def dump_findings(findings: Iterable[Finding], path: str | Path, meta: dict | None = None) -> dict:
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow(),
        "meta": meta or {},
        "findings": [f.to_dict() for f in findings],
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return doc


def load_findings(path: str | Path) -> list[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if str(doc.get("schema_version", "")).split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise ValueError(f"unsupported findings schema_version {doc.get('schema_version')!r}")
    return [Finding.from_dict(f) for f in doc["findings"]]


def summarize(findings: Iterable[Finding]) -> dict:
    fl = list(findings)
    by_sev = {s.value: 0 for s in Severity}
    by_status = {s.value: 0 for s in Status}
    hosts: set[str] = set()
    for f in fl:
        by_status[f.status.value] += 1
        hosts.add(f.host)
        if f.is_open:
            by_sev[f.severity.value] += 1
    return {"total": len(fl), "hosts": sorted(hosts), "open_by_severity": by_sev, "by_status": by_status,
            "sources": sorted({f.source for f in fl})}
