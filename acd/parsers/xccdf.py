"""XCCDF 1.1/1.2 parser: benchmarks (DISA STIG XCCDF, SCAP datastreams) and results (oscap --results, SCC, ARF).

Namespace-agnostic on purpose: DISA, ComplianceAsCode, SCC and ARF wrap the same elements in
different namespaces/containers. We match on local tag names and walk the whole document.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from acd.findings.schema import (Finding, Reference, Severity, Status,
                                 extract_references, utcnow)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return " ".join("".join(el.itertext()).split())


def _child(el: ET.Element, name: str) -> ET.Element | None:
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _local(c.tag) == name]


@dataclass
class RuleMeta:
    rule_id: str
    title: str
    severity: Severity
    group_id: str | None = None
    rule_version: str | None = None
    description: str = ""
    check_text: str | None = None
    fix_text: str | None = None
    fix_script: str | None = None
    fix_ansible: str | None = None
    references: list[Reference] = field(default_factory=list)


@dataclass
class XccdfParse:
    path: str
    benchmark_id: str | None = None
    benchmark_title: str | None = None
    benchmark_release: str | None = None
    rules: dict[str, RuleMeta] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    profile: str | None = None

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_open]


def _parse_rule(rule: ET.Element, parents: dict) -> RuleMeta:
    rid = rule.get("id", "")
    # Nearest enclosing Group carries the V-id in DISA content.
    group_id = None
    p = parents.get(rule)
    while p is not None:
        if _local(p.tag) == "Group":
            group_id = p.get("id")
            break
        p = parents.get(p)

    version = _text(_child(rule, "version")) or None
    description = _text(_child(rule, "description"))
    # DISA wraps discussion in <VulnDiscussion> pseudo-tags inside the description text.
    if "<VulnDiscussion>" in description:
        description = description.split("<VulnDiscussion>", 1)[1].split("</VulnDiscussion>", 1)[0].strip()

    check_text = None
    chk = _child(rule, "check")
    if chk is not None:
        cc = _child(chk, "check-content")
        ref = _child(chk, "check-content-ref")
        if cc is not None:
            check_text = _text(cc)
        elif ref is not None:
            check_text = f"{ref.get('href', '')}#{ref.get('name', '')}"

    fix_text = _text(_child(rule, "fixtext")) or None
    fix_script = fix_ansible = None
    for fx in _children(rule, "fix"):
        system = (fx.get("system") or "").lower()
        body = "".join(fx.itertext()).strip()
        if system.endswith("script:sh") and not fix_script:
            fix_script = body
        elif system.endswith("script:ansible") and not fix_ansible:
            fix_ansible = body

    ref_texts = [rid, version or "", group_id or ""]
    for el in _children(rule, "ident") + _children(rule, "reference"):
        ref_texts.append(_text(el))
        ref_texts.append(el.get("href", ""))
    references = extract_references(ref_texts)
    # Keep idents that do not match our patterns; the system attribute says what they are.
    for el in _children(rule, "ident"):
        t = _text(el)
        sysattr = (el.get("system") or "").rstrip("/").rsplit("/", 1)[-1] or "ident"
        if t and all(r.id != t for r in references):
            references.append(Reference(sysattr, t))

    if not version:
        version = next((r.id for r in references if r.system == "stig_id"), None)
    if not group_id:
        group_id = next((r.id for r in references if r.system == "group"), None)

    return RuleMeta(rule_id=rid, title=_text(_child(rule, "title")), severity=Severity.parse(rule.get("severity")),
                    group_id=group_id, rule_version=version, description=description, check_text=check_text,
                    fix_text=fix_text, fix_script=fix_script, fix_ansible=fix_ansible, references=references)


def parse_xccdf(path: str | Path, host: str | None = None, source: str = "openscap") -> XccdfParse:
    """Parse a benchmark and/or results document. Findings are only produced for TestResult blocks."""
    path = str(path)
    root = ET.parse(path).getroot()
    parents = {c: p for p in root.iter() for c in p}
    out = XccdfParse(path=path)

    for el in root.iter():
        name = _local(el.tag)
        if name == "Benchmark" and out.benchmark_id is None:
            out.benchmark_id = el.get("id")
            out.benchmark_title = _text(_child(el, "title")) or None
            for pt in _children(el, "plain-text"):
                if pt.get("id") == "release-info":
                    out.benchmark_release = _text(pt)
            if out.benchmark_release is None:
                out.benchmark_release = _text(_child(el, "version")) or None
        elif name == "Rule":
            meta = _parse_rule(el, parents)
            if meta.rule_id:
                out.rules[meta.rule_id] = meta

    for tr in (el for el in root.iter() if _local(el.tag) == "TestResult"):
        targets = [t for t in (_text(x) for x in _children(tr, "target")) if t]
        out.targets.extend(t for t in targets if t not in out.targets)
        prof = _child(tr, "profile")
        if prof is not None:
            out.profile = prof.get("idref")
        collected = tr.get("end-time") or tr.get("start-time") or utcnow()
        tr_host = host or (targets[0] if targets else None) or "unknown"
        for rr in _children(tr, "rule-result"):
            status = Status.from_xccdf(_text(_child(rr, "result")))
            if status is None:
                continue
            rid = rr.get("idref", "")
            meta = out.rules.get(rid) or RuleMeta(rule_id=rid, title=rid, severity=Severity.parse(rr.get("severity")))
            sev = Severity.parse(rr.get("severity")) if rr.get("severity") else meta.severity
            evidence = " | ".join(t for t in (_text(m) for m in _children(rr, "message")) if t) or None
            out.findings.append(Finding(
                host=tr_host, source=source, rule_id=rid, title=meta.title, severity=sev, status=status,
                rule_version=meta.rule_version, group_id=meta.group_id,
                benchmark=out.benchmark_title or out.benchmark_id, benchmark_release=out.benchmark_release,
                description=meta.description, check_text=meta.check_text, fix_text=meta.fix_text,
                fix_script=meta.fix_script, fix_ansible=meta.fix_ansible, references=list(meta.references),
                evidence=evidence, collected_at=collected, raw_ref=path,
            ))
    return out
