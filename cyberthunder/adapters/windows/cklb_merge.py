"""Merge an Evaluate-STIG / STIG Viewer CKLB with this adapter's own checks.

Rules are matched by STIG ID (rule_version). For a matched rule the benchmark text from the CKLB is kept
(title, discussion, check and fix text, CCIs), and the status from our own check of the live state wins when
the two disagree; the disagreement is written into the evidence so the reviewer can see both. Rules the
checklist covers that we do not check natively are passed through as-is, re-homed to the target.
"""
from __future__ import annotations

from cyberthunder.findings.schema import Finding, Status

from cyberthunder.adapters.base import make_finding

SOURCE = "evaluate-stig"


def merge(target, native: list[Finding], cklb: list[Finding]) -> list[Finding]:
    by_version = {f.rule_version: f for f in native if f.rule_version}
    out = list(native)
    for c in cklb:
        n = by_version.get(c.rule_version) if c.rule_version else None
        refs = [r.id for r in c.references]
        if n is None:
            out.append(make_finding(
                target=target, source=SOURCE, rule_id=c.rule_id or f"win:{c.rule_version}", title=c.title,
                severity=c.severity, status=c.status, description=c.description, evidence=c.evidence,
                references=refs, check_text=c.check_text, fix_text=c.fix_text, rule_version=c.rule_version,
                group_id=c.group_id, benchmark=c.benchmark, benchmark_release=c.benchmark_release,
                tags=["windows", "stig", "cklb"], raw_ref=c.raw_ref, collected_at=c.collected_at))
            continue
        i = out.index(n)
        evidence = n.evidence or ""
        if c.status != n.status and n.status != Status.NOT_REVIEWED:
            evidence += (f" | checklist status was {c.status.value}; this scan's own check of the live state "
                         f"({n.status.value}) is used")
        status = c.status if n.status == Status.NOT_REVIEWED else n.status
        if c.evidence:
            evidence += f" | checklist finding details: {c.evidence[:500]}"
        merged = make_finding(
            target=target, source=n.source, rule_id=n.rule_id, title=c.title or n.title, severity=c.severity,
            status=status, description=c.description or n.description, evidence=evidence.strip(" |"),
            references=[*refs, *(r.id for r in n.references)], check_text=c.check_text or n.check_text,
            fix_text=c.fix_text or n.fix_text, rule_version=n.rule_version, group_id=c.group_id or n.group_id,
            benchmark=c.benchmark or n.benchmark, benchmark_release=c.benchmark_release or n.benchmark_release,
            fix_ref=n.fix_ref, tags=[*n.tags, "cklb"], raw_ref=n.raw_ref, collected_at=n.collected_at)
        out[i] = merged
    return out
