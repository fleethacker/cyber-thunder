"""Merge DISA SCAP benchmark results with this adapter's native checks.

Rules are matched by STIG ID (rule_version). For a matched rule the benchmark's OVAL result wins: the finding
takes the benchmark's status, title, severity, fix text and evidence. It keeps the native finding's id
(source and rule id), fix reference and check text, so proposals and history recorded before a datastream was
configured still point at the same finding. One exception: when the benchmark could not decide a rule
(not_reviewed) and the native check did, the native result is kept and the evidence says why.

Native checks for rules the datastream lacks are kept as they are; benchmark rules with no native check are
added as their own findings (source windows-scap).
"""
from __future__ import annotations

from cyberthunder.adapters.base import make_finding
from cyberthunder.findings.schema import Finding, Status


def merge(target, native: list[Finding], bench: list[Finding]) -> list[Finding]:
    by_version = {f.rule_version: i for i, f in enumerate(native) if f.rule_version}
    out = list(native)
    for b in bench:
        i = by_version.get(b.rule_version) if b.rule_version else None
        if i is None:
            out.append(b)
            continue
        n = native[i]
        refs = [*(r.id for r in b.references), *(r.id for r in n.references)]
        if b.status == Status.NOT_REVIEWED and n.status != Status.NOT_REVIEWED:
            status = n.status
            evidence = f"{n.evidence or ''} | SCAP benchmark could not decide this rule: {b.evidence or ''}"
            tags = [*n.tags, "scap:undecided"]
        else:
            status = b.status
            evidence = f"SCAP benchmark (OVAL): {b.evidence or ''}"
            if n.status != b.status and n.status != Status.NOT_REVIEWED:
                evidence += f" | native check said {n.status.value}: {n.evidence or ''}"
            tags = [*n.tags, *(t for t in b.tags if t not in n.tags)]
        out[i] = make_finding(
            target=target, source=n.source, rule_id=n.rule_id, title=b.title or n.title, severity=b.severity,
            status=status, description=b.description or n.description, evidence=evidence.strip(" |"),
            references=refs, check_text=n.check_text or b.check_text, fix_text=b.fix_text or n.fix_text,
            rule_version=n.rule_version, group_id=b.group_id or n.group_id, benchmark=b.benchmark or n.benchmark,
            benchmark_release=b.benchmark_release or n.benchmark_release, fix_ref=n.fix_ref, tags=tags,
            raw_ref=b.raw_ref or n.raw_ref, collected_at=b.collected_at or n.collected_at)
    return out
