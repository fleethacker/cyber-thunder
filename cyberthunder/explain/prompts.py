"""Prompts for the explain layer.

The model is given one finding as labelled lines and the exact list of identifiers it may cite. It is asked
for JSON only. Nothing it returns is ever executed; the validator keeps only known identifiers.
"""
from __future__ import annotations

from cyberthunder.findings.schema import Finding
from cyberthunder.remediation.library import FixEntry

EVIDENCE_MAX = 400
DESCRIPTION_MAX = 600

SYSTEM = (
    "You are the explain module of a Navy cyber defense tool running on an isolated shipboard network. "
    "Your audience is the commanding officer and the system owner: plain language, no jargon, no commands. "
    "You explain one finding produced by a deterministic scanner. You do not decide or perform any action; "
    "a human approves every change.\n"
    "Return ONLY a JSON object with exactly these keys:\n"
    '  "risk": two sentences on what is wrong and why it matters, ending with what to do,\n'
    '  "impact": one sentence on mission impact (availability, integrity, confidentiality of shipboard systems),\n'
    '  "plan": one sentence naming the proposed fix and stating that it requires approval before it is applied,\n'
    '  "citations": a list of identifiers you relied on, chosen ONLY from the Allowed citations line.\n'
    "Do not invent STIG IDs, CVE numbers or any other identifier."
)

STRICT = (
    "Your previous answer was rejected. Output a single JSON object and nothing else: no prose, no code "
    "fences, no markdown. Keys: risk, impact, plan (strings) and citations (a non-empty list). Every "
    "citation must be copied exactly from the Allowed citations line. Do not include shell commands."
)


def _trim(text: str | None, limit: int) -> str:
    t = " ".join((text or "").split())
    return t if len(t) <= limit else t[: limit - 3].rstrip() + "..."


def allowed_citations(finding: Finding, fix: FixEntry | None) -> list[str]:
    out = list(finding.citations)
    if fix and fix.fix_ref and fix.fix_ref not in out:
        out.append(fix.fix_ref)
    return out


def finding_block(finding: Finding, fix: FixEntry | None) -> str:
    lines = [
        f"Host: {finding.host}",
        f"Asset type: {finding.asset_type or 'unknown'}",
        f"Rule id: {finding.rule_id}",
        f"STIG ID: {finding.rule_version or '-'}",
        f"Group: {finding.group_id or '-'}",
        f"Severity: {finding.severity.cat} ({finding.severity.value})",
        f"Title: {_trim(finding.title, 200)}",
        f"Status: {finding.status.value}",
        f"Evidence: {_trim(finding.evidence, EVIDENCE_MAX) or '-'}",
        f"Description: {_trim(finding.description, DESCRIPTION_MAX) or '-'}",
        f"Allowed citations (the ONLY identifiers you may cite): {', '.join(allowed_citations(finding, fix)) or '-'}",
    ]
    if fix:
        lines.append(f"Proposed fix: {fix.title} ({fix.fix_ref})")
        lines.append(f"Fix blast radius: {', '.join(fix.risk_tags())}")
    else:
        lines.append("Proposed fix: none in the vetted library; say a vetted fix or manual steps are needed")
    return "\n".join(lines)


def build_prompt(finding: Finding, fix: FixEntry | None = None, *, strict: bool = False) -> str:
    parts = [SYSTEM]
    if strict:
        parts.append(STRICT)
    parts.append("Finding:\n" + finding_block(finding, fix))
    parts.append("JSON:")
    return "\n\n".join(parts)


def build_strict_prompt(finding: Finding, fix: FixEntry | None = None) -> str:
    return build_prompt(finding, fix, strict=True)
