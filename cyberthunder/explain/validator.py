"""Validates model output before anyone sees it.

The model's answer is untrusted text. This module parses it as JSON, keeps only the four expected fields,
clamps their length, and keeps only citations that are identifiers already attached to the finding (or the
resolved fix_ref). Anything else is dropped and reported. Output from here is display text only.
"""
from __future__ import annotations

import json
import re

from cyberthunder.findings.schema import (RE_ATTACK, RE_CCE, RE_CCI, RE_CVE, RE_GROUP_ID, RE_IAVM, RE_STIG_ID,
                                          RE_STIG_RULE, Finding)
from cyberthunder.remediation.library import FixEntry

LIMITS = {"risk": 600, "impact": 300, "plan": 300}
ID_PATTERNS = (RE_STIG_RULE, RE_GROUP_ID, RE_STIG_ID, RE_CCI, RE_CCE, RE_CVE, RE_ATTACK, RE_IAVM)

_FENCE = re.compile(r"```[a-zA-Z]*")
# A citation that looks like a command or a path is rejected outright, even if it contains a valid id.
_SHELL = re.compile(r"[;|&`$<>\\]|\$\(|\b(?:rm|curl|wget|sudo|chmod|chown|bash|sh|powershell|cmd|echo|nc|python)\b"
                    r"|(?:^|\s)/[\w.-]+/", re.IGNORECASE)


def strip_fences(text: str) -> str:
    return _FENCE.sub("", text).replace("```", "").strip()


def extract_json_object(text: str) -> dict | None:
    """Parse the whole text as JSON, or else the first balanced {...} block in it."""
    t = strip_fences(text or "")
    try:
        obj = json.loads(t)
        return obj if isinstance(obj, dict) else None
    except ValueError:
        pass
    start = t.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(t)):
            c = t[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(t[start:i + 1])
                        return obj if isinstance(obj, dict) else None
                    except ValueError:
                        break
        start = t.find("{", start + 1)
    return None


def clamp(text: str, limit: int) -> str:
    t = " ".join(text.split())
    if len(t) <= limit:
        return t
    cut = t[: limit - 3]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:") + "..."


def looks_like_shell(text: str) -> bool:
    return bool(_SHELL.search(text))


def normalise_citation(raw: str, allowed: set[str]) -> list[str]:
    """Identifiers found in one raw citation string, in order. Exact matches on allowed ids (fix_ref,
    ComplianceAsCode rule ids) count, as do any identifiers matched by the schema patterns."""
    s = raw.strip().strip("\"'[](){}.,")
    if not s:
        return []
    if s in allowed:
        return [s]
    out: list[str] = []
    for rx in ID_PATTERNS:
        for m in rx.findall(s):
            if m not in out:
                out.append(m)
    return out


def validate(text: str | None, finding: Finding, fix: FixEntry | None = None) -> tuple[dict | None, list[str]]:
    """Return ({risk, impact, plan, citations}, dropped) or (None, dropped) when the answer is unusable."""
    dropped: list[str] = []
    if not text:
        return None, dropped
    obj = extract_json_object(text)
    if obj is None:
        return None, dropped
    out: dict = {}
    for key, limit in LIMITS.items():
        v = obj.get(key)
        if not isinstance(v, str) or not v.strip():
            return None, dropped
        out[key] = clamp(v, limit)
    cites = obj.get("citations")
    if isinstance(cites, str):
        cites = [cites]
    if not isinstance(cites, list):
        return None, dropped

    allowed = set(finding.citations)
    if fix and fix.fix_ref:
        allowed.add(fix.fix_ref)
    kept: list[str] = []
    for c in cites:
        if not isinstance(c, str):
            dropped.append(str(c)[:80])
            continue
        if c.strip() in allowed:          # exact copy of an id already attached to the finding
            if c.strip() not in kept:
                kept.append(c.strip())
            continue
        if looks_like_shell(c):
            dropped.append(c[:80])
            continue
        ids = normalise_citation(c, allowed)
        if not ids:
            dropped.append(c[:80])
            continue
        for i in ids:
            if i in allowed:
                if i not in kept:
                    kept.append(i)
            elif i not in dropped:
                dropped.append(i)
    if not kept:
        return None, dropped
    out["citations"] = kept
    return out, dropped
