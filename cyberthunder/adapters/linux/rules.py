"""STIG rule metadata for the native checks, read from stig_rules.json.

stig_rules.json was built from the public RHEL 9 STIG (V2R9) rule pages: STIG ID, V-id, severity, title,
CCIs and a short check/fix summary per rule. Native checks take their identifiers from here so that a
finding never cites an ID that is not in that file. Checks for settings that have no confirmed STIG ID in
the file cite the CCI instead and say so in their description.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

RULES_PATH = Path(__file__).with_name("stig_rules.json")
BENCHMARK = "Red Hat Enterprise Linux 9 STIG"
RELEASE = "V2R9"
SSG_PREFIX = "xccdf_org.ssgproject.content_rule_"


@lru_cache(maxsize=1)
def stig_rules() -> dict[str, dict]:
    try:
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {r["stig_id"]: r for r in data if isinstance(r, dict) and r.get("stig_id")}


def rule(stig_id: str | None) -> dict:
    return stig_rules().get(stig_id or "", {})


def ssg_xccdf_id(stig_id: str) -> str | None:
    ssg = rule(stig_id).get("ssg_rule")
    return f"{SSG_PREFIX}{ssg}" if ssg else None
