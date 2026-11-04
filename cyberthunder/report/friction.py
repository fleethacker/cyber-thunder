"""Friction log: policy, data, authority, ATO, tooling and range barriers met while building.

Submission asks for these explicitly, so they are data in docs/friction.yaml and render on demand.
"""
from __future__ import annotations

import yaml

from cyberthunder.report.render import ReportError, find_doc, render

AREAS = ("policy", "data", "authority", "ato", "tooling", "range")
FIELDS = ("id", "area", "what", "impact", "workaround", "ask")


def load_friction(ctx=None) -> list[dict]:
    path = find_doc(ctx, "friction.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("entries", [])
    for e in entries:
        absent = [k for k in FIELDS if not e.get(k)]
        if absent:
            raise ReportError(f"{path}: entry {e.get('id', '?')} is missing {', '.join(absent)}")
        if e["area"] not in AREAS:
            raise ReportError(f"{path}: entry {e['id']} has unknown area {e['area']!r}; expected one of {AREAS}")
    return entries


def render_friction(entries: list[dict], fmt: str, *, audit_head: str = "", node: str = "") -> str:
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["area"]] = counts.get(e["area"], 0) + 1
    return render("friction", fmt, entries=entries, counts=counts, audit_head=audit_head, node=node)
