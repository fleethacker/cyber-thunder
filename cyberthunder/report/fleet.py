"""One-page path to fleet, rendered from docs/fleet.yaml so the owners can edit facts without touching code."""
from __future__ import annotations

import yaml

from cyberthunder.report.render import ReportError, find_doc, render

REQUIRED = ("mission_owner", "technical_owner", "destination", "next_experiment", "required_resources",
            "timeline", "authorization_path", "measures_of_success", "guardrails")
GUARDRAIL_KEYS = ("may", "never", "requires_approval", "logged", "stopped")


def load_fleet(ctx=None) -> dict:
    path = find_doc(ctx, "fleet.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    missing = [k for k in REQUIRED if not data.get(k)]
    missing += [f"guardrails.{k}" for k in GUARDRAIL_KEYS if not (data.get("guardrails") or {}).get(k)]
    if missing:
        raise ReportError(f"{path} is missing: {', '.join(missing)}")
    data["timeline"] = sorted(data["timeline"], key=lambda t: int(t["day"]))
    return data


def render_fleet(data: dict, fmt: str, *, audit_head: str = "", node: str = "") -> str:
    return render("fleet", fmt, f=data, audit_head=audit_head, node=node)
