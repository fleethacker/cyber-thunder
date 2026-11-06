"""Explicit permissions; unknown actions and new write routes fail closed."""
from __future__ import annotations

READ = frozenset({"read", "read.all", "kill.engage"})
ROLE_PERMISSIONS = {
    "viewer": READ,
    "analyst": READ | {"scan", "discover", "propose", "explain", "plan", "import"},
    "approver": READ | {"approve", "deny", "cancel", "apply", "rollback", "verify", "plan", "review", "risk.accept", "maintenance.override"},
    "admin": READ | {"admin", "policy", "kill.release"},
    "auditor": READ | {"audit", "export"},
}
HUMAN_ACTIONS = frozenset({"approve", "deny", "cancel", "apply", "rollback", "verify", "review", "risk.accept", "maintenance.override", "admin", "policy", "kill.release"})


def permissions(principal) -> frozenset[str]:
    allowed = frozenset().union(*(ROLE_PERMISSIONS.get(role, frozenset()) for role in principal.roles))
    return allowed if principal.kind == "human" else allowed - HUMAN_ACTIONS


def permits(principal, action: str) -> bool:
    return action in permissions(principal)


# Route templates, never prefix matches against attacker-controlled URLs.
WRITE_ACTIONS = {
    ("POST", "/demo/load"): "admin", ("POST", "/demo/reset"): "admin", ("PUT", "/demo"): "admin",
    ("POST", "/cluster/baseline"): "scan", ("POST", "/cluster/known-good/exceptions"): "admin",
    ("POST", "/cluster/known-good/from-finding/{finding_id}"): "admin", ("DELETE", "/cluster/known-good/exceptions/{exception_id}"): "admin",
    ("POST", "/findings/explain"): "explain", ("POST", "/findings/{finding_id}/propose"): "propose",
    ("POST", "/findings/{finding_id}/explain"): "explain", ("PUT", "/findings/{finding_id}/review"): "review",
    ("PUT", "/findings/{finding_id}/risk-acceptance"): "risk.accept",
    ("POST", "/findings/{finding_id}/risk-acceptance/revoke"): "risk.accept",
    ("PUT", "/discovery/scopes"): "admin", ("POST", "/discovery/scopes/preview"): "read",
    ("GET", "/discovery/scopes/recipes"): "read", ("PUT", "/discovery/scopes/recipes"): "admin",
    ("POST", "/discovery/scopes/recipes/preview"): "read",
    ("PUT", "/discovery/scopes/ranges"): "admin", ("POST", "/discovery/sweep"): "discover",
    ("POST", "/discovery/vsphere/{target_id}/collect"): "discover",
    ("POST", "/discovery/assets/{asset_id}/accept"): "admin", ("POST", "/discovery/assets/{asset_id}/ignore"): "admin",
    ("POST", "/ingest/scanner"): "import", ("PUT", "/ingest/link"): "admin", ("POST", "/ingest/link/probe"): "admin",
    ("POST", "/ingest/stig"): "import", ("POST", "/ingest/stig/{delta_id}/rescan"): "scan",
    ("POST", "/ingest/bulletin"): "import", ("POST", "/outbox/sync"): "export",
    ("PUT", "/ingest/library/preferences"): "admin", ("POST", "/ingest/content/upload"): "import",
    ("POST", "/ingest/updates/check"): "admin", ("POST", "/ingest/updates/pull"): "admin",
    ("POST", "/ingest/manifest"): "export", ("POST", "/ingest/import-dir"): "import",
    ("POST", "/proposals/bulk"): "approve", ("POST", "/proposals/{pid}/approve"): "approve",
    ("POST", "/proposals/{pid}/impact"): "plan", ("POST", "/proposals/{pid}/review-impact"): "review",
    ("POST", "/proposals/{pid}/deny"): "deny", ("POST", "/proposals/{pid}/cancel"): "cancel",
    ("POST", "/proposals/{pid}/plan"): "plan", ("POST", "/proposals/{pid}/apply"): "apply",
    ("POST", "/proposals/{pid}/rollback"): "rollback", ("POST", "/proposals/{pid}/verify"): "verify",
    ("POST", "/kill/engage"): "kill.engage", ("POST", "/kill/release"): "kill.release",
    ("PUT", "/policy"): "policy", ("POST", "/policy/evaluate"): "read", ("POST", "/reports/queue"): "export",
    ("POST", "/scans"): "scan", ("POST", "/targets"): "admin", ("POST", "/targets/register-host"): "admin",
    ("PUT", "/targets/{target_id}"): "admin", ("DELETE", "/targets/{target_id}"): "admin",
    ("POST", "/targets/{target_id}/discover"): "discover",
    ("PUT", "/vulnerabilities/settings"): "admin", ("POST", "/vulnerabilities/update"): "admin",
    ("POST", "/vulnerabilities/import"): "import", ("POST", "/vulnerabilities/export"): "export",
    ("POST", "/discover"): "discover", ("POST", "/scan"): "scan",
    ("POST", "/generate/explain"): "explain", ("POST", "/generate/propose"): "propose",
    ("POST", "/apply"): "apply", ("POST", "/rollback"): "rollback",
    ("POST", "/reports"): "export",
}


READ_ROUTES = frozenset({
    "/change-assessments/{assessment_id}", "/cluster/known-good", "/cluster/risk", "/demo", "/discovery",
    "/discovery/applicable", "/discovery/assets", "/discovery/assets/{asset_id}", "/discovery/findings",
    "/discovery/runs", "/discovery/runs/{run_id}", "/discovery/scopes/recipes", "/findings",
    "/discovery/vsphere/{target_id}/runs", "/discovery/vsphere/{target_id}/runs/{run_id}",
    "/findings/{finding_id}", "/findings/{finding_id}/review", "/ingest/content", "/ingest/history",
    "/ingest/library", "/ingest/link", "/ingest/updates", "/ingest/updates/jobs/{job_id}", "/kill",
    "/outbox", "/policy", "/proposals", "/proposals/{pid}", "/proposals/{pid}/diff",
    "/proposals/{pid}/impact", "/receive/cve", "/receive/stig", "/runtime/context", "/scans",
    "/scans/preflight", "/scans/{scan_id}", "/status", "/targets", "/targets/{target_id}/readiness",
    "/vulnerabilities", "/vulnerabilities/jobs", "/vulnerabilities/jobs/{job_id}", "/whoami",
    "/api/docs", "/api/openapi.json",
})
EXPORT_ROUTES = frozenset({
    "/reports/checklist.cklb", "/reports/commander", "/reports/coverage", "/reports/fleet",
    "/reports/friction", "/reports/history", "/reports/history/{report_id}",
    "/reports/history/{report_id}/download", "/reports/poam.csv", "/reports/score", "/reports/{target_id}",
})


def route_action(method: str, path: str) -> str | None:
    relative = path.removeprefix("/api/v1")
    if method in {"GET", "HEAD"}:
        if relative == "/cluster/survey":
            return "discover"
        if relative in EXPORT_ROUTES:
            return "export"
        if relative in {"/audit", "/audit/stream", "/audit/verify"}:
            return "audit"
        return "read" if relative in READ_ROUTES else None
    return WRITE_ACTIONS.get((method, relative))
