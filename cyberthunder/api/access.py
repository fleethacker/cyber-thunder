"""Resource authorization before route execution and filtering before aggregation."""
from __future__ import annotations

from fastapi import Request

from cyberthunder.control.principal import authorize, current_operation, require_current
from cyberthunder.control.roles import route_action


def verified_mode(ctx) -> bool:
    return getattr(getattr(ctx, "settings", None), "auth_mode", "dev") != "dev"


def visible(ctx, target, action: str = "read") -> bool:
    return not verified_mode(ctx) or ctx.may_access(target, action)


def require_all(ctx, targets, action: str = "read") -> None:
    for target in targets:
        authorize(ctx, action, target=target)


def require_resource(ctx, target, action: str | None = None) -> None:
    authorize(ctx, action or current_operation() or "read", target=target)


# These handlers filter before pagination/aggregation, or enforce each resource in their core service.
SCOPED = {
    ("GET", "/targets"), ("GET", "/findings"), ("GET", "/proposals"), ("GET", "/scans"),
    ("GET", "/scans/preflight"), ("GET", "/scans/{scan_id}"),
    ("POST", "/scans"), ("POST", "/scan"), ("POST", "/findings/explain"),
    ("POST", "/proposals/bulk"), ("POST", "/generate/explain"), ("POST", "/generate/propose"),
    ("POST", "/apply"), ("POST", "/rollback"), ("POST", "/reports"),
    ("GET", "/cluster/survey"), ("POST", "/cluster/baseline"),
    ("GET", "/outbox"), ("POST", "/outbox/sync"),
    ("GET", "/cluster/risk"), ("GET", "/cluster/known-good"),
    ("POST", "/cluster/known-good/exceptions"), ("DELETE", "/cluster/known-good/exceptions/{exception_id}"),
}


async def authorize_request(request: Request) -> None:
    ctx = request.app.state.ctx
    if not verified_mode(ctx):
        return
    path = request.scope["route"].path.removeprefix("/api/v1")
    method = request.method
    action = route_action(method, path)
    if action is None:
        raise PermissionError("route has no authorization policy")
    require_current(action)
    if path in {"/demo", "/demo/load", "/demo/reset"} and method != "GET":
        raise PermissionError("demonstration controls are available only in local development mode")
    params = request.path_params
    if "target_id" in params:
        authorize(ctx, action, target=params["target_id"])
        # Connection declarations are node configuration, separate from rights on that target.
        if method in {"PUT", "DELETE"}:
            authorize(ctx, "admin")
        return
    if "finding_id" in params:
        from cyberthunder.api.util import get_finding
        finding = get_finding(ctx, params["finding_id"])
        authorize(ctx, action, target=finding.host)
        return
    if "pid" in params:
        from cyberthunder.api.util import get_proposal
        proposal = get_proposal(ctx, params["pid"])
        authorize(ctx, action, target=proposal.host)
        return
    if "assessment_id" in params:
        receipt = ctx.impact.get(params["assessment_id"])
        if receipt is None:
            raise KeyError("unknown dependency assessment")
        # Receipt schemas may evolve; never allow an unrecognized association through.
        proposal_id = receipt.get("proposal_id")
        if not isinstance(proposal_id, str):
            raise PermissionError("assessment resource association unavailable")
        from cyberthunder.api.util import get_proposal
        proposal = get_proposal(ctx, proposal_id)
        from cyberthunder.security.resources import check_record
        check_record(ctx, proposal, action)
        return
    if (method, path) in SCOPED:
        return
    # Node-wide views and operations require an explicit node grant. No target grant implies one.
    authorize(ctx, action)
    if action == "read":
        # Unfiltered node history can include removed targets. Current inventory grants
        # cannot prove ownership of that data; require an explicit global read grant.
        authorize(ctx, "read.all")
    if action in {"read", "export", "import", "admin", "discover", "scan", "policy"}:
        # Global reports, history and catalog selection can contain data from several environments.
        require_all(ctx, ctx.inventory.all())
