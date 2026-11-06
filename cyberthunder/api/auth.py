"""Authenticate API requests, then enforce explicit route permissions before calling a service."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.routing import compile_path

from cyberthunder.control.principal import Principal, principal_scope, operation_scope
from cyberthunder.control.roles import permissions, permits, route_action


def mode_for(settings) -> str:
    mode = getattr(settings, "auth_mode", "dev")
    profile = getattr(settings, "security_mode", "range")
    if mode not in {"dev", "oidc", "mesh"} or profile not in {"range", "fleet"}:
        raise ValueError("invalid authentication mode or security profile")
    if profile == "fleet" and mode == "dev":
        raise ValueError("fleet security requires verified authentication")
    return mode


def validate_bind(settings, host: str) -> None:
    mode = mode_for(settings)
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.casefold() == "localhost"
    if mode == "dev" and not loopback:
        raise ValueError("development authentication may bind only to loopback; configure oidc or mesh for network access")
    cert, key = getattr(settings, "tls_cert", None), getattr(settings, "tls_key", None)
    if bool(cert) != bool(key):
        raise ValueError("both CT_TLS_CERT and CT_TLS_KEY are required")
    if not loopback and mode != "mesh" and not cert:
        raise ValueError("network access requires TLS or an authenticated mesh gateway")


def make_validator(settings, state_dir: Path):
    from cyberthunder.security.oidc import OIDCConfig, OIDCValidator
    cache_dir = state_dir.absolute() / "auth"
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return OIDCValidator(OIDCConfig(
        issuer=getattr(settings, "oidc_issuer", ""), audience=getattr(settings, "oidc_audience", ""),
        jwks_url=getattr(settings, "oidc_jwks_url", ""), cache_path=cache_dir / "jwks.json",
        max_age_s=getattr(settings, "oidc_jwks_max_age", 86400),
        authorized_party=getattr(settings, "oidc_authorized_party", None)))


class AuthenticationMiddleware:
    def __init__(self, app, *, ctx, routes, mode: str, validator=None):
        self.app, self.ctx, self.routes, self.mode, self.validator = app, ctx, routes, mode, validator

    def _refusal(self, action: str, route: str, reason: str, principal=None) -> None:
        # Never include request headers, query strings, tokens, bodies, or validator exceptions.
        with principal_scope(principal):
            self.ctx.audit.append("authorization.denied", principal.actor if principal else "unverified",
                                  {"action": action, "route": route, "reason": reason}, outcome="rejected")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/") or self.mode == "dev":
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        route_path, action = "/api/unknown", None
        for route_method, template, pattern in self.routes:
            if route_method == method and pattern.fullmatch(scope["path"]):
                route_path = template
                action = route_action(method, route_path)
                break
        headers = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        principal = None
        reason, code = "authentication required", 401
        if len(headers) == 1 and len(headers[0]) <= 32768:
            try:
                scheme, value = headers[0].decode("ascii").split(" ", 1)
                if scheme.casefold() != "bearer" or not value or value.strip() != value:
                    raise ValueError("invalid credential")
                claims = await run_in_threadpool(self.validator.validate, value)
                principal = Principal.from_claims(claims, via=self.mode,
                    roles_claim=getattr(self.ctx.settings, "oidc_roles_claim", "ct_roles"))
            except Exception:
                reason = "authentication failed"
        if principal is not None:
            if action is None:
                reason, code = "route has no authorization policy", 403
            elif not permits(principal, action):
                reason, code = "role does not permit this action", 403
            else:
                scope.setdefault("state", {})["principal"] = principal
                with principal_scope(principal), operation_scope(action):
                    await self.app(scope, receive, send)
                return
        try:
            await run_in_threadpool(self._refusal, action or "unknown", route_path, reason, principal)
        except Exception:
            reason, code = "authorization audit unavailable", 503
        await JSONResponse({"detail": reason}, status_code=code,
                           headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})(scope, receive, send)


def install_auth(app, ctx):
    mode = mode_for(ctx.settings)
    validate_bind(ctx.settings, getattr(ctx.settings, "host", "127.0.0.1"))
    @app.get("/api/v1/whoami", tags=["identity"])
    def whoami():
        from cyberthunder.control.principal import current_principal
        principal = current_principal()
        return {"mode": mode, "principal": {**principal.evidence(), "actor": principal.actor} if principal else None,
                "permissions": sorted(permissions(principal)) if principal else [],
                "verified": bool(principal and principal.verified)}

    validator = make_validator(ctx.settings, Path(ctx.store.root)) if mode != "dev" else None
    routes = []
    # Use the public schema rather than framework-private included-router wrappers. Undocumented
    # API routes are denied by the middleware until deliberately added to this policy table.
    for path, methods in app.openapi()["paths"].items():
        if not path.startswith("/api/v1"):
            continue
        for method in methods:
            if method not in {"get", "head", "post", "put", "patch", "delete", "options", "trace"}:
                continue
            if route_action(method.upper(), path) is None:
                raise ValueError(f"route lacks authorization policy: {method.upper()} {path}")
            routes.append((method.upper(), path, compile_path(path)[0]))
    for path in ("/api/docs", "/api/openapi.json"):
        routes.append(("GET", path, compile_path(path)[0]))
    app.add_middleware(AuthenticationMiddleware, ctx=ctx, routes=routes, mode=mode, validator=validator)
