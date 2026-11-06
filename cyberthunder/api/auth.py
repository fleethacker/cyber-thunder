"""Authenticate API requests, then enforce explicit route permissions before calling a service."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import compile_path

from cyberthunder.control.principal import Principal, principal_scope, operation_scope
from cyberthunder.control.roles import permissions, permits, route_action
from cyberthunder.security.step_up import StepUpPolicy, StepUpRequired, require_step_up


def mode_for(settings) -> str:
    StepUpPolicy.from_settings(settings)
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


def make_session_config(settings, state_dir: Path):
    from cyberthunder.security.oidc import OIDCConfig
    from cyberthunder.security.sessions import SessionConfig
    names = ("oidc_client_id", "oidc_authorization_endpoint", "oidc_token_endpoint", "oidc_redirect_uri")
    values = [getattr(settings, name, "") for name in names]
    if not any(values):
        return None
    if not all(values):
        raise ValueError("browser sign-in requires client ID, authorization endpoint, token endpoint and redirect URI")
    if getattr(settings, "oidc_authorized_party", None) != values[0]:
        raise ValueError("browser sign-in requires CT_OIDC_AUTHORIZED_PARTY to equal CT_OIDC_CLIENT_ID")
    return SessionConfig(settings.oidc_issuer, *values,
        id_token_config=OIDCConfig(issuer=settings.oidc_issuer, audience=values[0],
            jwks_url=settings.oidc_jwks_url, cache_path=state_dir.absolute() / "auth" / "id-jwks.json",
            max_age_s=settings.oidc_jwks_max_age, authorized_party=values[0]),
        client_secret_ref=settings.oidc_client_secret_ref, scope=settings.oidc_scope,
        idle_timeout_s=settings.session_idle_seconds, absolute_timeout_s=settings.session_absolute_seconds,
        step_up_max_age_s=settings.step_up_max_age_s, step_up_acr_values=settings.step_up_acr_values)


class AuthenticationMiddleware:
    def __init__(self, app, *, ctx, routes, mode: str, validator=None, sessions=None):
        self.app, self.ctx, self.routes, self.mode, self.validator = app, ctx, routes, mode, validator
        self.sessions = sessions

    def _refusal(self, action: str, route: str, reason: str, principal=None, challenge=None) -> None:
        # Never include request headers, query strings, tokens, bodies, or validator exceptions.
        with principal_scope(principal):
            self.ctx.audit.append("authorization.denied", principal.actor if principal else "unverified",
                                  {"action": action, "route": route, "reason": reason,
                                   **({"step_up": challenge} if challenge is not None else {})}, outcome="rejected")

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
        principal = validity = None
        reason, code = "authentication required", 401
        cookie_request = any(b"__Host-ct_session" in v for k, v in scope.get("headers", []) if k.lower() == b"cookie")
        if cookie_request and self.sessions is not None:
            try:
                request_headers = Headers(scope=scope)
                await run_in_threadpool(self.sessions.csrf_check, method, request_headers)
                touch = not (method == "GET" and route_path in {"/api/v1/status", "/api/v1/audit/verify", "/api/v1/audit/stream"})
                resolved = await run_in_threadpool(self.sessions.resolve_session_with_lease, request_headers, touch=touch)
                if resolved is None:
                    raise ValueError("invalid session")
                claims, lease = resolved
                def validity():
                    try:
                        lease()
                    except Exception:
                        raise PermissionError("the authenticated application session is no longer valid") from None
                principal = Principal.from_claims(claims, via=self.mode,
                    roles_claim=getattr(self.ctx.settings, "oidc_roles_claim", "ct_roles"))
            except Exception:
                reason = "session authentication or request verification failed"
        elif not cookie_request and len(headers) == 1 and len(headers[0]) <= 32768:
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
                # Preflight also covers batch routes that report per-item exceptions.
                # The core repeats this check alongside current resource authorization.
                try:
                    require_step_up(self.ctx.settings, principal, action)
                except StepUpRequired as exc:
                    from cyberthunder.api.errors import error_response
                    try:
                        await run_in_threadpool(self._refusal, action, route_path, "step-up required", principal, exc.challenge())
                        response = error_response(exc)
                    except Exception:
                        response = JSONResponse({"detail": "authorization audit unavailable"}, status_code=503,
                                                headers={"Cache-Control": "no-store"})
                    await response(scope, receive, send)
                    return
                scope.setdefault("state", {})["principal"] = principal
                async def private_send(message):
                    if message["type"] == "http.response.start":
                        message = dict(message)
                        response_headers = [(k, v) for k, v in message.get("headers", [])
                                            if k.lower() not in {b"cache-control", b"pragma", b"vary", b"x-content-type-options"}]
                        response_headers.extend([(b"cache-control", b"no-store"), (b"pragma", b"no-cache"),
                                                 (b"vary", b"Cookie, Authorization"), (b"x-content-type-options", b"nosniff")])
                        message["headers"] = response_headers
                    await send(message)
                with principal_scope(principal, validity=validity), operation_scope(action):
                    await self.app(scope, receive, private_send)
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
    if not hasattr(ctx, "session_config"):
        ctx.session_config = make_session_config(ctx.settings, Path(ctx.store.root)) if mode != "dev" else None
    def session_identity(claims):
        principal = Principal.from_claims(claims, via=mode, roles_claim=ctx.settings.oidc_roles_claim)
        return {"principal": {"actor": principal.actor, "name": principal.display_name,
                "subject": principal.subject, "issuer": principal.issuer, "source": principal.via,
                "roles": list(principal.roles), "verified": principal.verified},
                "permissions": sorted(permissions(principal))}
    ctx.session_status_identity = session_identity
    from cyberthunder.api.session_routes import install_sessions
    sessions = install_sessions(app, ctx, validator)
    app.state.sessions = sessions
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
    app.add_middleware(AuthenticationMiddleware, ctx=ctx, routes=routes, mode=mode, validator=validator, sessions=sessions)
