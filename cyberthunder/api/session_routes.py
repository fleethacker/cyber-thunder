"""Root browser-login routes with their own session and CSRF boundary."""

import json

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from cyberthunder.security.oidc import AuthenticationError
from cyberthunder.security.sessions import LOGIN_COOKIE, SESSION_COOKIE, SessionConfig, SessionService


def _reauth_body(data):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise AuthenticationError()
            result[name] = value
        return result
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) - {"return_to"}:
        raise AuthenticationError()
    return value.get("return_to", "/")


def _private(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _cookie(response, name, value, age):
    response.set_cookie(name, value, max_age=age, secure=True, httponly=True, samesite="lax", path="/")


def _clear(response, name):
    response.delete_cookie(name, secure=True, httponly=True, samesite="lax", path="/")


def _error(status=401):
    return _private(JSONResponse({"detail": "Authentication failed"}, status_code=status))


def _identity(value):
    """Accept only the parent's small public identity projection, never claims."""
    if not isinstance(value, dict):
        raise AuthenticationError()
    permissions = value.get("permissions", [])
    if (not isinstance(permissions, list) or len(permissions) > 128
            or any(not isinstance(item, str) or len(item) > 128 for item in permissions)):
        raise AuthenticationError()
    result = {"permissions": permissions}
    principal = value.get("principal")
    if principal is not None:
        if not isinstance(principal, dict):
            raise AuthenticationError()
        public = {}
        for name in ("actor", "name", "subject", "issuer", "source", "identity_ref"):
            if name in principal:
                if not isinstance(principal[name], str) or len(principal[name]) > 2048:
                    raise AuthenticationError()
                public[name] = principal[name]
        if "verified" in principal:
            if type(principal["verified"]) is not bool:
                raise AuthenticationError()
            public["verified"] = principal["verified"]
        if "roles" in principal:
            roles = principal["roles"]
            if not isinstance(roles, list) or len(roles) > 64 or any(not isinstance(role, str) or len(role) > 128 for role in roles):
                raise AuthenticationError()
            public["roles"] = roles
        result["principal"] = public
    return result


def install_sessions(app, ctx, access_validator):
    """Install before the UI mount. No configuration means sessionless status."""
    mode = getattr(ctx.settings, "auth_mode", "dev")
    config = getattr(ctx, "session_config", None)
    if mode not in {"dev", "oidc", "mesh"} or config is not None and (
            mode == "dev" or not isinstance(config, SessionConfig)):
        raise AuthenticationError()
    service = SessionService(config, access_validator) if config is not None else None

    @app.get("/auth/status", include_in_schema=False)
    def status(request: Request):
        body = {"mode": mode, "authenticated": False, "login_available": service is not None, "permissions": []}
        if service is not None:
            try:
                claims, metadata = service.session_info(request.headers)
                projection = getattr(ctx, "session_status_identity", None)
                identity = _identity(projection(claims)) if callable(projection) else {}
                body.update(metadata)
                body.update(identity)
            except Exception:
                # Invalid or expired sessions report signed-out status. This is
                # not the API authentication path and never permits actor fallback.
                pass
        return _private(JSONResponse(body))

    @app.get("/auth/login", include_in_schema=False)
    def login(request: Request):
        if service is None:
            return _error(404)
        try:
            if request.scope.get("query_string"):
                raise AuthenticationError()
            url, cookie = service.start_login(request.headers)
            response = _private(RedirectResponse(url, status_code=303))
            _cookie(response, LOGIN_COOKIE, cookie, config.login_timeout_s)
            return response
        except Exception:
            return _error()

    @app.get("/auth/callback", include_in_schema=False)
    def callback(request: Request):
        if service is None:
            return _error(404)
        try:
            raw_query = request.scope.get("query_string", b"")
            # Standard ASGI access loggers observing this scope need not retain
            # authorization codes. Ingress logs must also redact callback queries.
            request.scope["query_string"] = b""
            query = raw_query.decode("ascii")
            cookie, return_to = service.finish_login(query, request.headers)
            response = _private(RedirectResponse(service.origin + return_to, status_code=303))
            _cookie(response, SESSION_COOKIE, cookie, config.absolute_timeout_s)
            _clear(response, LOGIN_COOKIE)
            return response
        except Exception:
            response = _error()
            _clear(response, LOGIN_COOKIE)
            return response

    @app.post("/auth/reauthenticate", include_in_schema=False)
    async def reauthenticate(request: Request):
        if service is None:
            return _error(404)
        try:
            if request.scope.get("query_string"):
                raise AuthenticationError()
            await run_in_threadpool(service.csrf_check, "POST", request.headers)
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > 8192:
                    raise AuthenticationError()
                data.extend(chunk)
            url, cookie = await run_in_threadpool(service.start_login, request.headers,
                step_up=True, return_to=_reauth_body(bytes(data)))
            response = _private(JSONResponse({"authorization_url": url}))
            _cookie(response, LOGIN_COOKIE, cookie, config.login_timeout_s)
            return response
        except Exception:
            return _error()

    @app.post("/auth/logout", include_in_schema=False)
    def logout(request: Request):
        if service is None:
            return _error(404)
        try:
            service.logout(request.headers)
            response = _private(Response(status_code=204))
            _clear(response, SESSION_COOKIE)
            _clear(response, LOGIN_COOKIE)
            return response
        except Exception:
            # Do not clear a valid browser cookie on a rejected CSRF attempt.
            return _error(403)

    return service
