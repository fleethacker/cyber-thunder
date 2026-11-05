"""Keycloak access tokens forwarded by UDS Authservice.

Mesh mode never trusts a display-name header. The browser session stays at the gateway; this process
only sees the bearer token Authservice adds after Keycloak accepts the login. The token signature is
checked against Keycloak's published keys. The token itself is not logged.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import jwt
from jwt import PyJWK

from cyberthunder.config import Settings

ALLOWED_ALGS = ["RS256", "ES256"]
_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, dict[str, dict]]] = {}


class AuthError(Exception):
    """The request has no acceptable Keycloak session."""


@dataclass(frozen=True)
class Principal:
    actor: str
    subject: str
    issuer: str
    username: str


def fetch_jwks(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeError) as e:
        raise AuthError("Keycloak signing keys are unavailable") from e


def clear_jwks_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def _keys(url: str, max_age_s: int, kid: str | None) -> dict[str, dict]:
    now = time.time()
    with _LOCK:
        fetched_at, keys = _CACHE.get(url, (0.0, {}))
        fresh = keys and now - fetched_at <= max_age_s
        if fresh and (not kid or kid in keys):
            return keys
    try:
        document = fetch_jwks(url)
    except AuthError:
        with _LOCK:
            fetched_at, keys = _CACHE.get(url, (0.0, {}))
        if keys and now - fetched_at <= max_age_s:
            return keys
        raise
    parsed = {item["kid"]: item for item in document.get("keys", []) if item.get("kid") and item.get("use", "sig") == "sig"}
    if not parsed:
        raise AuthError("Keycloak published no signing keys")
    with _LOCK:
        _CACHE[url] = (now, parsed)
    return parsed


def _bearer(header: str | None) -> str:
    if not header:
        raise AuthError("sign in through Keycloak")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("sign in through Keycloak")
    return token.strip()


def _username(claims: dict) -> str:
    for claim in ("preferred_username", "name", "sub"):
        value = claims.get(claim)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise AuthError("sign-in token did not name a person")


def authenticate(request, settings: Settings) -> Principal:
    """Validate the forwarded access token and return the Keycloak user it names."""
    issuer = (settings.oidc_issuer or "").strip().rstrip("/")
    client_id = (settings.oidc_client_id or "").strip()
    if not issuer or not client_id:
        raise AuthError("Keycloak authentication is not configured")
    jwks_url = (settings.oidc_jwks_url or "").strip() or f"{issuer}/protocol/openid-connect/certs"
    token = _bearer(request.headers.get("authorization"))
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise AuthError("sign-in token was not accepted") from e
    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGS:
        raise AuthError("sign-in token signing algorithm was not accepted")
    kid = header.get("kid")
    keys = _keys(jwks_url, settings.oidc_jwks_max_age_s, kid if isinstance(kid, str) else None)
    if not isinstance(kid, str) or kid not in keys:
        keys = _keys(jwks_url, 0, kid if isinstance(kid, str) else None)
    jwk = keys.get(kid) if isinstance(kid, str) else None
    if not jwk:
        raise AuthError("sign-in token was not accepted")
    options = {"verify_aud": bool(settings.oidc_audience), "require": ["exp", "iss", "sub"]}
    try:
        claims = jwt.decode(
            token,
            PyJWK.from_dict(jwk).key,
            algorithms=ALLOWED_ALGS,
            issuer=issuer,
            audience=settings.oidc_audience or None,
            leeway=60,
            options=options,
        )
    except jwt.ExpiredSignatureError as e:
        raise AuthError("sign-in token has expired") from e
    except jwt.InvalidIssuerError as e:
        raise AuthError("sign-in token issuer was not accepted") from e
    except jwt.InvalidAudienceError as e:
        raise AuthError("sign-in token audience was not accepted") from e
    except jwt.PyJWTError as e:
        raise AuthError("sign-in token was not accepted") from e
    if claims.get("azp") != client_id:
        raise AuthError("sign-in token was not issued for this application")
    username = _username(claims)
    return Principal(actor=username, subject=str(claims["sub"]), issuer=issuer, username=username)
