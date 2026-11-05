"""Mesh mode records the Keycloak user from the access token, not the typed X-Actor name."""
from __future__ import annotations

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cyberthunder.api.auth import clear_jwks_cache

ISSUER = "https://sso.uds.dev/realms/uds"
JWKS_URL = "http://keycloak-http.keycloak.svc.cluster.local:8080/realms/uds/protocol/openid-connect/certs"
CLIENT_ID = "cyber-thunder-app"
API = "/api/v1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def signing_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    return private, public


@pytest.fixture
def mesh(ctx, monkeypatch, signing_key):
    _, public = signing_key
    ctx.settings.auth_mode = "mesh"
    ctx.settings.oidc_issuer = ISSUER
    ctx.settings.oidc_jwks_url = JWKS_URL
    ctx.settings.oidc_client_id = CLIENT_ID
    ctx.settings.oidc_jwks_max_age_s = 3600
    clear_jwks_cache()
    monkeypatch.setattr("cyberthunder.api.auth.fetch_jwks", lambda url: {"keys": [public]})
    yield
    clear_jwks_cache()


def _token(private, *, username="hacker", issuer=ISSUER, azp=CLIENT_ID, exp=None, alg="RS256", headers=None):
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": "user-1",
        "aud": "account",
        "azp": azp,
        "preferred_username": username,
        "iat": now,
        "nbf": now,
        "exp": now + 300 if exp is None else exp,
    }
    return jwt.encode(claims, private, algorithm=alg, headers=headers or {"kid": "test-key"})


def _scope(client, headers):
    body = {"scopes": [{"cidr": "10.21.0.0/24"}], "reason": "keycloak session"}
    return client.put(f"{API}/discovery/scopes", json=body, headers=headers)


def test_dev_mode_whoami_keeps_the_typed_name(client):
    body = client.get(f"{API}/whoami").json()
    assert body["mode"] == "dev"
    assert body["authenticated"] is False


def test_typed_name_is_refused_when_keycloak_is_required(client, mesh):
    response = _scope(client, {"X-Actor": "IT1 Smith"})
    assert response.status_code == 401
    assert "keycloak" in response.json()["detail"].lower()


def test_valid_token_records_the_keycloak_username(client, ctx, mesh, signing_key):
    private, _ = signing_key
    token = _token(private, username="hacker")
    response = _scope(client, {"Authorization": f"Bearer {token}", "X-Actor": "IT1 Smith"})
    assert response.status_code == 200, response.text
    who = client.get(f"{API}/whoami", headers={"Authorization": f"Bearer {token}"}).json()
    assert who["authenticated"] is True
    assert who["actor"] == "hacker"
    assert who["subject"] == "user-1"
    record = client.get(f"{API}/audit", params={"action": "discovery.scopes"}).json()["records"][-1]
    assert record["actor"] == "hacker"
    assert ctx.audit.verify().ok


@pytest.mark.parametrize("mutate", ["expired", "issuer", "client", "none", "hmac"])
def test_bad_tokens_are_rejected(client, mesh, signing_key, mutate):
    private, public = signing_key
    headers = {"kid": "test-key"}
    kwargs = {}
    if mutate == "expired":
        kwargs["exp"] = int(time.time()) - 120
    elif mutate == "issuer":
        kwargs["issuer"] = "https://evil.example/realms/uds"
    elif mutate == "client":
        kwargs["azp"] = "some-other-app"
    if mutate == "none":
        header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = _b64(json.dumps({"iss": ISSUER, "sub": "user-1", "exp": int(time.time()) + 300}).encode())
        token = f"{header}.{payload}."
    elif mutate == "hmac":
        token = jwt.encode({"iss": ISSUER, "sub": "user-1", "exp": int(time.time()) + 300, "azp": CLIENT_ID},
                           "secret", algorithm="HS256", headers=headers)
    else:
        token = _token(private, headers=headers, **kwargs)
    response = _scope(client, {"Authorization": f"Bearer {token}"})
    assert response.status_code == 401, (mutate, response.text)
    assert public["kid"] == "test-key"
