"""Signed browser and bearer assurance with an isolated loopback identity provider."""
from dataclasses import replace
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from cyberthunder.control.principal import Principal
from cyberthunder.security.oidc import OIDCValidator
from cyberthunder.security.sessions import SessionService
from cyberthunder.security.step_up import StepUpPolicy, StepUpRequired
from tests.security.test_sessions import crypto, provider, configured, authenticated, ORIGIN, ISSUER, CLIENT, API_AUDIENCE
from tests.security.test_browser_api_identity import browser_api, sign_in

ACR = "urn:ct:test:strong"


def test_old_signed_browser_assurance_challenges_and_deliberate_reauthentication_allows(browser_api, provider):
    ctx, item, client, _ = browser_api
    provider.id_changes["auth_time"] = int(time.time()) - 600
    # A newly minted access token must not replace old ID-token authentication evidence.
    provider.access_changes.update(auth_time=int(time.time()), acr=ACR)
    headers, _ = sign_in(client, provider)
    path = f"/api/v1/proposals/{item.id}/approve"
    denied = client.post(path, json={}, headers=headers)
    assert denied.status_code == 401
    assert denied.json()["step_up"]["reason"] == "authentication_too_old"
    assert ctx.gate.get(item.id).state.value == "proposed"
    started = client.post("/auth/reauthenticate", json={"return_to": "/decisions?proposal=" + item.id + "#impact"}, headers=headers)
    assert started.status_code == 200
    query = parse_qs(urlsplit(started.json()["authorization_url"]).query)
    assert query["max_age"] == ["300"] and query["prompt"] == ["login"] and query["acr_values"] == [ACR]
    assert query["code_challenge_method"] == ["S256"] and query["nonce"]
    provider.id_changes["auth_time"] = int(time.time())
    callback = client.get("/auth/callback?" + provider.authorize(started.json()["authorization_url"]), follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == ORIGIN + "/decisions?proposal=" + item.id + "#impact"
    assert ctx.gate.get(item.id).state.value == "proposed", "Login does not replay a decision"
    status = client.get("/auth/status").json()
    response = client.post(path, json={}, headers={**headers, "X-CSRF-Token": status["csrf_token"]})
    assert response.status_code == 200, response.text
    saved = ctx.gate.get(item.id)
    assert saved.decided_principal["auth_time"] == provider.id_changes["auth_time"]
    assert saved.decided_principal["acr"] == ACR
    assert saved.decided_principal["amr"] == ["fixture"]


@pytest.mark.parametrize("id_changes,reason", [
    ({"auth_time": "missing"}, "invalid_authentication_time"),
    ({"auth_time": "future"}, "future_authentication_time"),
    ({"acr": "urn:ct:test:stronger", "amr": ["cac"]}, "assurance_not_accepted"),
])
def test_signed_insufficient_browser_claims_are_never_upgraded(browser_api, provider, id_changes, reason):
    _, item, client, _ = browser_api
    provider.id_changes.update(id_changes)
    if provider.id_changes.get("auth_time") == "missing":
        provider.id_changes.pop("auth_time")
    elif provider.id_changes.get("auth_time") == "future":
        provider.id_changes["auth_time"] = int(time.time()) + 30
    headers, _ = sign_in(client, provider)
    result = client.post(f"/api/v1/proposals/{item.id}/approve", json={}, headers=headers)
    assert result.status_code == 401 and result.json()["step_up"]["reason"] == reason


@pytest.mark.parametrize("invalid", [None, True, 1.5, "1000", 253402300799])
def test_malformed_signed_authentication_time_fails_token_validation(browser_api, provider, invalid):
    ctx, item, client, _ = browser_api
    provider.id_changes["auth_time"] = invalid
    login = client.get("/auth/login", follow_redirects=False)
    result = client.get("/auth/callback?" + provider.authorize(login.headers["location"]), follow_redirects=False)
    assert result.status_code == 401
    assert result.json() == {"detail": "Authentication failed"}
    assert client.get("/auth/status").json()["authenticated"] is False
    assert ctx.gate.get(item.id).state.value == "proposed"


def test_refresh_preserves_original_id_assurance_even_if_new_tokens_claim_more(configured, provider):
    config, access = configured
    provider.access_changes.update(ct_kind="human", ct_roles=["approver"])
    old = int(time.time()) - 600
    provider.id_changes.update(auth_time=old, acr="password")
    service = SessionService(replace(config, step_up_acr_values=(ACR,)), OIDCValidator(access))
    headers = authenticated(service, provider)
    _, current = service._live(headers)
    current.access_deadline = 0  # Exercise rotation without extending any credential lifetime.
    provider.refresh_id = True
    provider.id_changes.update(auth_time=int(time.time()), acr=ACR)
    provider.access_changes.update(auth_time=int(time.time()), acr=ACR)
    claims = service.resolve_session(headers)
    assert claims["auth_time"] == old and claims["acr"] == "password"
    assert provider.posts[-1][1]["grant_type"] == "refresh_token"
    with pytest.raises(StepUpRequired):
        StepUpPolicy(acr_values=(ACR,)).require(Principal.from_claims(claims, via="oidc"))
    claims["auth_time"] = int(time.time())
    assert service.resolve_session(headers)["auth_time"] == old


@pytest.mark.parametrize("change", ["old-time", "weak-acr", "different-subject", "workload", "logout"])
def test_reauthentication_callback_requires_new_same_account_human_evidence(browser_api, provider, change):
    _, _, client, _ = browser_api
    headers, _ = sign_in(client, provider)
    started = client.post("/auth/reauthenticate", json={}, headers=headers)
    assert started.status_code == 200
    if change == "old-time":
        provider.id_changes["auth_time"] = int(time.time()) - 10
    elif change == "weak-acr":
        provider.id_changes["acr"] = "password"
    elif change == "different-subject":
        provider.id_changes["sub"] = provider.access_changes["sub"] = "other-account"
    elif change == "workload":
        provider.access_changes["ct_kind"] = "workload"
    else:
        assert client.post("/auth/logout", headers=headers).status_code == 204
    result = client.get("/auth/callback?" + provider.authorize(started.json()["authorization_url"]), follow_redirects=False)
    assert result.status_code == 401
    assert result.json() == {"detail": "Authentication failed"}


def test_reauth_rejects_csrf_and_caller_threshold_endpoint_or_return_url_overrides(browser_api, provider):
    _, _, client, _ = browser_api
    headers, _ = sign_in(client, provider)
    assert client.post("/auth/reauthenticate", json={}).status_code == 401
    assert client.post("/auth/reauthenticate", json={}, headers={**headers, "Origin": "https://other.test"}).status_code == 401
    for body in [{"max_age": 999999}, {"acr_values": ["password"]}, {"prompt": "none"},
                 {"authorization_endpoint": "https://other.test"}, {"return_to": "https://other.test"},
                 {"return_to": "//other.test"}, {"return_to": "/\\other.test"}, {"return_to": "/\r\nInjected: yes"}]:
        assert client.post("/auth/reauthenticate", json=body, headers=headers).status_code in {400, 401, 422}
    assert client.post("/auth/reauthenticate?max_age=0", json={}, headers=headers).status_code == 401
    for raw in [b'{"return_to":"/","return_to":"/other"}', b'{"return_to":"' + b'x' * 8192 + b'"}', b'not-json']:
        result = client.post("/auth/reauthenticate", content=raw, headers=headers)
        assert result.status_code == 401 and result.json() == {"detail": "Authentication failed"}
    assert len(provider.posts) == 1, "Only the original login reached the token endpoint"


def test_bearer_needs_its_own_signed_assurance_and_cannot_borrow_browser_state(browser_api, provider):
    ctx, item, client, _ = browser_api
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "operator-123", "aud": API_AUDIENCE, "azp": CLIENT,
              "iat": now - 1, "exp": now + 300, "ct_kind": "human", "ct_roles": ["approver"]}
    path = f"/api/v1/proposals/{item.id}/approve"
    for assurance in [{}, {"auth_time": now - 600, "acr": ACR}, {"auth_time": now, "acr": "password"}]:
        result = client.post(path, json={}, headers={"Authorization": "Bearer " + provider.signed({**claims, **assurance})})
        assert result.status_code == 401
        assert result.json()["error"] == "insufficient_user_authentication"
    workload = {**claims, "ct_kind": "workload", "auth_time": now, "acr": ACR}
    assert client.post(path, json={}, headers={"Authorization": "Bearer " + provider.signed(workload)}).status_code == 403
    result = client.post(path, json={}, headers={"Authorization": "Bearer " + provider.signed({**claims, "auth_time": now, "acr": ACR})})
    assert result.status_code == 200, result.text
    assert ctx.gate.get(item.id).decided_principal["auth_time"] == now
