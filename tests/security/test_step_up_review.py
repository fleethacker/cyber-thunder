"""Adversarial assurance lifetime and transaction checks with signed fixture tokens."""
from dataclasses import replace
import time

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.security.oidc import AuthenticationError, OIDCValidator
from cyberthunder.security.sessions import LOGIN_COOKIE, SESSION_COOKIE, SessionService
from cyberthunder.security.step_up import StepUpRequired
from tests.security.test_identity_boundary import verified_app, identity, headers
from tests.security.test_sessions import crypto, provider, configured, authenticated, ORIGIN
from tests.security.test_browser_api_identity import browser_api, sign_in

ACR = "urn:ct:test:strong"


@pytest.mark.parametrize("boundary", ["core", "api"])
def test_clock_rollback_cannot_restore_stale_assurance(verified_app, monkeypatch, boundary):
    ctx, proposals, tokens, client, _ = verified_app
    wall, mono = time.time(), time.monotonic()
    person = replace(identity(), auth_time=int(wall) - 301, expires_at=wall + 900)
    header = headers(tokens, person)

    def refused():
        if boundary == "core":
            with principal_scope(person), pytest.raises(StepUpRequired) as caught:
                ctx.authorize("approve", actor=person.actor, target="alpha")
            assert caught.value.reason == "authentication_too_old"
        else:
            result = client.post(f"/api/v1/proposals/{proposals['alpha'].id}/approve", headers=header, json={})
            assert result.status_code == 401, result.text
            assert result.json()["step_up"]["reason"] == "authentication_too_old"

    refused()
    monkeypatch.setattr(time, "time", lambda: wall - 10)
    monkeypatch.setattr(time, "monotonic", lambda: mono + 1)
    refused()
    assert ctx.gate.get(proposals["alpha"].id).state.value == "proposed"


def test_future_signed_browser_event_is_rejected_before_it_can_mature(configured, provider):
    config, access = configured
    provider.access_changes.update(ct_kind="human", ct_roles=["approver"])
    provider.id_changes.update(auth_time=int(time.time()) + 30, acr=ACR)
    service = SessionService(replace(config, step_up_acr_values=(ACR,)), OIDCValidator(access))
    with pytest.raises(AuthenticationError):
        authenticated(service, provider)
    assert service._sessions == {}


def test_signed_browser_assurance_stays_stale_after_wall_clock_rollback(browser_api, provider, monkeypatch):
    ctx, item, client, _ = browser_api
    provider.id_changes["auth_time"] = int(time.time()) - 301
    headers, _ = sign_in(client, provider)
    wall, mono = time.time(), time.monotonic()
    path = f"/api/v1/proposals/{item.id}/approve"
    assert client.post(path, headers=headers, json={}).status_code == 401
    monkeypatch.setattr(time, "time", lambda: wall - 10)
    monkeypatch.setattr(time, "monotonic", lambda: mono + 1)
    result = client.post(path, headers=headers, json={})
    assert result.status_code == 401
    assert result.json()["step_up"]["reason"] == "authentication_too_old"
    assert ctx.gate.get(item.id).state.value == "proposed"


@pytest.mark.parametrize("part,change", [
    ("id", {"iss": "https://other.example.test"}),
    ("id", {"sub": "different-person"}),
    ("id", {"aud": "different-client"}),
    ("id", {"azp": "different-client"}),
    ("access", {"azp": "different-client"}),
    ("id", {"nonce": "different-transaction"}),
    ("id", {"at_hash": "unbound-access-token"}),
])
def test_reauthentication_checks_signed_token_pair_and_consumes_bad_transaction(configured, provider, part, change):
    config, access = configured
    provider.access_changes.update(ct_kind="human", ct_roles=["approver"])
    provider.id_changes.update(auth_time=int(time.time()), acr=ACR)
    service = SessionService(replace(config, step_up_acr_values=(ACR,)), OIDCValidator(access))
    original = authenticated(service, provider)
    _, status = service.session_info(original)
    url, cookie = service.start_login({**original, "Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]}, step_up=True)
    provider.id_changes["auth_time"] = int(time.time())
    getattr(provider, part + "_changes").update(change)
    pending_headers = {"Cookie": original["Cookie"] + f"; {LOGIN_COOKIE}={cookie}"}
    query = provider.authorize(url)
    before = len(provider.posts)
    with pytest.raises(AuthenticationError):
        service.finish_login(query, pending_headers)
    assert len(provider.posts) == before + 1
    with pytest.raises(AuthenticationError):
        service.finish_login(query, pending_headers)
    assert len(provider.posts) == before + 1, "A failed callback cannot replay the token exchange"
    assert service.resolve_session(original)["sub"] == "operator-123"


def test_missing_accepted_acr_cannot_start_step_up(configured, provider):
    config, access = configured
    provider.access_changes.update(ct_kind="human", ct_roles=["approver"])
    provider.id_changes.update(auth_time=int(time.time()), acr=ACR)
    service = SessionService(config, OIDCValidator(access))
    original = authenticated(service, provider)
    _, status = service.session_info(original)
    with pytest.raises(AuthenticationError):
        service.start_login({**original, "Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]}, step_up=True)
    assert len(provider.posts) == 1


def test_revoked_step_up_transaction_cannot_exchange_a_code(configured, provider):
    config, access = configured
    provider.access_changes.update(ct_kind="human", ct_roles=["approver"])
    provider.id_changes.update(auth_time=int(time.time()), acr=ACR)
    service = SessionService(replace(config, step_up_acr_values=(ACR,)), OIDCValidator(access))
    original = authenticated(service, provider)
    _, status = service.session_info(original)
    headers = {**original, "Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]}
    url, login_cookie = service.start_login(headers, step_up=True)
    query = provider.authorize(url)
    # Another tab logs out without the pending transaction's cookie.
    service.logout(headers)
    pending_headers = {"Cookie": original["Cookie"] + f"; {LOGIN_COOKIE}={login_cookie}"}
    before = len(provider.posts)
    with pytest.raises(AuthenticationError):
        service.finish_login(query, pending_headers)
    assert len(provider.posts) == before, "Revoked transactions must fail before token endpoint I/O"


def test_reauthentication_rotates_csrf_cookie_and_copied_session_guard(browser_api, provider):
    _, item, client, app = browser_api
    headers, _ = sign_in(client, provider)
    old_cookie = client.cookies.get(SESSION_COOKIE)
    old_headers = {"Cookie": f"{SESSION_COOKIE}={old_cookie}"}
    _, lease = app.state.sessions.resolve_session_with_lease(old_headers)
    started = client.post("/auth/reauthenticate", headers=headers, json={})
    assert started.status_code == 200
    provider.id_changes["auth_time"] = int(time.time())
    callback = client.get("/auth/callback?" + provider.authorize(started.json()["authorization_url"]), follow_redirects=False)
    assert callback.status_code == 303
    assert client.cookies.get(SESSION_COOKIE) != old_cookie
    with pytest.raises(PermissionError):
        lease()
    with pytest.raises(AuthenticationError):
        app.state.sessions.resolve_session(old_headers)
    path = f"/api/v1/proposals/{item.id}/approve"
    assert client.post(path, headers=headers, json={}).status_code == 401
    new_csrf = client.get("/auth/status").json()["csrf_token"]
    assert new_csrf != headers["X-CSRF-Token"]
    assert client.post(path, headers={**headers, "X-CSRF-Token": new_csrf}, json={}).status_code == 200
