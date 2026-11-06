"""Device PKCE contract, lifetime and credential-reflection regressions."""
import base64
import hashlib
import json
import re
import subprocess

import pytest

from cyberthunder.client import auth as module
from cyberthunder.client.errors import ClientError
from cyberthunder.client.http import Response, Transport
from tests.client.test_auth import client
from tests.client.test_security_review import challenge


# Public RFC 7636 Appendix B vector, never a real credential.
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_s256_vector_stays_bound_through_pending_slowdown_and_timeout(client, monkeypatch):
    auth, provider, clock = client
    entropy = []
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda size: entropy.append(size) or VERIFIER)
    provider.tokens = [Response(400, {"error": "authorization_pending"}),
                       Response(400, {"error": "slow_down"}), ClientError("request_timeout", outcome=4)]
    displayed = []
    result = auth.login(lambda *args: displayed.append(args))
    assert entropy == [32] and clock.sleeps == [1, 1, 6, 12]
    device = provider.requests[0][1]["payload"]
    assert device == {"client_id": auth.profile["client_id"], "scope": auth.profile["scope"],
                      "code_challenge": CHALLENGE, "code_challenge_method": "S256"}
    polls = [kw["payload"] for kind, kw in provider.requests if kind == "token_endpoint"]
    assert len(polls) == 4
    assert all(p["code_verifier"] == VERIFIER and p["device_code"] == "device-secret" for p in polls)
    assert all("code_challenge" not in p and "code_challenge_method" not in p for p in polls)
    assert VERIFIER not in str(displayed) + json.dumps(result) + auth.store.data.read_text()
    assert VERIFIER not in str(vars(auth))


@pytest.mark.parametrize("end", ["failure", "logout", "cancel", "interrupt"])
def test_each_attempt_has_fresh_bounded_random_verifier(client, end):
    auth, provider, _ = client
    if end == "failure":
        provider.tokens = [Response(400, {"error": "access_denied"})]
    def display(*_):
        if end == "cancel": auth.logout()
        if end == "interrupt": raise KeyboardInterrupt()
    if end == "logout":
        auth.login(display)
        auth.logout()
    else:
        with pytest.raises(KeyboardInterrupt if end == "interrupt" else ClientError):
            auth.login(display)
    prior = list(provider.requests)
    auth.login(lambda *_: None)
    devices = [kw["payload"] for kind, kw in provider.requests if kind == "device_authorization_endpoint"]
    assert len(devices) == 2 and devices[0]["code_challenge"] != devices[1]["code_challenge"]
    assert all(p["code_challenge_method"] == "S256" for p in devices)
    if end in {"cancel", "interrupt"}:
        assert not any(kind == "token_endpoint" for kind, _ in prior)
    polls = [kw["payload"] for kind, kw in provider.requests if kind == "token_endpoint"]
    for poll in polls:
        verifier = poll["code_verifier"]
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", verifier)
        assert len(base64.urlsafe_b64decode(verifier + "=")) == 32
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        assert expected in [p["code_challenge"] for p in devices]
        assert verifier not in auth.store.data.read_text()
    assert len({p["code_verifier"] for p in polls}) == len(polls)


@pytest.mark.parametrize("stage", ["device", "token"])
def test_pkce_rejection_never_downgrades_or_reflects_provider_error(client, monkeypatch, stage):
    auth, provider, _ = client
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _: VERIFIER)
    original = provider.request
    def reject(kind, **kwargs):
        response = original(kind, **kwargs)
        if kind == ("device_authorization_endpoint" if stage == "device" else "token_endpoint"):
            return Response(400, {"error": "invalid_request", "error_description": VERIFIER,
                                  "code_challenge_methods_supported": ["plain"]})
        return response
    monkeypatch.setattr(provider, "request", reject)
    with pytest.raises(ClientError) as caught:
        auth.login(lambda *_: None)
    assert VERIFIER not in json.dumps(caught.value.public()) + auth.store.data.read_text()
    assert sum(kind == "device_authorization_endpoint" for kind, _ in provider.requests) == 1
    assert sum(kind == "token_endpoint" for kind, _ in provider.requests) == (stage == "token")
    assert not any(kind == "api" for kind, _ in provider.requests)
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


@pytest.mark.parametrize("stage", ["device", "access_token", "refresh_token", "identity", "challenge"])
def test_reflected_verifier_never_reaches_cache_or_public_error(client, monkeypatch, stage):
    auth, provider, _ = client
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _: VERIFIER)
    original = provider.request
    def reflect(kind, **kwargs):
        response = original(kind, **kwargs)
        if stage == "device" and kind == "device_authorization_endpoint":
            response.body["device_code"] = VERIFIER
        if stage in {"access_token", "refresh_token"} and kind == "token_endpoint":
            response.body[stage] = "prefix-" + VERIFIER
        if kind == "api":
            if stage == "identity": response.body["principal"]["name"] = "prefix-" + VERIFIER
            if stage == "challenge": return challenge(VERIFIER)
        return response
    monkeypatch.setattr(provider, "request", reflect)
    with pytest.raises(ClientError) as caught:
        auth.login(lambda *_: None)
    assert VERIFIER not in json.dumps(caught.value.public()) + auth.store.data.read_text()
    if stage == "challenge":
        assert caught.value.code == "insufficient_user_authentication" and caught.value.status == 401
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


def test_verifier_uses_private_worker_pipe_not_argv_environment_or_stderr(profile, monkeypatch):
    captured = {}
    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b'{"status":200,"body":"e30="}')
    monkeypatch.setattr("cyberthunder.client.http.subprocess.run", run)
    Transport(profile).request("token_endpoint", payload={"client_id": profile["client_id"],
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": "fixture", "code_verifier": VERIFIER})
    assert VERIFIER.encode() in captured["input"]
    assert VERIFIER not in str(captured["argv"]) + str(captured["env"])
    assert captured["stderr"] == subprocess.DEVNULL


def test_verifier_is_not_reused_for_refresh_or_revocation(client):
    auth, provider, clock = client
    auth.login(lambda *_: None)
    provider.requests.clear()
    clock.elapsed += 280
    provider.refresh = "rotated-refresh"
    with auth.access(): pass
    auth.logout()
    payloads = [kw["payload"] for _, kw in provider.requests if "payload" in kw]
    assert len(payloads) == 3
    assert all(not {"code_verifier", "code_challenge", "code_challenge_method"}.intersection(p) for p in payloads)
