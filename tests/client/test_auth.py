from types import SimpleNamespace
import time

import pytest

from cyberthunder.client import auth as module
from cyberthunder.client.auth import ClientAuth
from cyberthunder.client.errors import ClientError
from cyberthunder.client.http import Response
from cyberthunder.control.principal import Principal


class Clock:
    def __init__(self):
        self.base, self.elapsed, self.sleeps = time.time(), 0, []
    def time(self): return self.base + self.elapsed
    def monotonic(self): return self.elapsed
    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.elapsed += seconds


class Provider:
    def __init__(self, profile, clock):
        self.profile, self.clock = profile, clock
        self.tokens = []
        self.requests = []
        self.claim_changes = {}
        self.refresh = "refresh-one"
        self.device_changes = {}
        self.failure = None
    def request(self, kind, **kwargs):
        self.requests.append((kind, kwargs))
        if self.failure and kind == self.failure:
            raise ClientError("request_timeout", outcome=4)
        if kind == "device_authorization_endpoint":
            return Response(200, {"device_code": "device-secret", "user_code": "TEST-CODE", "expires_in": 90,
                "interval": 1, "verification_uri": self.profile["verification_uri"], **self.device_changes})
        if kind == "token_endpoint":
            if self.tokens:
                item = self.tokens.pop(0)
                if isinstance(item, Exception): raise item
                return item
            return Response(200, {"access_token": "access-private", "refresh_token": self.refresh,
                                  "expires_in": 300, "token_type": "Bearer"})
        if kind == "api":
            p = Principal(self.profile["issuer"], "alice", "Alice", kind="human", roles=("analyst",),
                          expires_at=self.clock.time()+300, auth_time=int(self.clock.base), acr="urn:test:strong")
            return Response(200, {"mode": "oidc", "verified": True,
                "principal": {**p.evidence(), "actor": p.actor, **self.claim_changes}})
        return Response(200, {})


@pytest.fixture
def client(profile, store, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(module, "time", clock)
    monkeypatch.setattr("cyberthunder.client.store.time", clock)
    http = Provider(profile, clock)
    return ClientAuth(profile, store=store, transport=http), http, clock


def test_device_pending_slowdown_timeout_then_verified_login(client):
    auth, provider, clock = client
    provider.tokens = [Response(400, {"error": "authorization_pending"}), Response(400, {"error": "slow_down"}),
                       ClientError("request_timeout", outcome=4)]
    displayed = []
    result = auth.login(lambda uri, code: displayed.append((uri, code)))
    assert result["status"] == "authenticated" and clock.sleeps == [1, 1, 6, 12]
    assert displayed == [(auth.profile["verification_uri"], "TEST-CODE")]
    assert "private" not in str(result) and "device-secret" not in auth.store.data.read_text()
    assert auth.status()[1] == 0


@pytest.mark.parametrize("error", ["access_denied", "expired_token", "SECRET-PROVIDER-ERROR"])
def test_terminal_device_failure_never_publishes_tokens(client, error):
    auth, provider, _ = client
    provider.tokens = [Response(400, {"error": error, "error_description": "SECRET-DESCRIPTION"})]
    with pytest.raises(ClientError) as caught:
        auth.login(lambda *_: None)
    assert "SECRET" not in str(caught.value)
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


@pytest.mark.parametrize("changes", [{"verification_uri": "https://evil.test/verify"}, {"interval": True},
    {"expires_in": -1}, {"user_code": "\x1bSECRET"}, {"device_code": "secret\n"}])
def test_malformed_device_response_is_rejected(client, changes):
    auth, provider, _ = client
    provider.device_changes = changes
    with pytest.raises(ClientError): auth.login(lambda *_: None)


def test_device_deadline_is_pending_not_success(client):
    auth, provider, clock = client
    provider.device_changes.update(expires_in=2, interval=5)
    with pytest.raises(ClientError) as error: auth.login(lambda *_: None)
    assert error.value.outcome == 4 and clock.sleeps == [2]
    assert not any(kind == "token_endpoint" for kind, _ in provider.requests)


@pytest.mark.parametrize("claims", [{"kind": "workload"}, {"verified": False}, {"iss": "https://evil.test"},
                                    {"actor": "typed-administrator"}])
def test_only_api_verified_human_identity_is_accepted(client, claims):
    auth, provider, _ = client
    provider.claim_changes.update(claims)
    with pytest.raises(ClientError): auth.login(lambda *_: None)
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


def test_logout_cancels_pending_login_publication(client):
    auth, _, _ = client
    with pytest.raises(ClientError, match="login_cancelled"):
        auth.login(lambda *_: auth.logout())
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


def test_refresh_rotates_and_logout_reports_provider_failure(client):
    auth, provider, clock = client
    auth.login(lambda *_: None)
    clock.elapsed += 280
    provider.refresh = "refresh-two"
    with auth.access() as access: assert access == "access-private"
    assert "refresh-one" not in auth.store.data.read_text()
    provider.failure = "revocation_endpoint"
    result, outcome = auth.logout()
    assert outcome == 4 and result["local_cleared"] and result["provider_revocation"] == "unconfirmed"
    assert "private" not in auth.store.data.read_text()


@pytest.mark.parametrize("failure", ["same_refresh", "assurance", "subject", "timeout"])
def test_refresh_cannot_replay_or_upgrade_identity_and_failure_clears_cache(client, failure):
    auth, provider, clock = client
    auth.login(lambda *_: None)
    clock.elapsed += 280
    if failure != "same_refresh": provider.refresh = "refresh-two"
    if failure == "assurance": provider.claim_changes["auth_time"] = int(clock.time())
    if failure == "subject": provider.claim_changes["sub"] = "different"
    if failure == "timeout": provider.failure = "token_endpoint"
    with pytest.raises(ClientError):
        with auth.access(): pass
    with auth.store.locked(): assert auth.store.load()["phase"] == "empty"


def test_status_does_not_refresh_and_clock_rollback_does_not_extend_session(client):
    auth, provider, clock = client
    auth.login(lambda *_: None)
    before = len(provider.requests)
    clock.elapsed += 301
    assert auth.status() == ({"status": "expired", "verified": False}, 3)
    assert len(provider.requests) == before
    clock.base -= 1000
    with pytest.raises(ClientError, match="clock_changed"):
        auth.status()
