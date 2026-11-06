"""Provider sessions can disappear when their refresh credential is revoked."""
import pytest

from cyberthunder.client.errors import ClientError
from cyberthunder.client.http import Response
from tests.client.test_auth import client


@pytest.mark.parametrize("access_failure", [None, "invalid_token", "http_error", "timeout"])
def test_logout_revokes_access_before_session_and_requires_both_acknowledgements(client, monkeypatch, access_failure):
    auth, provider, _ = client
    auth.login(lambda *_: None)
    with auth.store.locked(): generation = auth.store.load()["generation"]
    original = provider.request
    session_alive = True
    revoked = []

    def revoke(kind, **kwargs):
        nonlocal session_alive
        if kind != "revocation_endpoint":
            return original(kind, **kwargs)
        with auth.store.locked():
            cleared = auth.store.load()
            assert cleared["phase"] == "empty" and cleared["session"] is None
            assert cleared["generation"] != generation
        hint = kwargs["payload"]["token_type_hint"]
        revoked.append(hint)
        # Keycloak validates the session for either token type. Refresh
        # revocation removes that session; later access revocation cannot ack.
        if not session_alive:
            return Response(200, {"error": "invalid_token"})
        if hint == "refresh_token":
            session_alive = False
        elif access_failure == "timeout":
            raise ClientError("request_timeout", outcome=4)
        elif access_failure is not None:
            return Response(400 if access_failure == "http_error" else 200, {"error": "invalid_token"})
        return Response(200, {})

    monkeypatch.setattr(provider, "request", revoke)
    result, outcome = auth.logout()
    assert revoked == ["access_token", "refresh_token"] and not session_alive
    assert result["local_cleared"] is True
    assert result["provider_revocation"] == ("unconfirmed" if access_failure else "acknowledged")
    assert outcome == (4 if access_failure else 0)
