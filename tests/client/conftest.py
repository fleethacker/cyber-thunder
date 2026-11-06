import json
from pathlib import Path

import pytest

from cyberthunder.client.config import ClientProfile
from cyberthunder.client.store import TokenStore
from tests.security.test_oidc import certificates, signing_keys


@pytest.fixture
def profile_factory(tmp_path):
    def make(origin="https://identity.example.test", **changes):
        data = {"version": 1, "api_base_url": origin + "/api/v1", "issuer": origin + "/issuer",
                "audience": "ct-api", "client_id": "ct-human", "device_authorization_endpoint": origin + "/device",
                "token_endpoint": origin + "/token", "revocation_endpoint": origin + "/revoke",
                "verification_uri": origin + "/verify", "scope": "openid profile", "ca_file": None}
        data.update(changes)
        path = tmp_path / "profile.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o600)
        return ClientProfile.load(path)
    return make


@pytest.fixture
def profile(profile_factory):
    return profile_factory()


@pytest.fixture
def store(tmp_path, profile):
    return TokenStore(profile.digest, root=tmp_path / "client-private")
