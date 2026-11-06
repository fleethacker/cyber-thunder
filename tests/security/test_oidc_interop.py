"""Mixed provider JWKS select verification keys without hiding invalid entries."""
import json

import pytest

from cyberthunder.security.oidc import OIDCValidator
from tests.security.test_oidc import (
    certificates, environment, https_server, jwk, rejected, signing_keys, token,
)


def encryption_key(keys):
    value = jwk(keys["rogue"], "encryption", alg="RSA-OAEP")
    value.update(use="enc")
    value.pop("key_ops")
    return value


@pytest.mark.parametrize("operations", [None, ["encrypt"], ["wrapKey"], ["encrypt", "wrapKey"]])
@pytest.mark.parametrize("order", ["encryption-first", "signing-first"])
def test_mixed_public_keys_only_cache_and_use_signing_key(environment, signing_keys, operations, order):
    config, server = environment
    excluded = encryption_key(signing_keys)
    if operations is not None:
        excluded["key_ops"] = operations
    keys = [excluded, jwk(signing_keys["rsa"])]
    server["body"] = json.dumps({"keys": keys if order == "encryption-first" else keys[::-1]}).encode()
    validator = OIDCValidator(config)
    assert validator.validate(token(signing_keys))["sub"] == "operator-123"
    assert [k["kid"] for k in json.loads(config.cache_path.read_text())["jwks"]["keys"]] == ["rsa"]
    assert OIDCValidator(config).validate(token(signing_keys))["sub"] == "operator-123"
    # A perfectly valid RS256 signature from the excluded public key is still forbidden.
    rejected(validator, token(signing_keys, kid="encryption", key_name="rogue"))
    rejected(validator, token(signing_keys, kid="rsa", key_name="rogue"))


@pytest.mark.parametrize("change", [
    {"kid": "rsa"}, {"kid": ""}, {"d": "private-value"}, {"k": "secret"},
    {"x5u": "https://other.example.test/key"}, {"n": "AA"}, {"n": "!"}, {"e": "Aw"},
    {"kty": "oct"}, {"alg": "RS256"}, {"alg": None}, {"alg": []},
    {"key_ops": ["verify"]}, {"key_ops": ["decrypt"]}, {"key_ops": ["encrypt", "verify"]},
    {"key_ops": ["encrypt", "encrypt"]}, {"key_ops": "encrypt"}, {"key_ops": []},
    {"key_ops": [[]]}, {"use": "unknown"},
])
@pytest.mark.parametrize("order", ["encryption-first", "signing-first"])
def test_ineligible_key_does_not_hide_malformed_private_or_duplicate_entries(environment, signing_keys, change, order):
    config, server = environment
    keys = [{**encryption_key(signing_keys), **change}, jwk(signing_keys["rsa"])]
    server["body"] = json.dumps({"keys": keys if order == "encryption-first" else keys[::-1]}).encode()
    rejected(OIDCValidator(config), token(signing_keys))
    assert not config.cache_path.exists()


@pytest.mark.parametrize("case", ["only-encryption", "duplicate-encryption", "duplicate-json"])
def test_encryption_only_or_duplicate_set_is_not_a_verification_set(environment, signing_keys, case):
    config, server = environment
    key = encryption_key(signing_keys)
    keys = [key] if case == "only-encryption" else [key, key, jwk(signing_keys["rsa"])]
    body = json.dumps({"keys": keys})
    if case == "duplicate-json":
        body = body.replace('"use": "enc"', '"use": "enc", "use": "sig"')
    server["body"] = body.encode()
    rejected(OIDCValidator(config), token(signing_keys))
    assert not config.cache_path.exists()
