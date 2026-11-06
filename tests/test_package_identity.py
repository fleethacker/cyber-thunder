"""Packaged startup must use the same verified-identity boundary as the native CLI."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

import jwt
import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient

from cyberthunder.cli import main
from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.inventory.targets import Target
from cyberthunder.security._oidc_cache import write_cache
from cyberthunder.security.oidc import OIDCValidator
from cyberthunder.security.oidc import AuthenticationError
from tests.security.test_sessions import crypto

ROOT = Path(__file__).resolve().parents[1]


BUILDS = ("Dockerfile", "Containerfile")
TRIVY_IMAGE = "aquasec/trivy:0.71.1@sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7"


def docker_defaults(filename):
    source = (ROOT / filename).read_text(encoding="utf-8")
    block = re.search(r"(?ms)^ENV (.*?)(?=^[A-Z]+ )", source).group(1)
    environment = dict(item.split("=", 1) for item in shlex.split(block.replace("\\\n", " ")))
    command = json.loads(re.search(r"(?m)^ENTRYPOINT (.+)$", source).group(1))
    command += json.loads(re.search(r"(?m)^CMD (.+)$", source).group(1))
    assert command == ["cyberthunder", "serve"]
    return environment, command[1:]


@pytest.mark.parametrize("filename", BUILDS)
def test_builds_pin_supported_scanner_and_guarded_single_worker(filename):
    source = (ROOT / filename).read_text(encoding="utf-8")
    assert re.search(r"(?m)^FROM (\S+) AS trivy$", source).group(1) == TRIVY_IMAGE
    environment, _ = docker_defaults(filename)
    assert environment["CT_HOST"] == "0.0.0.0"
    assert environment["CT_PORT"] == "8000" and environment["WEB_CONCURRENCY"] == "1"


@pytest.fixture(params=BUILDS)
def packaged_env(state_dir, monkeypatch, request):
    for name in os.environ:
        if name.startswith("CT_") and name not in {"CT_STATE_BACKEND", "CT_STATE_BACKENDS"}:
            monkeypatch.delenv(name)
    environment, command = docker_defaults(request.param)
    for name, value in environment.items():
        if name.startswith("CT_") or name == "WEB_CONCURRENCY":
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    return command


def test_container_without_verified_config_exits_before_listening(packaged_env):
    result = subprocess.run([sys.executable, "-m", "cyberthunder", *packaged_env],
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "development authentication may bind only to loopback" in result.stderr
    assert "Uvicorn running" not in result.stderr


@pytest.mark.parametrize("case", ["dev", "oidc_without_tls", "missing_issuer"])
def test_container_refuses_invalid_network_identity(packaged_env, monkeypatch, case):
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("Invalid configuration reached listener"))
    if case == "oidc_without_tls":
        monkeypatch.setenv("CT_AUTH_MODE", "oidc")
        expected, message = ValueError, "network access requires TLS"
    elif case == "missing_issuer":
        monkeypatch.setenv("CT_AUTH_MODE", "mesh")
        expected, message = AuthenticationError, "Authentication failed"
    else:
        expected, message = ValueError, "development authentication may bind only to loopback"
    with pytest.raises(expected, match=message):
        main(packaged_env)


def test_configured_container_uses_validated_host_tls_and_one_worker(packaged_env, monkeypatch, crypto):
    cert, key, _ = crypto
    monkeypatch.setenv("WEB_CONCURRENCY", "8")
    for name, value in {
        "CT_AUTH_MODE": "oidc", "CT_SECURITY_MODE": "fleet", "CT_HOST": "0.0.0.0",
        "CT_TLS_CERT": str(cert), "CT_TLS_KEY": str(key),
        "CT_OIDC_ISSUER": "https://identity.example.test/realms/fixture",
        "CT_OIDC_AUDIENCE": "cyberthunder-api", "CT_OIDC_AUTHORIZED_PARTY": "cyberthunder-browser",
        "CT_OIDC_JWKS_URL": "https://identity.example.test/realms/fixture/protocol/openid-connect/certs",
    }.items():
        monkeypatch.setenv(name, value)
    captured = []

    def start(app, **kwargs):
        config = uvicorn.Config(app, **kwargs)
        config.load()  # Includes real certificate/key loading; no socket is opened.
        captured.append(config)
        assert app.state.ctx.settings.host == kwargs["host"] == "0.0.0.0"
        with TestClient(app) as client:
            assert client.get("/api/v1/targets").status_code == 401

    monkeypatch.setattr(uvicorn, "run", start)
    assert main(packaged_env) == 0
    assert len(captured) == 1
    config = captured[0]
    assert config.workers == 1 and config.port == 8000 and config.ssl is not None
    assert config.proxy_headers is False


def test_explicit_loopback_dev_start_still_uses_native_cli(packaged_env, monkeypatch):
    monkeypatch.setenv("CT_HOST", "127.0.0.1")
    monkeypatch.setenv("WEB_CONCURRENCY", "8")
    captured = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: captured.append((app, kwargs)))
    assert main(packaged_env) == 0
    assert captured[0][0].state.ctx.settings.auth_mode == "dev"
    assert captured[0][1]["host"] == "127.0.0.1"
    assert captured[0][1]["workers"] == 1


MANIFESTS = ("deploy/kubernetes/cyberthunder.yaml", "packages/cyberthunder/app.yaml")


def documents(filename):
    source = (ROOT / filename).read_text(encoding="utf-8")
    for name, value in {"DOMAIN": "fixture.test", "SCAN_TARGET_CIDR": "192.0.2.1/32", "SCAN_SSH_PORT": "22"}.items():
        source = source.replace("###ZARF_VAR_" + name + "###", value)
    assert "###ZARF_VAR_" not in source
    return list(yaml.safe_load_all(source))


def pod(filename):
    deployment = next(d for d in documents(filename) if d["kind"] == "Deployment")
    assert deployment["spec"]["replicas"] == 1 and deployment["spec"]["strategy"]["type"] == "Recreate"
    return deployment["spec"]["template"]["spec"]


def preflight():
    source = documents("deploy/kubernetes/identity-preflight.yaml")[0]["data"]["validate.py"]
    namespace = {"__name__": "package_identity_preflight"}
    exec(compile(source, "identity-preflight/validate.py", "exec"), namespace)
    return namespace["validate"]


@pytest.mark.parametrize("filename", MANIFESTS)
def test_manifests_require_identity_and_protected_storage_without_anonymous_api_probe(filename):
    spec = pod(filename)
    assert "fsGroup" not in spec["securityContext"]
    app, init = spec["containers"][0], spec["initContainers"][0]
    assert init["image"] == app["image"]
    assert init["command"] == ["python", "/etc/package-identity/validate.py"]
    for container in (app, init):
        assert {"configMapRef": {"name": "cyberthunder-identity", "optional": False}} in container["envFrom"]
        env = {entry["name"]: entry.get("value") for entry in container["env"]}
        assert env["CT_HOST"] == "0.0.0.0" and env["CT_SECURITY_MODE"] == "fleet"
    secret = next(e for e in app["env"] if e["name"] == "CT_CRED_BROWSER_LOGIN")
    assert secret["valueFrom"]["secretKeyRef"] == {
        "name": "cyberthunder-oidc-client", "key": "client-secret", "optional": False}
    assert all(m["readOnly"] for m in init["volumeMounts"])
    assert not any(e["name"].startswith("CT_CRED_") for e in init["env"])
    for name in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert app[name]["tcpSocket"]["port"] == "http"
        assert "httpGet" not in app[name]
    state = next(v for v in spec["volumes"] if v["name"] == "state")
    assert state["persistentVolumeClaim"]["claimName"] == "cyberthunder-state"


def test_uds_native_oidc_registration_matches_application_profile():
    package = next(d for d in documents("packages/cyberthunder/uds.yaml") if d["kind"] == "Package")
    config = documents("packages/cyberthunder/identity.yaml")[0]["data"]
    client, = package["spec"]["sso"]
    assert client["clientId"] == config["CT_OIDC_CLIENT_ID"] == config["CT_OIDC_AUTHORIZED_PARTY"]
    assert client["redirectUris"] == [config["CT_OIDC_REDIRECT_URI"]]
    assert client["redirectUris"][0].endswith("/auth/callback")
    assert client["publicClient"] is False and client["serviceAccountsEnabled"] is False
    assert client["fullScopeAllowed"] is False
    assert "enableAuthserviceSelector" not in client
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["secretConfig"] == {"name": "cyberthunder-oidc-client", "template": {"client-secret": "clientField(secret)"}}
    mappers = {m["name"]: m for m in client["protocolMappers"]}
    audience = mappers["application-api-audience"]["config"]
    assert audience["included.custom.audience"] == config["CT_OIDC_AUDIENCE"] != client["clientId"]
    assert audience["access.token.claim"] == "true" and audience["id.token.claim"] == "false"
    roles = mappers["application-roles"]["config"]
    assert roles["claim.name"] == config["CT_OIDC_ROLES_CLAIM"] == "ct_roles"
    assert roles["usermodel.clientRoleMapping.clientId"] == client["clientId"] and roles["multivalued"] == "true"
    assert mappers["account-kind"]["config"]["user.attribute"] == "ct_kind"
    assert not any(m["protocolMapper"] == "oidc-hardcoded-claim-mapper" for m in client["protocolMappers"])
    assert any(rule.get("remoteHost") == "sso.fixture.test" and rule["port"] == 443
               and rule["remoteProtocol"] == "TLS" for rule in package["spec"]["network"]["allow"])
    zarf = documents("packages/cyberthunder/zarf.yaml")[0]
    files = [path for component in zarf["components"] for manifest in component.get("manifests", [])
             for path in manifest["files"]]
    assert {"identity.yaml", "../../deploy/kubernetes/identity-preflight.yaml",
            "../../deploy/kubernetes/cyberthunder.yaml"} <= set(files)
    assert all((ROOT / "packages/cyberthunder" / path).is_file() for path in files)


def test_uds_network_selectors_match_the_actual_application_pod():
    package = next(d for d in documents("packages/cyberthunder/uds.yaml") if d.get("kind") == "Package")
    deployment = next(d for d in documents("packages/cyberthunder/app.yaml") if d.get("kind") == "Deployment")
    labels = deployment["spec"]["template"]["metadata"]["labels"]
    network = package["spec"]["network"]
    for rule in network["allow"] + network["expose"]:
        assert rule["selector"] and all(labels.get(key) == value for key, value in rule["selector"].items())


@pytest.mark.parametrize("filename", ["packages/cyberthunder/identity.yaml", "deploy/kubernetes/identity-config.example.yaml"])
def test_packaged_assurance_requires_real_realm_configuration(filename):
    config = documents(filename)[0]["data"]
    assert config["CT_STEP_UP_MAX_AGE_SECONDS"] == "300"
    assert json.loads(config["CT_STEP_UP_ACR_VALUES"]) == []


@pytest.fixture(params=["native", "native-alternate", "uds"])
def manifest_env(state_dir, monkeypatch, crypto, request):
    for name in os.environ:
        if name.startswith("CT_") and name not in {"CT_STATE_BACKEND", "CT_STATE_BACKENDS"}:
            monkeypatch.delenv(name)
    config = documents("packages/cyberthunder/identity.yaml" if request.param == "uds"
                       else "deploy/kubernetes/identity-config.example.yaml")[0]["data"]
    if request.param != "uds":
        issuer = "https://identity.fixture.test/realms/fixture"
        config.update(CT_OIDC_ISSUER=issuer, CT_OIDC_JWKS_URL=issuer + "/protocol/openid-connect/certs",
                      CT_OIDC_AUTHORIZATION_ENDPOINT=issuer + "/protocol/openid-connect/auth",
                      CT_OIDC_TOKEN_ENDPOINT=issuer + "/protocol/openid-connect/token",
                      CT_OIDC_REDIRECT_URI="https://console.fixture.test/auth/callback",
                      CT_TLS_CERT=str(crypto[0]), CT_TLS_KEY=str(crypto[1]))
    manifest = MANIFESTS[1] if request.param == "native-alternate" else MANIFESTS[0]
    env = {entry["name"]: entry["value"] for entry in pod(manifest)["containers"][0]["env"] if "value" in entry}
    env.update(config)
    env.update(CT_STATE_DIR=str(state_dir), CT_BOOTSTRAP_CLUSTER_TARGET="false", CT_EXPLAIN_PRECOMPUTE="false",
               CT_AUTO_PROPOSE="false", CT_LLM_BACKEND="template", CT_SCAN_INTERVAL_SECONDS="0",
               CT_CONTENT_CHECK_INTERVAL_SECONDS="0", CT_CRED_BROWSER_LOGIN="fixture-only-client-secret")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    auth = state_dir / "auth"
    auth.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    policy = {"version": 1, "entries": [{"issuer": env["CT_OIDC_ISSUER"], "subject": "fixture-reader",
              "node_actions": [], "grants": [{"actions": ["read"], "environments": ["alpha"]}]}]}
    path = auth / "access.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    path.chmod(0o600)
    return env, policy


def test_preflight_validates_operator_policy_without_writes(manifest_env):
    state = Path(manifest_env[0]["CT_STATE_DIR"])
    before = {p: p.read_bytes() for p in state.rglob("*") if p.is_file()}
    preflight()()
    assert {p: p.read_bytes() for p in state.rglob("*") if p.is_file()} == before


def test_preflight_rejects_projected_policy_symlink(manifest_env):
    path = Path(manifest_env[0]["CT_STATE_DIR"]) / "auth/access.json"
    real = path.with_name("projected-access.json")
    path.rename(real)
    try:
        path.symlink_to(real)
    except OSError as error:
        pytest.skip("Host cannot create the projected-policy symlink fixture: " + str(error))
    with pytest.raises(ValueError, match="protected regular"):
        preflight()()


@pytest.mark.parametrize("problem", ["missing_issuer", "missing_client", "missing_policy", "invalid_policy",
                                     "wrong_issuer", "empty_accounts", "same_audience", "dev"])
def test_preflight_refuses_incomplete_or_untrusted_identity(manifest_env, monkeypatch, problem):
    env, policy = manifest_env
    path = Path(env["CT_STATE_DIR"]) / "auth/access.json"
    if problem == "missing_issuer":
        monkeypatch.delenv("CT_OIDC_ISSUER")
    elif problem == "missing_client":
        monkeypatch.delenv("CT_OIDC_CLIENT_ID")
    elif problem == "missing_policy":
        path.unlink()
    elif problem == "invalid_policy":
        path.write_text('{"version":1,"entries":[],"entries":[]}', encoding="utf-8")
    elif problem == "same_audience":
        monkeypatch.setenv("CT_OIDC_AUDIENCE", env["CT_OIDC_CLIENT_ID"])
    elif problem == "dev":
        monkeypatch.setenv("CT_AUTH_MODE", "dev")
    else:
        if problem == "wrong_issuer":
            policy["entries"][0]["issuer"] = "https://other.fixture.test"
        else:
            policy["entries"] = []
        path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError):
        preflight()()


def test_rendered_profiles_validate_signed_identity_and_account_scope(manifest_env, crypto, monkeypatch):
    env, _ = manifest_env
    preflight()()
    now = int(time.time())
    key = crypto[2]["rsa"]
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="fixture", alg="RS256")
    cache = {"version": 1, "issuer": env["CT_OIDC_ISSUER"], "audience": env["CT_OIDC_AUDIENCE"],
             "authorized_party": env["CT_OIDC_AUTHORIZED_PARTY"], "jwks_url": env["CT_OIDC_JWKS_URL"],
             "fetched_at": now, "observed_at": now, "jwks": {"keys": [jwk]}}
    write_cache(Path(env["CT_STATE_DIR"]) / "auth/jwks.json", json.dumps(cache).encode())
    monkeypatch.setattr(OIDCValidator, "_refresh", lambda _: pytest.fail("Fixture must not contact an identity endpoint"))
    ctx = AppContext(Settings.from_env())
    for tid in ("alpha", "beta"):
        ctx.inventory.add_new(Target(tid, tid, "linux", simulated=True, transport="simulated", environment=tid))
    ctx.inventory.save()
    app = create_app(ctx)
    claims = {"iss": env["CT_OIDC_ISSUER"], "sub": "fixture-reader", "aud": env["CT_OIDC_AUDIENCE"],
              "azp": env["CT_OIDC_CLIENT_ID"], "iat": now, "exp": now + 120,
              "ct_kind": "human", "ct_roles": ["viewer"]}

    def bearer(**updates):
        return {"Authorization": "Bearer " + jwt.encode({**claims, **updates}, key, algorithm="RS256", headers={"kid": "fixture"})}

    with TestClient(app, base_url=env["CT_OIDC_REDIRECT_URI"].removesuffix("/auth/callback")) as client:
        status = client.get("/auth/status")
        assert status.status_code == 200 and status.json()["authenticated"] is False
        assert status.json()["login_available"] is True
        assert client.get("/api/v1/status").status_code == 401
        targets = client.get("/api/v1/targets", headers=bearer())
        assert targets.status_code == 200, targets.text
        assert [target["id"] for target in targets.json()["targets"]] == ["alpha"]
        assert client.get("/api/v1/targets/beta/readiness", headers=bearer()).status_code == 403
        assert client.get("/api/v1/targets/alpha/readiness", headers=bearer(sub="unprovisioned", ct_roles=["admin"])).status_code == 403
        assert client.get("/api/v1/targets", headers=bearer(aud=env["CT_OIDC_CLIENT_ID"])).status_code == 401
