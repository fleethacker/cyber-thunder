"""Packaged startup must use the same verified-identity boundary as the native CLI."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

import pytest
import uvicorn
from fastapi.testclient import TestClient

from cyberthunder.cli import main
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
    captured = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: captured.append((app, kwargs)))
    assert main(packaged_env) == 0
    assert captured[0][0].state.ctx.settings.auth_mode == "dev"
    assert captured[0][1]["host"] == "127.0.0.1"
