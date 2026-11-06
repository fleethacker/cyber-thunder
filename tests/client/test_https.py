import time

import pytest

from cyberthunder.client.errors import ClientError
from cyberthunder.client.http import Transport, require_api
from tests.security.test_oidc import https_server


def transport(server, profile_factory, certificates):
    return Transport(profile_factory(server["url"].removesuffix("/jwks"), ca_file=str(certificates[0])))


def test_real_https_and_safe_authorization_errors(https_server, profile_factory, certificates):
    server = https_server({"targets": []})
    client = transport(server, profile_factory, certificates)
    assert client.request("api", method="GET", route="/targets", credential="fixture-private").body == {"targets": []}
    assert server["requests"][0][1]["Authorization"] == "Bearer fixture-private"
    server.update(status=403, body=b'{"detail":"NEVER-PRINT-SECRET"}')
    with pytest.raises(ClientError) as error:
        require_api(client.request("api", method="GET", route="/targets", credential="fixture-private"))
    assert error.value.status == 403 and error.value.outcome == 3
    assert "NEVER" not in str(error.value.public())


@pytest.mark.parametrize("attack", ["redirect", "duplicate_length", "encoding", "oversize", "duplicate_json", "header_size"])
def test_https_bounds_and_no_credential_redirect(https_server, profile_factory, certificates, attack):
    server = https_server({})
    trap = https_server({})
    if attack == "redirect": server.update(status=307, headers={"Location": trap["url"]})
    if attack == "duplicate_length": server["extra_headers"] = [("Content-Length", "2")]
    if attack == "encoding": server["headers"]["Content-Encoding"] = "gzip"
    if attack == "oversize": server["headers"]["Content-Length"] = str(5*1024*1024)
    if attack == "duplicate_json": server["body"] = b'{"x":1,"x":2}'
    if attack == "header_size": server["headers"]["X-Huge"] = "x"*33000
    with pytest.raises(ClientError):
        transport(server, profile_factory, certificates).request("api", method="GET", route="/targets", credential="fixture-private")
    assert trap["requests"] == []


def test_https_wrong_hostname_and_missing_ca_are_rejected(https_server, profile_factory, certificates):
    wrong = https_server({}, certificate="wrong-host")
    with pytest.raises(ClientError):
        transport(wrong, profile_factory, certificates).request("api", method="GET", route="/targets")
    valid = https_server({})
    profile = profile_factory(valid["url"].removesuffix("/jwks"))
    # The fixture's SSL_CERT_FILE environment variable is intentionally not inherited.
    with pytest.raises(ClientError): Transport(profile).request("api", method="GET", route="/targets")


def test_total_deadline_stops_header_trickle(https_server, profile_factory, certificates):
    server = https_server({})
    server["slow_headers"] = True
    start = time.monotonic()
    with pytest.raises(ClientError, match="request_timeout"):
        transport(server, profile_factory, certificates).request("api", method="GET", route="/targets", timeout=0.5)
    assert time.monotonic() - start < 3


def test_worker_receives_credentials_only_over_pipe(profile, monkeypatch):
    import subprocess
    captured = {}
    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b'{"status":200,"body":"e30="}')
    monkeypatch.setattr("cyberthunder.client.http.subprocess.run", run)
    monkeypatch.setenv("CT_CRED_LEAK", "not-to-child")
    Transport(profile).request("api", method="GET", route="/targets", credential="fixture-private")
    assert "fixture-private" not in str(captured["argv"]) and "fixture-private" not in str(captured["env"])
    assert "CT_CRED_LEAK" not in captured["env"] and b"fixture-private" in captured["input"]
    assert captured["stderr"] == subprocess.DEVNULL
