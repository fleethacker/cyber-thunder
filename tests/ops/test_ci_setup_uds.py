"""Offline acquisition failures and integrity checks for the CI-only tool."""
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace
import urllib.error

import pytest

from scripts import ci_setup_uds as setup
from scripts.ci_pytest import RegressionPolicy, UDS_REASON, UDS_TESTS


@pytest.fixture
def download(monkeypatch):
    payload = b"reviewed test bytes"
    monkeypatch.setattr(setup.sys, "platform", "linux")
    monkeypatch.setattr(setup.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(setup, "SHA256", hashlib.sha256(payload).hexdigest())
    calls = []

    def open_url(url, timeout):
        calls.append((url, timeout))
        response = io.BytesIO(payload)
        response.status = 200
        response.geturl = lambda: setup.URL
        return response

    monkeypatch.setattr(setup.urllib.request, "urlopen", open_url)
    return payload, calls


def test_verified_download_and_offline_reuse(tmp_path, download, monkeypatch):
    payload, calls = download
    target = setup.install(tmp_path)
    assert target.read_bytes() == payload
    assert calls == [(setup.URL, 60)]
    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network"))
    assert setup.install(tmp_path, offline=True) == target
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("payload", [b"", b"<html>error</html>", b"wrong binary"])
def test_malformed_or_mismatched_download_not_published(tmp_path, download, monkeypatch, payload):
    def malformed(*args, **kwargs):
        response = io.BytesIO(payload)
        response.status = 200
        response.geturl = lambda: setup.URL
        return response
    monkeypatch.setattr(setup.urllib.request, "urlopen", malformed)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        setup.install(tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("offline", [False, True])
def test_corrupt_cache_fails_without_network(tmp_path, download, offline):
    (tmp_path / "uds").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        setup.install(tmp_path, offline=offline)
    assert download[1] == []
    assert (tmp_path / "uds").read_bytes() == b"corrupt"


def test_offline_cache_miss(tmp_path, download):
    with pytest.raises(ValueError, match="unavailable"):
        setup.install(tmp_path, offline=True)
    assert download[1] == []


@pytest.mark.parametrize("failure", [urllib.error.URLError("offline"), TimeoutError("timeout"),
                                   urllib.error.HTTPError(setup.URL, 404, "missing", {}, None)])
def test_download_error_cleans_partial_file(tmp_path, download, monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(setup.urllib.request, "urlopen", fail)
    with pytest.raises(OSError):
        setup.install(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_size_limit(tmp_path, download, monkeypatch):
    monkeypatch.setattr(setup, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        setup.install(tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("status,url", [(503, setup.URL), (200, "http://example.invalid/uds")])
def test_unsuccessful_or_insecure_response(tmp_path, download, monkeypatch, status, url):
    def response(*args, **kwargs):
        stream = io.BytesIO(download[0])
        stream.status = status
        stream.geturl = lambda: url
        return stream
    monkeypatch.setattr(setup.urllib.request, "urlopen", response)
    with pytest.raises(ValueError, match="HTTPS response"):
        setup.install(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_partial_read_failure_is_cleaned(tmp_path, download, monkeypatch):
    class Interrupted(io.BytesIO):
        status = 200

        def geturl(self):
            return setup.URL

        def read(self, size):
            if self.tell():
                raise OSError("connection lost")
            return super().read(size)

    monkeypatch.setattr(setup.urllib.request, "urlopen", lambda *a, **k: Interrupted(download[0]))
    with pytest.raises(OSError, match="connection lost"):
        setup.install(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_non_file_cache_refused(tmp_path, download):
    (tmp_path / "uds").mkdir()
    with pytest.raises(ValueError, match="regular file"):
        setup.install(tmp_path)
    assert download[1] == []


@pytest.mark.parametrize("system,machine", [("win32", "AMD64"), ("linux", "aarch64")])
def test_unsupported_platform(tmp_path, download, monkeypatch, system, machine):
    monkeypatch.setattr(setup.sys, "platform", system)
    monkeypatch.setattr(setup.platform, "machine", lambda: machine)
    with pytest.raises(ValueError, match="Linux amd64 only"):
        setup.install(tmp_path)
    assert download[1] == []


def test_cli_failure_is_nonzero(tmp_path, download, monkeypatch, capsys):
    monkeypatch.setattr(setup.sys, "argv", ["ci_setup_uds.py", "--directory", str(tmp_path), "--offline"])
    assert setup.main() == 1
    assert "UDS setup failed" in capsys.readouterr().err


def test_all_19_missing_tool_skips_fail_policy():
    policy = RegressionPolicy(Path.cwd(), "linux")
    for name in UDS_TESTS:
        policy.pytest_runtest_logreport(SimpleNamespace(
            nodeid=f"tests/test_dev.py::DevelopmentModeTests::{name}", when="setup",
            outcome="skipped", skipped=True, longrepr=("test_dev.py", 1, "Skipped: " + UDS_REASON)))
    assert len(policy.errors) == len(policy.skips) == 19
    assert not any(skip["allowed"] for skip in policy.skips)
