"""Portable container installation must fail before publishing unverified bytes."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import urllib.request

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_kubectl", ROOT / "scripts/install_kubectl.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
VERSION = "v1.36.4"
BINARY = b"test executable bytes\x00\xff"
CHECKSUM = hashlib.sha256(BINARY).hexdigest().encode() + b"\n"


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


@pytest.fixture
def download_fixture(tmp_path, monkeypatch):
    destination = tmp_path / "kubectl"
    destination.write_bytes(b"previous executable")
    monkeypatch.setattr(installer, "DESTINATION", destination)
    fixture = SimpleNamespace(destination=destination, binary=BINARY, checksum=CHECKSUM, calls=[], failure=None)

    def open_url(url, timeout):
        fixture.calls.append((url, timeout))
        if not url.endswith(".sha256") and fixture.failure:
            raise fixture.failure
        return Response(fixture.checksum if url.endswith(".sha256") else fixture.binary, url)

    monkeypatch.setattr(installer.urllib.request, "build_opener", lambda *args: SimpleNamespace(open=open_url))
    return fixture


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_explicit_target_architecture_takes_precedence(monkeypatch, arch):
    monkeypatch.setattr(installer.platform, "machine", lambda: pytest.fail("explicit architecture was ignored"))
    assert installer.release_url(VERSION, arch).endswith(f"/linux/{arch}/kubectl")


@pytest.mark.parametrize("machine,arch", [("x86_64", "amd64"), ("AMD64", "amd64"),
                                          ("aarch64", "arm64"), ("arm64", "arm64")])
def test_legacy_builder_uses_known_native_linux_architecture(monkeypatch, machine, arch):
    monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    assert installer.release_url(VERSION, "").endswith(f"/linux/{arch}/kubectl")


@pytest.mark.parametrize("system,machine", [("Linux", "riscv64"), ("Linux", "i686"), ("Windows", "AMD64")])
def test_native_fallback_rejects_unsupported_platforms(monkeypatch, system, machine):
    monkeypatch.setattr(installer.platform, "system", lambda: system)
    monkeypatch.setattr(installer.platform, "machine", lambda: machine)
    with pytest.raises(ValueError):
        installer.release_url(VERSION, "")


@pytest.mark.parametrize("version,arch", [
    ("", "amd64"), ("latest", "amd64"), ("1.36.4", "amd64"), ("v2.0.0", "amd64"),
    ("v1.36.4-rc.1", "amd64"), ("v1.036.4", "amd64"), ("v1.36.4\n", "amd64"),
    ("v1.36.4/../../elsewhere", "amd64"), ("https://user:password@other.test/file", "amd64"),
    (VERSION, "../arm64"), (VERSION, "arm64;id"), (VERSION, "x86_64"),
    (VERSION, "s390x"), (VERSION, " "), ("v1.36.4?token=value", "amd64"),
])
def test_invalid_inputs_fail_before_network_or_writes(download_fixture, version, arch):
    with pytest.raises(ValueError):
        installer.install(version, arch)
    assert download_fixture.calls == []
    assert download_fixture.destination.read_bytes() == b"previous executable"
    assert list(download_fixture.destination.parent.iterdir()) == [download_fixture.destination]


@pytest.mark.parametrize("existing", [True, False])
def test_verified_bytes_replace_existing_file_atomically(download_fixture, monkeypatch, existing):
    if not existing:
        download_fixture.destination.unlink()
    download_fixture.checksum = CHECKSUM.upper()
    monkeypatch.setattr(installer, "MAX_BINARY_BYTES", len(BINARY))
    original_replace = os.replace
    replacements = []

    def replace(source, destination):
        assert source.parent == destination.parent
        assert source.read_bytes() == BINARY
        if existing:
            assert destination.read_bytes() == b"previous executable"
        else:
            assert not destination.exists()
        if os.name != "nt":
            assert stat.S_IMODE(source.stat().st_mode) == 0o755
        replacements.append((source, destination))
        original_replace(source, destination)

    monkeypatch.setattr(installer.os, "replace", replace)
    installer.install(VERSION, "amd64")
    assert download_fixture.destination.read_bytes() == BINARY
    assert len(replacements) == 1
    assert all(0 < timeout <= installer.SOCKET_TIMEOUT for _, timeout in download_fixture.calls)
    assert list(download_fixture.destination.parent.iterdir()) == [download_fixture.destination]


@pytest.mark.parametrize("failure", ["mismatch", "malformed", "empty", "oversize_checksum",
                                     "oversize_binary", "timeout", "interrupted", "replace"])
def test_failed_install_preserves_old_binary_and_removes_temporary_file(download_fixture, monkeypatch, failure):
    if failure == "mismatch":
        download_fixture.checksum = b"0" * 64
    elif failure == "malformed":
        download_fixture.checksum = b"not a checksum"
    elif failure == "empty":
        download_fixture.binary = b""
        download_fixture.checksum = hashlib.sha256(b"").hexdigest().encode()
    elif failure == "oversize_checksum":
        download_fixture.checksum = b"a" * (installer.MAX_CHECKSUM_BYTES + 1)
    elif failure == "oversize_binary":
        monkeypatch.setattr(installer, "MAX_BINARY_BYTES", len(BINARY) - 1)
    elif failure == "timeout":
        download_fixture.failure = TimeoutError("socket timeout")
    elif failure == "interrupted":
        def interrupted(opener, url, limit, deadline):
            yield CHECKSUM if url.endswith(".sha256") else BINARY[:5]
            if not url.endswith(".sha256"):
                raise OSError("connection interrupted")
        monkeypatch.setattr(installer, "download", interrupted)
    else:
        def denied(*args):
            raise PermissionError("cannot replace executable")
        monkeypatch.setattr(installer.os, "replace", denied)
    with pytest.raises((ValueError, OSError)):
        installer.install(VERSION, "amd64")
    assert download_fixture.destination.read_bytes() == b"previous executable"
    assert list(download_fixture.destination.parent.iterdir()) == [download_fixture.destination]


def test_deadline_stops_stream_before_further_reads(monkeypatch):
    ticks = iter([0, 0, 121])
    monkeypatch.setattr(installer.time, "monotonic", lambda: next(ticks))
    response = Response(b"partial", installer.release_url(VERSION, "amd64"))
    opener = SimpleNamespace(open=lambda *a, **kw: response)
    with pytest.raises(TimeoutError, match="deadline"):
        list(installer.download(opener, response.url, 100, 120))
    assert response.closed


def test_expired_deadline_prevents_open(monkeypatch):
    monkeypatch.setattr(installer.time, "monotonic", lambda: 121)
    opener = SimpleNamespace(open=lambda *a, **kw: pytest.fail("expired download opened a connection"))
    with pytest.raises(TimeoutError, match="deadline"):
        list(installer.download(opener, installer.release_url(VERSION, "amd64"), 100, 120))


@pytest.mark.parametrize("url", ["http://dl.k8s.io/release/file", "file:///etc/passwd",
                                 "https://other.test/file", "https://user:pass@dl.k8s.io/file",
                                 "https://dl.k8s.io:8443/file", "https://dl.k8s.io/file?token=value",
                                 "https://dl.k8s.io/file#fragment"])
def test_redirects_reject_unapproved_urls(url):
    request = urllib.request.Request("https://dl.k8s.io/release/file")
    with pytest.raises(ValueError):
        installer.ReleaseRedirects().redirect_request(request, None, 302, "Found", {}, url)


def test_release_cdn_redirect_is_allowed():
    request = urllib.request.Request("https://dl.k8s.io/release/file")
    result = installer.ReleaseRedirects().redirect_request(
        request, None, 302, "Found", {}, "https://cdn.dl.k8s.io/release/file")
    assert result.full_url == "https://cdn.dl.k8s.io/release/file"


def test_docker_build_copies_installer_and_checks_executable_without_heredoc():
    source = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "<<" not in source
    assert "COPY scripts/install_kubectl.py /tmp/install_kubectl.py" in source
    command = re.search(r"(?m)^RUN python /tmp/install_kubectl.py.*", source.replace("\\\n", " ")).group()
    assert '--version="$KUBECTL_VERSION" --arch="$TARGETARCH"' in command
    assert "&& /usr/local/bin/kubectl version --client=true --output=json" in command
    patterns = (ROOT / ".dockerignore").read_text().splitlines()
    assert "!scripts/" in patterns and "!scripts/install_kubectl.py" in patterns
    assert patterns.index("!scripts/") < patterns.index("scripts/**") < patterns.index("!scripts/install_kubectl.py")
    assert "!scripts/**" not in patterns


def test_docker_build_requires_reviewed_digests_before_running_tools():
    source = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"(?m)^FROM (\S+)", source)
    assert len(images) == 3
    assert all(re.fullmatch(r"[^@]+:[^@]+@sha256:[a-f0-9]{64}", image) for image in images)
    assert "ARG KUBECTL_VERSION=v1.36.6\n" in source
    for arch in ("AMD64", "ARM64"):
        assert re.search(rf"(?m)^ARG KUBECTL_SHA256_{arch}=[a-f0-9]{{64}}$", source)
        assert f'echo "$KUBECTL_SHA256_{arch}  /usr/local/bin/kubectl"' in source
    assert source.index("sha256sum --check --strict") < source.index("kubectl version --client")
    assert "pip==26.3 --hash=sha256:" in source
    assert "--require-hashes --only-binary=:all: -r /tmp/pip-pin.txt" in source
