"""Install a checksum-verified Linux kubectl using only the Python standard library."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import tempfile
import time
from urllib.parse import urlsplit
import urllib.request


DESTINATION = Path("/usr/local/bin/kubectl")
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_CHECKSUM_BYTES = 256
SOCKET_TIMEOUT = 15
DOWNLOAD_SECONDS = 120
CHUNK_BYTES = 64 * 1024
HOSTS = {"dl.k8s.io", "cdn.dl.k8s.io"}


def validate_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.query or parsed.fragment):
        raise ValueError("kubectl downloads require an approved HTTPS release host")


class ReleaseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def release_url(version, arch):
    if not re.fullmatch(r"v1\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})", version):
        raise ValueError("kubectl version must be a stable v1.MINOR.PATCH release")
    if not arch:
        if platform.system() != "Linux":
            raise ValueError("native kubectl architecture detection requires Linux")
        arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64",
                "arm64": "arm64"}.get(platform.machine().lower())
    if arch not in {"amd64", "arm64"}:
        raise ValueError("kubectl architecture must be amd64 or arm64")
    return f"https://dl.k8s.io/release/{version}/bin/linux/{arch}/kubectl"


def download(opener, url, limit, deadline):
    """Yield bounded chunks; each blocking operation also has a socket timeout."""
    validate_url(url)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("kubectl download deadline exceeded")
    with opener.open(url, timeout=min(SOCKET_TIMEOUT, remaining)) as response:
        validate_url(response.geturl())
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("kubectl download deadline exceeded")
            chunk = response.read1(min(CHUNK_BYTES, limit - total + 1))
            total += len(chunk)
            if total > limit:
                raise ValueError("kubectl download exceeds size limit")
            if not chunk:
                break
            yield chunk


def install(version, arch):
    url = release_url(version, arch)
    opener = urllib.request.build_opener(ReleaseRedirects())
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    expected = b"".join(download(opener, url + ".sha256", MAX_CHECKSUM_BYTES, deadline)).strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", expected):
        raise ValueError("invalid kubectl SHA-256 checksum")
    # A sibling temporary file keeps replacement atomic and never follows an old destination symlink.
    fd, temporary = tempfile.mkstemp(prefix=".kubectl-", dir=DESTINATION.parent)
    temporary = Path(temporary)
    try:
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "wb") as output:
            for chunk in download(opener, url, MAX_BINARY_BYTES, deadline):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            if not size or digest.hexdigest() != expected.decode("ascii").lower():
                raise ValueError("kubectl checksum mismatch or empty binary")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o755)
        os.replace(temporary, DESTINATION)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Installed kubectl {version} ({size} bytes, sha256={digest.hexdigest()}) from {url}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--arch", default="")
    args = parser.parse_args()
    install(args.version, args.arch)


if __name__ == "__main__":
    main()
