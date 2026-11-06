"""Acquire the reviewed Linux amd64 UDS binary for CI rendering tests only."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import sys
import tempfile
import urllib.request

VERSION = "0.39.0"
ASSET = f"uds-cli_v{VERSION}_Linux_amd64"
URL = f"https://github.com/defenseunicorns/uds-cli/releases/download/v{VERSION}/{ASSET}"
# Official v0.39.0 checksums.txt and GitHub release asset digest agree.
SHA256 = "a40495f2c5c78507bd1b99fbaab59508f5dab71546f7cc09a902a7b07969b7a4"
MAX_BYTES = 512 * 1024 * 1024


def verify(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("UDS cache must be a regular file, not a symlink")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SHA256:
        raise ValueError(f"UDS SHA-256 mismatch: expected {SHA256}, got {digest}")


def install(directory: Path, *, offline: bool = False) -> Path:
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise ValueError("UDS CI setup supports Linux amd64 only")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "uds"
    if target.exists() or target.is_symlink():
        verify(target)  # Never silently replace a corrupt cache or use ambient PATH.
        target.chmod(0o700)
        return target
    if offline:
        raise ValueError("Verified UDS cache unavailable in offline mode")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".uds-", delete=False) as output:
            temporary = Path(output.name)
            with urllib.request.urlopen(URL, timeout=60) as response:
                if response.status != 200 or not response.geturl().startswith("https://"):
                    raise ValueError("UDS download requires a successful HTTPS response")
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError("UDS download exceeds size limit")
                    output.write(chunk)
        verify(temporary)
        temporary.chmod(0o700)
        os.replace(temporary, target)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        target = install(args.directory.resolve(), offline=args.offline)
    except (OSError, ValueError) as exc:
        print(f"UDS setup failed: {exc}", file=sys.stderr)
        return 1
    print(f"UDS {VERSION}: {target} sha256:{SHA256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
