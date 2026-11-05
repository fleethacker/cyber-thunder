"""Controlled Trivy invocations; no OCI client or scanner implementation."""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable

from .errors import UpdateStopped, VulnerabilityUnavailable

MINIMUM_VERSION = (0, 71, 1)
MAIN_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
JAVA_REPOSITORY = "ghcr.io/aquasecurity/trivy-java-db:1"
OUTPUT_LIMIT = 64 * 1024
POLL_SECONDS = 0.1


def environment(home: Path) -> dict[str, str]:
    # Exclude TRIVY_*, registry credentials, credential helper configuration,
    # loader injection variables and user configuration directories entirely.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC",
               "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    result = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "DOCKER_CONFIG",
                 "TMPDIR", "TMP", "TEMP", "APPDATA", "LOCALAPPDATA"):
        result[name] = str(home)
    return result


def executable(binary: str) -> str:
    found = shutil.which(binary)
    if not found or Path(found).suffix.lower() in {".bat", ".cmd", ".ps1"}:
        raise VulnerabilityUnavailable("Trivy executable is unavailable")
    return str(Path(found).resolve())


def _stop(process: subprocess.Popen) -> None:
    """Bounded termination; downloads use a process group on POSIX."""
    if os.name == "nt" and process.poll() is not None:
        return
    if os.name == "nt":
        # Use the OS executable directly, never cmd.exe or shell=True.
        taskkill = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "taskkill.exe"
        try:
            subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=3, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _read_available(stream) -> bytes | None:
    """Read a pipe without blocking: None means open but no bytes available."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
        peek.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                         wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
        peek.restype = wintypes.BOOL
        available = wintypes.DWORD()
        if not peek(msvcrt.get_osfhandle(stream.fileno()), None, 0, None,
                    ctypes.byref(available), None):
            if ctypes.get_last_error() == 109:  # ERROR_BROKEN_PIPE: all writers closed
                return b""
            raise VulnerabilityUnavailable("Trivy version output was invalid")
        if not available.value:
            return None
        return stream.read(min(4096, available.value))
    import select
    if not select.select([stream], [], [], 0)[0]:
        return None
    return stream.read(4096)


def run(argv: list[str], *, home: Path, timeout: float, guard: Callable[[], None],
        capture: bool = False) -> bytes:
    """Poll controls and discard raw output. Only the bounded version probe captures."""
    guard()
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    try:
        process = subprocess.Popen(argv, cwd=home, env=environment(home), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False, bufsize=0, **kwargs)
    except OSError:
        raise VulnerabilityUnavailable("Trivy executable could not be started") from None
    output = bytearray()
    deadline = time.monotonic() + timeout
    pipe_deadline = None
    try:
        while True:
            guard()
            if time.monotonic() >= deadline:
                raise UpdateStopped("Trivy operation timed out")
            eof = not capture
            if capture:
                while True:
                    block = _read_available(process.stdout)
                    if not block:
                        eof = block == b""
                        break
                    if len(output) + len(block) > OUTPUT_LIMIT:
                        raise VulnerabilityUnavailable("Trivy version output exceeded limit")
                    output.extend(block)
            if process.poll() is not None:
                if eof:
                    break
                if pipe_deadline is None:
                    pipe_deadline = time.monotonic() + 1
                elif time.monotonic() >= pipe_deadline:
                    raise VulnerabilityUnavailable("Trivy version output was invalid")
            time.sleep(POLL_SECONDS)
        guard()
        if process.returncode:
            raise VulnerabilityUnavailable("Trivy operation failed; previous database retained")
        return bytes(output)
    finally:
        _stop(process)
        if process.stdout:
            process.stdout.close()


def probe(binary: str, home: Path, *, guard: Callable[[], None] | None = None) -> dict:
    result = {"available": False, "version": None, "supported": False, "error": None}
    try:
        command = executable(binary)
        raw = run([command, "--version"], home=home, timeout=5, guard=guard or (lambda: None), capture=True)
        result["available"] = True
        match = re.search(rb"(?m)^Version:\s*v?(\d+)\.(\d+)\.(\d+)([^\r\n]*)", raw)
        if not match or len(match.group(0)) > 128:
            raise VulnerabilityUnavailable("Trivy returned an unrecognized version")
        version = tuple(int(match.group(i)) for i in (1, 2, 3))
        # Prerelease/development builds are not a supported patched release.
        suffix = match.group(4).strip()
        if suffix and not re.fullmatch(rb"\+[A-Za-z0-9.-]+", suffix):
            raise VulnerabilityUnavailable("Trivy prerelease builds are unsupported")
        result["version"] = ".".join(str(i) for i in version)
        result["supported"] = version >= MINIMUM_VERSION
        if not result["supported"]:
            result["error"] = "Trivy 0.71.1 or newer is required"
    except UpdateStopped as exc:
        if guard is not None:
            raise
        result["error"] = str(exc)
    except VulnerabilityUnavailable as exc:
        result["error"] = str(exc)
    return result


def download_args(binary: str, cache: Path, config: Path, timeout: float, *, java: bool) -> list[str]:
    return [binary, "image", "--config", str(config), "--cache-dir", str(cache),
            "--scanners", "vuln", "--skip-version-check", "--no-progress", "--quiet",
            "--timeout", f"{max(1, int(timeout))}s", "--db-repository", MAIN_REPOSITORY,
            "--java-db-repository", JAVA_REPOSITORY,
            *( ["--download-java-db-only", "--skip-db-update"] if java
               else ["--download-db-only", "--skip-java-db-update"] )]
