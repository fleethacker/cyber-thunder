"""Run commands on this machine. Used for self-checks, for tools installed locally (trivy, oscap in WSL)
and for tests. Default shell is bash on POSIX and PowerShell on Windows; pass shell="bash" to force bash
(Git Bash on Windows)."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from .base import CommandResult, Transport, TransportError, sudo_wrap


class LocalTransport(Transport):
    kind = "local"

    def __init__(self, shell: str | None = None, cwd: str | None = None, env: dict | None = None):
        self.shell = shell or ("powershell" if sys.platform == "win32" else "bash")
        self.cwd = cwd
        self.env = env

    def _argv(self, command: str) -> list[str]:
        if self.shell == "powershell":
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        if self.shell == "cmd":
            return ["cmd", "/c", command]
        return [self.shell, "-lc", command]

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        if sudo and sys.platform != "win32" and os.geteuid() != 0:  # type: ignore[attr-defined]
            command = sudo_wrap(command)
        t0 = time.time()
        try:
            p = subprocess.run(self._argv(command), capture_output=True, text=True, timeout=timeout,
                               cwd=self.cwd, env=self.env, encoding="utf-8", errors="replace")
            return CommandResult(command, p.returncode, p.stdout, p.stderr, time.time() - t0, t0)
        except subprocess.TimeoutExpired as e:
            return CommandResult(command, 124, (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                                 f"timeout after {timeout}s", time.time() - t0, t0)
        except FileNotFoundError as e:
            raise TransportError(f"shell not found: {e}") from e

    def read_file(self, path: str) -> bytes:
        return Path(path).read_bytes()

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if mode is not None and sys.platform != "win32":
            os.chmod(p, mode)
