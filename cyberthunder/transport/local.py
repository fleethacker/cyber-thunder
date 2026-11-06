"""Run commands on this machine. Used for self-checks, for tools installed locally (trivy, oscap in WSL)
and for tests. Default shell is bash on POSIX and PowerShell on Windows; pass shell="bash" to force bash
(Git Bash on Windows)."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

from .base import CommandResult, Transport, TransportError, sudo_wrap


def command_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Pass platform essentials, never ambient credentials or shell startup hooks."""
    explicit = source is not None
    source = os.environ if source is None else source
    if not isinstance(source, Mapping):
        raise TransportError("local command environment must be a mapping")
    names = {"path": "PATH", "systemroot": "SystemRoot", "windir": "WINDIR",
             "comspec": "COMSPEC", "pathext": "PATHEXT", "temp": "TEMP", "tmp": "TMP",
             "tmpdir": "TMPDIR", "lang": "LANG", "lc_all": "LC_ALL",
             "lc_ctype": "LC_CTYPE", "tz": "TZ"}
    result = {}
    for name, value in source.items():
        canonical = names.get(name.casefold()) if isinstance(name, str) else None
        if canonical is None:
            if explicit:
                raise TransportError("local command environment contains an unsupported variable")
            continue
        if canonical in result or not isinstance(value, str) or "\x00" in value or len(value) > 32768:
            raise TransportError("local command environment contains an invalid platform variable")
        result[canonical] = value
    return result


class LocalTransport(Transport):
    kind = "local"

    def __init__(self, shell: str | None = None, cwd: str | None = None, env: dict | None = None):
        self.shell = shell or ("powershell" if sys.platform == "win32" else "bash")
        self.cwd = cwd
        self._env = dict(env) if isinstance(env, Mapping) else env

    @property
    def env(self) -> dict[str, str]:
        # Dependency collection also reads this property before spawning a process.
        return command_environment(self._env)

    def _argv(self, command: str) -> list[str]:
        if self.shell == "powershell":
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        if self.shell == "cmd":
            return ["cmd", "/d", "/c", command]
        return [self.shell, "-c", command]

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
