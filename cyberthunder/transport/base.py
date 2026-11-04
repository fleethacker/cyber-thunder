"""Transport: how an adapter reaches an asset. Adapters never open sockets themselves.

Implementations: local (subprocess), ssh (paramiko), winrm (pywinrm), fixture (replay recorded outputs),
and adapter-provided ones (simulated hosts, config files, kubeconfig) via Adapter.make_transport().
"""
from __future__ import annotations

import shlex
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.config import Settings
    from cyberthunder.inventory.targets import Target


class TransportError(RuntimeError):
    pass


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    started_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return asdict(self)


class Transport(ABC):
    """Minimal remote-execution surface. `sudo=True` asks for privilege escalation where that applies."""
    kind: str = "abstract"

    @abstractmethod
    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult: ...

    @abstractmethod
    def read_file(self, path: str) -> bytes: ...

    @abstractmethod
    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None: ...

    def fetch(self, remote_path: str, local_path: str) -> None:
        from pathlib import Path
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_bytes(self.read_file(remote_path))

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # convenience
    def check_output(self, command: str, *, timeout: int = 120, sudo: bool = False) -> str:
        r = self.run(command, timeout=timeout, sudo=sudo)
        if not r.ok:
            raise TransportError(f"{command!r} failed ({r.exit_code}): {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout


def sudo_wrap(command: str) -> str:
    """Wrap a shell command for non-interactive sudo. The command runs under `sh -c` so pipes work."""
    return f"sudo -n sh -c {shlex.quote(command)}"


def make_transport(target: "Target", settings: "Settings | None" = None) -> Transport:
    """Build the transport for a target. Generic kinds here; anything else is asked of the adapter."""
    kind = target.transport
    if kind == "local":
        from .local import LocalTransport
        return LocalTransport()
    if kind == "ssh":
        from .ssh import SSHTransport
        return SSHTransport.from_target(target)
    if kind == "winrm":
        from .winrm import WinRMTransport
        return WinRMTransport.from_target(target)
    if kind == "fixture":
        from .fixture import FixtureTransport
        return FixtureTransport(target.options["fixture_dir"])
    from cyberthunder.adapters import registry
    adapter = registry.get(target.asset_type)
    t = adapter.make_transport(target, settings)
    if t is None:
        raise TransportError(f"adapter {adapter.asset_type} does not provide transport kind {kind!r}")
    return t
