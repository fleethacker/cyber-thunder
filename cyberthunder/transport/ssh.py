"""SSH transport (paramiko). Credentials come from the environment or a key file, never from the inventory.

Resolution order for a target:
  options.key_file                       -> private key path
  credential_ref that is an existing path -> private key path
  env CT_CRED_<credential_ref>            -> password  (ref must match [A-Za-z0-9_.-]{1,64})
  otherwise agent/keyring and ~/.ssh keys
A bare environment variable name is never read: a ref of PATH must not send $PATH to a host.
"""
from __future__ import annotations

import os
import re
import shlex
import time
from pathlib import Path

from .base import CommandResult, Transport, TransportError, sudo_wrap


CRED_REF_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def credential_from_env(ref: str) -> str | None:
    """Password for credential_ref `ref`: only the CT_CRED_<ref> variable, never a bare variable name."""
    if not CRED_REF_RE.fullmatch(ref):
        raise TransportError(f"credential_ref {ref!r} is not a key file and not a valid name ([A-Za-z0-9_.-]{{1,64}})")
    return os.environ.get(f"CT_CRED_{ref}")


class SSHTransport(Transport):
    kind = "ssh"

    def __init__(self, host: str, *, port: int = 22, username: str | None = None, password: str | None = None,
                 key_filename: str | None = None, sudo: bool = True, connect_timeout: int = 20):
        self.host, self.port, self.username = host, port, username
        self._password, self._key = password, key_filename
        self.sudo_default = sudo
        self.connect_timeout = connect_timeout
        self._client = None

    @classmethod
    def from_target(cls, target) -> "SSHTransport":
        if not target.address:
            raise TransportError(f"target {target.id} has no address")
        password = key = None
        ref = target.credential_ref
        if target.options.get("key_file"):
            key = target.options["key_file"]
        elif ref and Path(ref).expanduser().exists():
            key = str(Path(ref).expanduser())
        elif ref:
            password = credential_from_env(ref)
        return cls(target.address, port=target.port or 22, username=target.username, password=password,
                   key_filename=key, sudo=target.sudo)

    def _conn(self):
        if self._client is None:
            import paramiko
            c = paramiko.SSHClient()
            c.load_system_host_keys()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # range hosts; pin keys before fleet use
            try:
                c.connect(self.host, port=self.port, username=self.username, password=self._password,
                          key_filename=self._key, timeout=self.connect_timeout, look_for_keys=True,
                          allow_agent=True)
            except Exception as e:  # noqa: BLE001
                raise TransportError(f"ssh connect to {self.host}:{self.port} failed: {e}") from e
            self._client = c
        return self._client

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        if sudo:
            command = sudo_wrap(command)
        t0 = time.time()
        try:
            _, out, err = self._conn().exec_command(command, timeout=timeout)
            stdout = out.read().decode("utf-8", "replace")
            stderr = err.read().decode("utf-8", "replace")
            code = out.channel.recv_exit_status()
        except Exception as e:  # noqa: BLE001
            raise TransportError(f"ssh exec failed on {self.host}: {e}") from e
        return CommandResult(command, code, stdout, stderr, time.time() - t0, t0)

    def open_shell(self, width: int = 200, height: int = 50):
        """Interactive channel for devices that need a shell (network gear). Caller handles paging and prompts."""
        return self._conn().invoke_shell(width=width, height=height)

    def read_file(self, path: str) -> bytes:
        try:
            with self._conn().open_sftp() as sftp, sftp.open(path, "rb") as fh:
                return fh.read()
        except PermissionError:
            r = self.run(f"cat {shlex.quote(path)}", sudo=True)
            if not r.ok:
                raise TransportError(f"cannot read {path}: {r.stderr.strip()}")
            return r.stdout.encode("utf-8")
        except FileNotFoundError:
            raise TransportError(f"no such file on {self.host}: {path}") from None

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        tmp = f"/tmp/.ct-{os.getpid()}-{int(time.time()*1000)}"
        with self._conn().open_sftp() as sftp, sftp.open(tmp, "wb") as fh:
            fh.write(data)
        mode_arg = f"-m {mode:o} " if mode is not None else ""
        r = self.run(f"install {mode_arg}{shlex.quote(tmp)} {shlex.quote(path)} && rm -f {shlex.quote(tmp)}", sudo=sudo)
        if not r.ok:
            raise TransportError(f"cannot write {path}: {r.stderr.strip()}")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
