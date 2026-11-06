"""SSH transport (paramiko). Credentials come from the environment or a key file, never from the inventory.

Resolution order for an unbound target:
  options.key_file                       -> private key path
  credential_ref that is an existing path -> private key path
  env CT_CRED_<credential_ref>            -> password  (ref must match [A-Za-z0-9_.-]{1,64})
  otherwise fail without attempting implicit agent or ~/.ssh key discovery
A bare environment variable name is never read: a ref of PATH must not send $PATH to a host.
Bound targets resolve only their selected credential_source and enforce their sudo permission.
"""
from __future__ import annotations

import os
import re
import shlex
import time
from pathlib import Path, PurePosixPath, PureWindowsPath

from .base import CommandResult, Transport, TransportError, sudo_wrap
from .trust import (GuardedShell, TrustError, TrustEvents, boolean, bound_account, configure_ssh_client, endpoint_host,
                    endpoint_port, security_mode as resolve_security_mode, sha256_pin)


CRED_REF_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def credential_from_env(ref: str) -> str | None:
    """Password for credential_ref `ref`: only the CT_CRED_<ref> variable, never a bare variable name."""
    if not isinstance(ref, str) or not CRED_REF_RE.fullmatch(ref):
        raise TransportError("credential_ref must be a key file or a name matching [A-Za-z0-9_.-]{1,64}")
    return os.environ.get(f"CT_CRED_{ref}")


class SSHTransport(TrustEvents, Transport):
    kind = "ssh"

    def __init__(self, host: str, *, port: int = 22, username: str | None = None, password: str | None = None,
                 key_filename: str | None = None, sudo: bool = True, connect_timeout: int = 20,
                 security_mode: str = "range", host_key_sha256: str | None = None,
                 known_hosts: str | None = None, allow_insecure_range: bool = False,
                 interactive: bool = False, allow_agent: bool = False, credential_bound: bool = False,
                 guard=None, on_security_event=None):
        self._init_events(on_security_event)
        self.security_mode = resolve_security_mode(value=security_mode)
        self.host, self.port, self.username = endpoint_host(host), endpoint_port(port), username
        self._password, self._key = password, key_filename
        self.host_key_sha256 = sha256_pin(host_key_sha256) if host_key_sha256 is not None else None
        self.known_hosts = known_hosts
        self.allow_insecure_range = boolean(allow_insecure_range, "allow_insecure_range")
        self.interactive = boolean(interactive, "interactive")
        self.allow_agent = boolean(allow_agent, "allow_agent")
        self._credential_bound = boolean(credential_bound, "credential_bound")
        if self._credential_bound and (self.interactive or self.allow_agent):
            raise TrustError("transport:invalid_credential_binding", "Selected SSH accounts cannot use ambient authentication")
        if self.allow_agent and not self.interactive:
            raise TrustError("transport:interactive_required", "SSH agent use requires an explicit interactive invocation")
        if self.host_key_sha256 and known_hosts:
            raise TrustError("transport:ambiguous_trust", "Choose one SSH host key pin or known_hosts file")
        if self.security_mode == "fleet" and not (self.host_key_sha256 or known_hosts):
            raise TrustError("transport:ssh_trust_required", "Fleet SSH requires a host key pin or provisioned known_hosts file")
        if not (self.host_key_sha256 or known_hosts) and self.allow_insecure_range:
            self._event("transport:ssh_unverified", "Range exception: SSH host identity is unverified")
        self._guard = guard if guard is not None else lambda: None
        self.sudo_default = boolean(sudo, "sudo") if self._credential_bound else sudo
        self.connect_timeout = connect_timeout
        self._client = None

    @classmethod
    def from_target(cls, target, settings=None, *, interactive=False, guard=None, on_security_event=None) -> "SSHTransport":
        if not target.address:
            raise TransportError("SSH target has no address")
        password = key = None
        ref = target.credential_ref
        options = target.options or {}
        bound = bound_account(target)
        try:
            if bound:
                source = options["credential_source"]
                if source == "environment":
                    if "key_file" in options or not ref:
                        raise TrustError("transport:invalid_credential_binding", "Selected environment credential cannot include a key file")
                    # Never probe the filesystem for a selected environment reference.
                    password = credential_from_env(ref)
                    if not password:
                        raise TrustError("transport:credential_unavailable", "Selected SSH environment credential is unavailable")
                else:
                    key = options.get("key_file")
                    if (ref is not None or not isinstance(key, str) or not key
                            or not (PurePosixPath(key).is_absolute() or PureWindowsPath(key).is_absolute())):
                        raise TrustError("transport:invalid_credential_binding", "Selected SSH key requires one explicit absolute path")
            elif options.get("key_file"):
                key = str(Path(options["key_file"]).expanduser())
            elif ref and Path(ref).expanduser().is_file():
                key = str(Path(ref).expanduser())
            elif ref:
                password = credential_from_env(ref)
        except (OSError, ValueError, TypeError):
            raise TransportError("SSH credential reference or key path is invalid") from None
        return cls(target.address, port=target.port if target.port is not None else 22,
                   username=target.username, password=password,
                   key_filename=key, sudo=target.sudo, security_mode=resolve_security_mode(settings),
                   host_key_sha256=options.get("host_key_sha256"), known_hosts=options.get("known_hosts"),
                   allow_insecure_range=options.get("allow_insecure_range", False),
                   interactive=False if bound else interactive, allow_agent=options.get("allow_agent", False),
                   credential_bound=bound,
                   guard=guard, on_security_event=on_security_event)

    def connect_client(self, *, timeout=None, guard=None, allow_agent=None):
        """New policy-checked client; callers close it, including on bounded reads.

        allow_agent=False restricts an otherwise authorized interactive agent;
        True never grants agent access absent the instance's authorization.
        """
        import paramiko

        self._guard()

        def check():
            self._guard()
            if guard is not None:
                guard()

        check()
        if allow_agent is not None:
            boolean(allow_agent, "allow_agent")
        use_agent = self.allow_agent and self.interactive and allow_agent is not False
        if not self._password and not self._key and not use_agent:
            raise TransportError("SSH requires an explicit password, key file, or authorized interactive agent")
        client = paramiko.SSHClient()
        try:
            configure_ssh_client(client, host=self.host, port=self.port, pin=self.host_key_sha256,
                                 known_hosts=self.known_hosts,
                                 allow_unverified=self.security_mode == "range" and self.allow_insecure_range,
                                 event=self._event)
            check()
            limit = self.connect_timeout if timeout is None else min(timeout, self.connect_timeout)
            try:
                client.connect(self.host, port=self.port, username=self.username, password=self._password,
                               key_filename=self._key, timeout=limit, banner_timeout=limit,
                               auth_timeout=limit, channel_timeout=limit, look_for_keys=False,
                               allow_agent=use_agent)
            except paramiko.BadHostKeyException:
                self._event("discovery:identity_changed", "SSH host key differs from provisioned known_hosts", "high")
                raise TrustError("discovery:identity_changed", "SSH host key does not match provisioned known_hosts") from None
            except TrustError:
                raise
            except Exception:
                raise TransportError("SSH connection or authentication failed") from None
            check()
            return client
        except BaseException:
            client.close()
            raise

    def _conn(self):
        self._guard()
        if self._client is None:
            self._client = self.connect_client()
        return self._client

    def _check_sudo(self, requested: bool) -> None:
        self._guard()
        if self._credential_bound and requested and self.sudo_default is not True:
            raise TrustError("transport:sudo_forbidden", "Selected SSH account does not permit sudo") from None

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        self._check_sudo(sudo)
        if sudo:
            command = sudo_wrap(command)
        t0 = time.time()
        client = self._conn()
        self._guard()
        try:
            _, out, err = client.exec_command(command, timeout=timeout)
            stdout = out.read().decode("utf-8", "replace")
            stderr = err.read().decode("utf-8", "replace")
            code = out.channel.recv_exit_status()
        except Exception:  # noqa: BLE001
            raise TransportError("SSH command failed") from None
        self._guard()
        return CommandResult(command, code, stdout, stderr, time.time() - t0, t0)

    def open_shell(self, width: int = 200, height: int = 50):
        """Interactive channel for devices that need a shell (network gear). Caller handles paging and prompts."""
        client = self._conn()
        self._guard()
        try:
            channel = client.invoke_shell(width=width, height=height)
        except Exception:
            raise TransportError("SSH interactive shell failed") from None
        try:
            self._guard()
        except BaseException:
            channel.close()
            raise
        return GuardedShell(channel, self._guard)

    def read_file(self, path: str) -> bytes:
        client = self._conn()
        self._guard()
        try:
            with client.open_sftp() as sftp, sftp.open(path, "rb") as fh:
                data = fh.read()
        except PermissionError:
            self._check_sudo(True)
            r = self.run(f"cat {shlex.quote(path)}", sudo=True)
            if not r.ok:
                raise TransportError("SSH file read failed")
            return r.stdout.encode("utf-8")
        except FileNotFoundError:
            raise TransportError("SSH file not found") from None
        except Exception:
            raise TransportError("SSH file read failed") from None
        self._guard()
        return data

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        self._check_sudo(sudo)
        tmp = f"/tmp/.ct-{os.getpid()}-{int(time.time()*1000)}"
        client = self._conn()
        self._guard()
        try:
            with client.open_sftp() as sftp, sftp.open(tmp, "wb") as fh:
                fh.write(data)
        except Exception:
            raise TransportError("SSH file staging failed") from None
        mode_arg = f"-m {mode:o} " if mode is not None else ""
        r = self.run(f"install {mode_arg}{shlex.quote(tmp)} {shlex.quote(path)} && rm -f {shlex.quote(tmp)}", sudo=sudo)
        if not r.ok:
            raise TransportError("SSH file installation failed")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
