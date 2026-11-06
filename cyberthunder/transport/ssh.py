"""SSH transport (paramiko). Inventory contains references, never passwords.

Account-bound resolver uses lease one explicitly selected password source.
Explicit key files use the shared native private-file reader and in-memory parsing.
Legacy range resolution order for an unbound target:
  options.key_file                       -> private key path
  credential_ref that is an existing path -> private key path
  env CT_CRED_<credential_ref>            -> password  (ref must match [A-Za-z0-9_.-]{1,64})
  otherwise fail without attempting implicit agent or ~/.ssh key discovery
A bare environment variable name is never read: a ref of PATH must not send $PATH to a host.
Bound targets resolve only their selected credential_source and enforce their sudo permission.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
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
                 guard=None, on_security_event=None, credential_use=None):
        self._init_events(on_security_event)
        self.security_mode = resolve_security_mode(value=security_mode)
        self.host, self.port, self.username = endpoint_host(host), endpoint_port(port), username
        self._password, self._key = password, key_filename
        if key_filename is not None and password is not None:
            raise TransportError("SSH key files cannot be combined with a password")
        self._credential_use = credential_use
        if credential_use is not None:
            from cyberthunder.security.secret_resolver import CredentialUse
            if (not isinstance(credential_use, CredentialUse) or not credential_bound or password is not None
                    or credential_use.security_mode != self.security_mode
                    or key_filename is not None or interactive or allow_agent
                    or credential_use.binding.provenance.target[3] != "ssh"
                    or endpoint_host(credential_use.binding.provenance.target[4]) != self.host
                    or (credential_use.binding.provenance.target[5] or 22) != self.port
                    or credential_use.binding.username != username):
                raise TransportError("SSH credential lease does not match this connection")
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
        def check_authorization():
            if guard is not None:
                guard()
            if credential_use is not None:
                credential_use.check()
        self._guard = check_authorization
        self.sudo_default = boolean(sudo, "sudo") if self._credential_bound else sudo
        self.connect_timeout = connect_timeout
        self._client = None

    @classmethod
    def from_target(cls, target, settings=None, *, interactive=False, guard=None, on_security_event=None,
                    credential_use=None) -> "SSHTransport":
        if not target.address:
            raise TransportError("SSH target has no address")
        password = key = None
        ref = target.credential_ref
        options = target.options or {}
        bound = bound_account(target)
        mode = resolve_security_mode(settings)
        resolver_required = False
        if credential_use is not None:
            from cyberthunder.security.secret_resolver import CredentialUse
            if not isinstance(credential_use, CredentialUse) or not bound or options["credential_source"] != "environment":
                raise TransportError("SSH resolver requires an explicitly selected alias binding")
            credential_use.matches_target(target)
        try:
            if credential_use is not None:
                if "key_file" in options:
                    raise TransportError("SSH resolver cannot be combined with a key file")
            elif bound:
                source = options["credential_source"]
                if source == "environment":
                    if "key_file" in options or not ref:
                        raise TrustError("transport:invalid_credential_binding", "Selected environment credential cannot include a key file")
                    # Never probe the filesystem for a selected environment reference.
                    if mode == "fleet":
                        resolver_required = True
                    else:
                        password = credential_from_env(ref)
                    if not password and not resolver_required:
                        raise TrustError("transport:credential_unavailable", "Selected SSH environment credential is unavailable")
                else:
                    key = options.get("key_file")
                    if (ref is not None or not isinstance(key, str) or not key
                            or not (PurePosixPath(key).is_absolute() or PureWindowsPath(key).is_absolute())):
                        raise TrustError("transport:invalid_credential_binding", "Selected SSH key requires one explicit absolute path")
            elif options.get("key_file"):
                key = str(Path(options["key_file"]).expanduser())
            elif ref and (mode == "range" or PurePosixPath(ref).is_absolute() or PureWindowsPath(ref).is_absolute()) and Path(ref).expanduser().is_file():
                key = str(Path(ref).expanduser())
            elif ref:
                if mode == "fleet":
                    resolver_required = True
                else:
                    password = credential_from_env(ref)
        except (OSError, ValueError, TypeError):
            raise TransportError("SSH credential reference or key path is invalid") from None
        result = cls(target.address, port=target.port if target.port is not None else 22,
                   username=target.username, password=password,
                   key_filename=key, sudo=target.sudo, security_mode=mode,
                   host_key_sha256=options.get("host_key_sha256"), known_hosts=options.get("known_hosts"),
                   allow_insecure_range=options.get("allow_insecure_range", False),
                   interactive=False if bound else interactive, allow_agent=options.get("allow_agent", False),
                   credential_bound=bound,
                   guard=guard, on_security_event=on_security_event, credential_use=credential_use)
        if resolver_required:
            raise TrustError("transport:credential_resolver_required", "Fleet SSH requires a configured credential resolver for password references")
        return result

    def connect_client(self, *, timeout=None, guard=None, allow_agent=None, deadline=None):
        """New policy-checked client; callers close it, including on bounded reads.

        allow_agent=False restricts an otherwise authorized interactive agent;
        True never grants agent access absent the instance's authorization.
        """
        import paramiko

        def check():
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("SSH connection deadline expired")
            self._guard()
            if guard is not None:
                guard()
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("SSH connection deadline expired")

        check()
        if allow_agent is not None:
            boolean(allow_agent, "allow_agent")
        use_agent = self._key is None and self.allow_agent and self.interactive and allow_agent is not False
        if not self._password and not self._key and not use_agent and self._credential_use is None:
            raise TransportError("SSH requires an explicit password, key file, or authorized interactive agent")
        client = paramiko.SSHClient()
        try:
            configure_ssh_client(client, host=self.host, port=self.port, pin=self.host_key_sha256,
                                 known_hosts=self.known_hosts,
                                 allow_unverified=self.security_mode == "range" and self.allow_insecure_range,
                                 event=self._event)
            check()
            limit = self.connect_timeout if timeout is None else min(timeout, self.connect_timeout)
            with ExitStack() as leases:
                use = replace(self._credential_use, guard=check) if self._credential_use is not None else None
                lease = leases.enter_context(use.lease()) if use is not None else None
                if lease is not None:
                    limit = min(limit, lease.remaining())
                password = lease.secret.reveal() if lease is not None else self._password
                pkey = None
                key_auth = None
                failure = None
                try:
                    if self._key is not None:
                        from cyberthunder.security.ssh_keys import SSHKeyError, SelectedKeyAuth, load_private_key
                        try:
                            pkey = load_private_key(self._key)
                        except SSHKeyError:
                            failure = "key"
                        if failure == "key":
                            raise TrustError("transport:ssh_key_unavailable", "SSH private key is unavailable or unsafe") from None
                        key_auth = SelectedKeyAuth(self.username, pkey)
                    # Resolution and its audit/authorization callbacks can take
                    # time or cancel the caller's separate bounded probe.
                    check()
                    if lease is not None:
                        limit = min(limit, lease.remaining())
                    if deadline is not None:
                        limit = min(limit, deadline - time.monotonic())
                        if limit <= 0:
                            raise TimeoutError("SSH connection deadline expired")
                    try:
                        client.connect(self.host, port=self.port, username=self.username,
                                       key_filename=None, timeout=limit, banner_timeout=limit,
                                       auth_timeout=limit, channel_timeout=limit, look_for_keys=False,
                                       allow_agent=use_agent,
                                       **({"auth_strategy": key_auth} if key_auth is not None else {"password": password}))
                    except paramiko.BadHostKeyException:
                        failure = "host_key"
                    except paramiko.AuthenticationException:
                        failure = "authentication"
                    except TrustError as exc:
                        # Preserve the public trust diagnostic, not provider
                        # traceback frames holding the selected private key.
                        failure = (exc.code, str(exc))
                    except Exception:
                        failure = "connection"
                finally:
                    password = None
                    if lease is not None:
                        # Paramiko retains this plaintext reference after authentication.
                        # Drop it; this cannot erase copies made by Python or the provider.
                        handler = getattr(client.get_transport(), "auth_handler", None)
                        if handler is not None and hasattr(handler, "password"):
                            handler.password = None
                    if pkey is not None:
                        handler = getattr(client.get_transport(), "auth_handler", None)
                        if handler is not None and hasattr(handler, "private_key"):
                            handler.private_key = None
                    if key_auth is not None:
                        key_auth.pkey = None
                    pkey = None
                    key_auth = None
                if isinstance(failure, tuple):
                    raise TrustError(*failure) from None
                if failure == "host_key":
                    self._event("discovery:identity_changed", "SSH host key differs from provisioned known_hosts", "high")
                    raise TrustError("discovery:identity_changed", "SSH host key does not match provisioned known_hosts") from None
                if failure is not None:
                    if lease is not None and failure == "authentication":
                        lease.authentication_failed()
                    raise TransportError("SSH connection or authentication failed") from None
            check()
            return client
        except BaseException:
            try:
                client.close()
            except Exception:
                pass
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
