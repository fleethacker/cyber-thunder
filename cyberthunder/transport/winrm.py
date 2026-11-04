"""WinRM transport (pywinrm) for Windows hosts.

Commands run as PowerShell. A command that is already a 'powershell ... -EncodedCommand <b64>' line (how the
Windows adapter ships its scripts) is started directly, so it is not wrapped and encoded a second time.
Everything else goes through Session.run_ps.

Target fields:
  address, port (5985 http / 5986 https), username, credential_ref -> password from env CT_CRED_<ref>
  options.transport        ntlm (default) | kerberos | basic | credssp
  options.ssl              true for https; default true when port is 5986
  options.cert_validation  validate (default) | ignore      (ignore only on an isolated range)
  options.ca_trust_path    CA bundle for https
The password is read from the environment when the transport is built and is never written anywhere.
"""
from __future__ import annotations

import base64
import os
import re
import time

from .base import CommandResult, Transport, TransportError

ENCODED_RE = re.compile(r"(?i)^\s*(powershell(?:\.exe)?)((?:\s+-(?!EncodedCommand\b)\w+)*)\s+-EncodedCommand\s+([A-Za-z0-9+/=]+)\s*$")
WRITE_CHUNK = 6000          # raw bytes per write_file call; keeps each command line well under the Windows limit
AUTH_KINDS = ("ntlm", "kerberos", "basic", "credssp")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _path_expr(path: str) -> str:
    """PowerShell expression yielding `path`, passed as base64 so no quoting of the path is ever needed."""
    return f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{_b64(path)}'))"


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def read_file_script(path: str) -> str:
    return (f"$p = {_path_expr(path)}\n"
            "if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { [Console]::Error.WriteLine('not found'); exit 2 }\n"
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))")


def write_chunk_script(path: str, chunk: bytes, first: bool) -> str:
    data = base64.b64encode(chunk).decode("ascii")
    mode = "Create" if first else "Append"
    return (f"$p = {_path_expr(path)}\n"
            "$d = Split-Path -Parent $p; if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }\n"
            f"$b = [Convert]::FromBase64String('{data}')\n"
            f"$f = [IO.File]::Open($p, [IO.FileMode]::{mode}, [IO.FileAccess]::Write)\n"
            "try { $f.Write($b, 0, $b.Length) } finally { $f.Close() }")


class WinRMTransport(Transport):
    kind = "winrm"

    def __init__(self, host: str, *, port: int | None = None, username: str | None = None, password: str | None = None,
                 auth: str = "ntlm", ssl: bool | None = None, cert_validation: str = "validate",
                 ca_trust_path: str | None = None, operation_timeout_s: int = 60, read_timeout_s: int = 90,
                 session=None):
        if auth not in AUTH_KINDS:
            raise TransportError(f"unknown WinRM transport {auth!r}; expected one of {AUTH_KINDS}")
        self.host = host
        self.ssl = bool(ssl) if ssl is not None else (port == 5986)
        self.port = port or (5986 if self.ssl else 5985)
        self.username = username
        self._password = password
        self.auth = auth
        self.cert_validation = cert_validation
        self.ca_trust_path = ca_trust_path
        self.operation_timeout_s = operation_timeout_s
        self.read_timeout_s = read_timeout_s
        self._session = session          # tests inject a fake; live use builds a pywinrm Session lazily

    @property
    def endpoint(self) -> str:
        return f"{'https' if self.ssl else 'http'}://{self.host}:{self.port}/wsman"

    @classmethod
    def from_target(cls, target) -> "WinRMTransport":
        if not target.address:
            raise TransportError(f"target {target.id} has no address")
        o = target.options or {}
        password = None
        if target.credential_ref:
            password = os.environ.get(f"CT_CRED_{target.credential_ref}")
        auth = str(o.get("transport", "ntlm")).lower()
        if password is None and auth != "kerberos":
            raise TransportError(f"target {target.id}: set CT_CRED_{target.credential_ref or '<credential_ref>'} "
                                 f"in the environment for WinRM {auth} logon")
        ssl = o.get("ssl")
        return cls(target.address, port=target.port, username=target.username, password=password, auth=auth,
                   ssl=None if ssl is None else bool(ssl), cert_validation=o.get("cert_validation", "validate"),
                   ca_trust_path=o.get("ca_trust_path"))

    def _sess(self):
        if self._session is None:
            try:
                import winrm  # pywinrm, in requirements
            except ImportError as e:  # pragma: no cover
                raise TransportError("pywinrm is not installed") from e
            kw = dict(transport=self.auth, server_cert_validation=self.cert_validation,
                      operation_timeout_sec=self.operation_timeout_s, read_timeout_sec=self.read_timeout_s)
            if self.ca_trust_path:
                kw["ca_trust_path"] = self.ca_trust_path
            auth = (self.username or "", self._password or "")
            try:
                self._session = winrm.Session(self.endpoint, auth=auth, **kw)
            except Exception as e:  # noqa: BLE001
                raise TransportError(f"winrm session to {self.endpoint} failed: {e}") from e
        return self._session

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        t0 = time.time()
        sess = self._sess()
        m = ENCODED_RE.match(command)
        try:
            if m:
                args = [*m.group(2).split(), "-EncodedCommand", m.group(3)]
                r = sess.run_cmd(m.group(1), args)
            else:
                r = sess.run_ps(command)
        except TransportError:
            raise
        except Exception as e:  # noqa: BLE001
            raise TransportError(f"winrm command on {self.host} failed: {e}") from e
        return CommandResult(command, int(getattr(r, "status_code", 1)), _decode(getattr(r, "std_out", b"")),
                             _decode(getattr(r, "std_err", b"")), time.time() - t0, t0)

    def read_file(self, path: str) -> bytes:
        r = self.run(read_file_script(path))
        if not r.ok:
            raise TransportError(f"read {path} on {self.host} failed ({r.exit_code}): {r.stderr.strip()[:200]}")
        try:
            return base64.b64decode("".join(r.stdout.split()))
        except ValueError as e:
            raise TransportError(f"read {path}: output was not base64") from e

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        chunks = [data[i:i + WRITE_CHUNK] for i in range(0, len(data), WRITE_CHUNK)] or [b""]
        for n, chunk in enumerate(chunks):
            r = self.run(write_chunk_script(path, chunk, first=(n == 0)))
            if not r.ok:
                raise TransportError(f"write {path} on {self.host} failed at chunk {n} ({r.exit_code}): {r.stderr.strip()[:200]}")

    def close(self) -> None:
        s, self._session = self._session, None
        proto = getattr(s, "protocol", None)
        tr = getattr(proto, "transport", None)
        closer = getattr(tr, "close_session", None)
        if callable(closer):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass
