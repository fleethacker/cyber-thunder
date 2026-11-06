"""WinRM transport (pywinrm) for Windows hosts.

Commands run as PowerShell. A command that is already a 'powershell ... -EncodedCommand <b64>' line (how the
Windows adapter ships its scripts) is started directly, so it is not wrapped and encoded a second time.
Everything else goes through Session.run_ps.

Target fields:
  address, port (5985 http / 5986 https), username, credential_ref -> password from env CT_CRED_<ref>
  options.transport        ntlm (range default) | kerberos (fleet default) | basic | credssp
  options.ssl              true for https; fleet defaults to HTTPS on port 5986
  options.cert_validation  validate (default) | ignore      (ignore only on an isolated range)
  options.ca_trust_path    CA bundle for https
  options.allow_insecure_range  explicit acknowledgement for insecure range connections
The password is read from the environment when the transport is built and is never written anywhere.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import time

from .base import CommandResult, Transport, TransportError
from .trust import (TrustError, TrustEvents, boolean, bound_account, ca_context, endpoint_host, endpoint_port,
                    harden_winrm_session, security_mode as resolve_security_mode, trust_file)

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


class WinRMTransport(TrustEvents, Transport):
    kind = "winrm"

    def __init__(self, host: str, *, port: int | None = None, username: str | None = None, password: str | None = None,
                 auth: str | None = None, ssl: bool | None = None, cert_validation: str = "validate",
                 ca_trust_path: str | None = None, operation_timeout_s: int = 60, read_timeout_s: int = 90,
                 session=None, security_mode: str = "range", allow_insecure_range: bool = False,
                 guard=None, on_security_event=None):
        self._init_events(on_security_event)
        self.security_mode = resolve_security_mode(value=security_mode)
        auth = auth if auth is not None else ("kerberos" if self.security_mode == "fleet" else "ntlm")
        if auth not in AUTH_KINDS:
            raise TransportError("WinRM transport must be ntlm, kerberos, basic, or credssp")
        if cert_validation not in ("validate", "ignore"):
            raise TransportError("WinRM cert_validation must be validate or ignore")
        self.host = endpoint_host(host)
        self.ssl = boolean(ssl, "ssl") if ssl is not None else (port == 5986 or (port is None and self.security_mode == "fleet"))
        self.port = endpoint_port(port if port is not None else (5986 if self.ssl else 5985))
        self.username = username
        self._password = password
        self.auth = auth
        self.cert_validation = cert_validation
        self.ca_trust_path = ca_trust_path
        self.allow_insecure_range = boolean(allow_insecure_range, "allow_insecure_range")
        self._guard = guard if guard is not None else lambda: None
        self._tls_context = None
        if self.security_mode == "fleet":
            self._check_policy()
            self.ca_trust_path = trust_file(ca_trust_path, "CA bundle")
            self._tls_context = ca_context(self.ca_trust_path)
            if session is not None:
                raise TrustError("transport:injected_session", "Fleet WinRM must construct its own trusted session")
        self.operation_timeout_s = operation_timeout_s
        self.read_timeout_s = read_timeout_s
        self._session = session          # tests inject a fake; live use builds a pywinrm Session lazily

    @property
    def endpoint(self) -> str:
        host = self.host
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        return f"{'https' if self.ssl else 'http'}://{host}:{self.port}/wsman"

    @classmethod
    def from_target(cls, target, settings=None, *, guard=None, on_security_event=None) -> "WinRMTransport":
        if not target.address:
            raise TransportError("WinRM target has no address")
        o = target.options or {}
        bound = bound_account(target)
        if bound and (o["credential_source"] != "environment" or o.get("transport") != "ntlm"
                      or not target.credential_ref or "key_file" in o or target.sudo is not False):
            raise TrustError("transport:invalid_credential_binding", "Selected WinRM account requires an explicit NTLM environment credential without sudo")
        password = None
        if target.credential_ref:
            from cyberthunder.transport.ssh import credential_from_env
            password = credential_from_env(target.credential_ref) if target.credential_ref else None
        if bound and not password:
            raise TrustError("transport:credential_unavailable", "Selected WinRM environment credential is unavailable")
        mode = resolve_security_mode(settings)
        auth = o.get("transport", "kerberos" if mode == "fleet" else "ntlm")
        if isinstance(auth, str):
            auth = auth.lower()
        if password is None and auth != "kerberos":
            raise TransportError("Set the target's named CT_CRED credential in the environment for WinRM logon")
        ssl = o.get("ssl")
        return cls(target.address, port=target.port, username=target.username, password=password, auth=auth,
                   ssl=ssl, cert_validation=o.get("cert_validation", "validate"),
                   ca_trust_path=o.get("ca_trust_path"), security_mode=mode,
                   allow_insecure_range=o.get("allow_insecure_range", False),
                   guard=guard, on_security_event=on_security_event)

    def _check_policy(self):
        if self.security_mode == "fleet":
            if not self.ssl or self.port == 5985:
                raise TrustError("transport:https_required", "Fleet WinRM requires HTTPS and refuses port 5985")
            if self.cert_validation != "validate":
                raise TrustError("transport:certificate_required", "Fleet WinRM requires certificate validation")
            if self.auth not in ("kerberos", "ntlm"):
                raise TrustError("transport:auth_refused", "Fleet WinRM refuses Basic and CredSSP")
            if not self.ca_trust_path:
                raise TrustError("transport:ca_required", "Fleet WinRM requires an explicit trusted CA bundle")
        else:
            exceptions = []
            if not self.ssl:
                exceptions.append(("transport:winrm_http", "Range exception: WinRM uses HTTP without TLS server identity verification"))
            if self.ssl and self.cert_validation == "ignore":
                exceptions.append(("transport:winrm_cert_unverified", "Range exception: WinRM certificate identity is unverified"))
            if self.auth in ("basic", "credssp"):
                exceptions.append(("transport:winrm_legacy_auth", "Range exception: WinRM uses Basic or CredSSP authentication"))
            if exceptions and not self.allow_insecure_range:
                raise TrustError("transport:range_ack_required", "Insecure range WinRM requires allow_insecure_range=true")
            for code, message in exceptions:
                self._event(code, message)

    def _sess(self):
        self._guard()
        self._check_policy()
        if self._session is None:
            try:
                import winrm  # pywinrm, in requirements
            except ImportError:  # pragma: no cover
                raise TransportError("pywinrm is not installed") from None
            kw = dict(transport=self.auth, server_cert_validation=self.cert_validation,
                      operation_timeout_sec=self.operation_timeout_s, read_timeout_sec=self.read_timeout_s)
            if self.ca_trust_path:
                kw["ca_trust_path"] = self.ca_trust_path
            if self.security_mode == "fleet":
                kw.update(proxy=None, kerberos_delegation=False, send_cbt=True)
            auth = (self.username or "", self._password or "")
            try:
                session = winrm.Session(self.endpoint, auth=auth, **kw)
                if self.security_mode == "fleet":
                    http_session = session.protocol.transport.build_session()
                    harden_winrm_session(http_session, endpoint=self.endpoint,
                                         ca_path=self.ca_trust_path, context=self._tls_context, event=self._event)
                self._session = session
            except Exception:  # noqa: BLE001
                raise TransportError("WinRM session initialization failed; check configured authentication support") from None
        return self._session

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        t0 = time.time()
        sess = self._sess()
        self._guard()
        m = ENCODED_RE.match(command)
        try:
            if m:
                args = [*m.group(2).split(), "-EncodedCommand", m.group(3)]
                r = sess.run_cmd(m.group(1), args)
            else:
                r = sess.run_ps(command)
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001
            from requests.exceptions import SSLError
            if isinstance(exc, SSLError):
                self._event("transport:tls_failed", "WinRM TLS trust or handshake failed", "high")
                raise TrustError("transport:tls_failed", "WinRM TLS trust or handshake failed") from None
            raise TransportError("WinRM command failed") from None
        self._guard()
        return CommandResult(command, int(getattr(r, "status_code", 1)), _decode(getattr(r, "std_out", b"")),
                             _decode(getattr(r, "std_err", b"")), time.time() - t0, t0)

    def read_file(self, path: str) -> bytes:
        r = self.run(read_file_script(path))
        if not r.ok:
            raise TransportError("WinRM file read failed")
        try:
            return base64.b64decode("".join(r.stdout.split()), validate=True)
        except ValueError:
            raise TransportError("WinRM file output was not base64") from None

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        chunks = [data[i:i + WRITE_CHUNK] for i in range(0, len(data), WRITE_CHUNK)] or [b""]
        for n, chunk in enumerate(chunks):
            r = self.run(write_chunk_script(path, chunk, first=(n == 0)))
            if not r.ok:
                raise TransportError("WinRM file write failed")

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
