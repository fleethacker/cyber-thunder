"""WinRM transport (pywinrm) for Windows hosts.

Commands run as PowerShell. A command that is already a 'powershell ... -EncodedCommand <b64>' line (how the
Windows adapter ships its scripts) is started directly, so it is not wrapped and encoded a second time.
Everything else goes through Session.run_ps.

Target fields:
  address, port (5985 http / 5986 https), username, credential_ref -> opaque password reference
  options.transport        ntlm (range default) | kerberos (fleet default) | basic | credssp
  options.ssl              true for https; fleet defaults to HTTPS on port 5986
  options.cert_validation  validate (default) | ignore      (ignore only on an isolated range)
  options.ca_trust_path    CA bundle for https
  options.allow_insecure_range  explicit acknowledgement for insecure range connections
Account-bound resolver uses lease the password for each operation. Legacy range
connections read CT_CRED_<ref> at construction; fleet references require a resolver.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import ipaddress
import math
import re
import time
import weakref
import xml.etree.ElementTree as ET

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
                 guard=None, on_security_event=None, credential_use=None):
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
        self._credential_use = credential_use
        if credential_use is not None:
            from cyberthunder.security.secret_resolver import CredentialUse
            if (not isinstance(credential_use, CredentialUse) or password is not None or session is not None
                    or credential_use.security_mode != self.security_mode
                    or auth != "ntlm" or credential_use.binding.provenance.target[3] != "winrm"
                    or endpoint_host(credential_use.binding.provenance.target[4]) != self.host
                    or (credential_use.binding.provenance.target[5] or (5986 if self.ssl else 5985)) != self.port
                    or credential_use.binding.username != username):
                raise TransportError("WinRM credential lease does not match this connection")
        self.auth = auth
        self.cert_validation = cert_validation
        self.ca_trust_path = ca_trust_path
        self.allow_insecure_range = boolean(allow_insecure_range, "allow_insecure_range")
        def check_authorization():
            if guard is not None:
                guard()
            if credential_use is not None:
                credential_use.check()
        self._guard = check_authorization
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
    def from_target(cls, target, settings=None, *, guard=None, on_security_event=None,
                    credential_use=None) -> "WinRMTransport":
        if not target.address:
            raise TransportError("WinRM target has no address")
        o = target.options or {}
        bound = bound_account(target)
        if bound and (o["credential_source"] != "environment" or o.get("transport") != "ntlm"
                      or not target.credential_ref or "key_file" in o or target.sudo is not False):
            raise TrustError("transport:invalid_credential_binding", "Selected WinRM account requires an explicit NTLM password reference without sudo")
        password = None
        mode = resolve_security_mode(settings)
        resolver_required = False
        if credential_use is not None:
            from cyberthunder.security.secret_resolver import CredentialUse
            if not isinstance(credential_use, CredentialUse) or not bound:
                raise TransportError("WinRM resolver requires an explicitly selected alias binding")
            credential_use.matches_target(target)
        elif target.credential_ref:
            if mode == "fleet":
                resolver_required = True
            else:
                from cyberthunder.transport.ssh import credential_from_env
                password = credential_from_env(target.credential_ref)
        if bound and not password and credential_use is None and not resolver_required:
            raise TrustError("transport:credential_unavailable", "Selected WinRM environment credential is unavailable")
        auth = o.get("transport", "kerberos" if mode == "fleet" else "ntlm")
        if isinstance(auth, str):
            auth = auth.lower()
        if password is None and auth != "kerberos" and credential_use is None and not resolver_required:
            raise TransportError("Set the target's named CT_CRED credential in the environment for WinRM logon")
        ssl = o.get("ssl")
        result = cls(target.address, port=target.port, username=target.username, password=password, auth=auth,
                   ssl=ssl, cert_validation=o.get("cert_validation", "validate"),
                   ca_trust_path=o.get("ca_trust_path"), security_mode=mode,
                   allow_insecure_range=o.get("allow_insecure_range", False),
                   guard=guard, on_security_event=on_security_event, credential_use=credential_use)
        if resolver_required:
            raise TrustError("transport:credential_resolver_required", "Fleet WinRM requires a configured credential resolver for password references")
        return result

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

    def _sess(self, *, lease=None, bounded=None):
        self._guard()
        self._check_policy()
        if self._credential_use is not None and (lease is None or self._session is not None):
            raise TransportError("WinRM resolver sessions require a scoped operation")
        if self._session is None:
            try:
                import winrm  # pywinrm, in requirements
            except ImportError:  # pragma: no cover
                raise TransportError("pywinrm is not installed") from None
            kw = dict(transport=self.auth, server_cert_validation=self.cert_validation,
                      operation_timeout_sec=self.operation_timeout_s, read_timeout_sec=self.read_timeout_s)
            if lease is not None:
                remaining = int(lease.remaining())
                if remaining < 2:
                    raise TransportError("WinRM credential lease has insufficient time remaining")
                kw["read_timeout_sec"] = min(self.read_timeout_s, remaining)
                kw["operation_timeout_sec"] = min(self.operation_timeout_s, kw["read_timeout_sec"] - 1)
            if bounded is not None:
                bounded.check()
                kw.update(operation_timeout_sec=1, read_timeout_sec=2)
            if self.ca_trust_path:
                kw["ca_trust_path"] = self.ca_trust_path
            if self.security_mode == "fleet":
                kw.update(proxy=None, kerberos_delegation=False, send_cbt=True)
            auth = (self.username or "", lease.secret.reveal() if lease is not None else self._password or "")
            failure = False
            session = None
            try:
                session = winrm.Session(self.endpoint, auth=auth, **kw)
                if bounded is not None:
                    bounded.attach(session)
                elif lease is not None:
                    sender = weakref.WeakMethod(session.protocol.transport.send_message)
                    def send_message(*args, **kwargs):
                        self._guard()
                        lease.check()
                        method = sender()
                        if method is None:
                            raise TransportError("WinRM session is closed")
                        response = method(*args, **kwargs)
                        lease.check()
                        self._guard()
                        return response
                    session.protocol.transport.send_message = send_message
                if self.security_mode == "fleet":
                    http_session = session.protocol.transport.build_session()
                    harden_winrm_session(http_session, endpoint=self.endpoint,
                                         ca_path=self.ca_trust_path, context=self._tls_context, event=self._event)
            except Exception:  # noqa: BLE001
                failure = True
            except BaseException:
                self._close_session(session, discard_password=lease is not None)
                raise
            finally:
                auth = None
            if failure:
                self._close_session(session, discard_password=lease is not None)
                raise TransportError("WinRM session initialization failed; check configured authentication support") from None
            if lease is not None or bounded is not None:
                return session
            self._session = session
        return self._session

    @contextmanager
    def bounded_reader(self, *, guard, deadline, cleanup_timeout=3):
        """One guarded lease/session; cleanup can only release this read's IDs."""
        from cyberthunder.security.secret_resolver import CredentialUse
        if (not callable(guard) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)
                or isinstance(cleanup_timeout, bool) or not isinstance(cleanup_timeout, (int, float))
                or not 0 < cleanup_timeout <= 3):
            raise TransportError("Invalid WinRM bounded read limits")
        if self._session is not None:
            raise TransportError("WinRM bounded reads cannot reuse a session")
        operation = _BoundedWinRMRead(self, guard, deadline, cleanup_timeout)
        operation.check()
        with ExitStack() as stack:
            if self._credential_use is not None:
                if not isinstance(self._credential_use, CredentialUse):
                    raise TransportError("WinRM bounded read requires a credential use")
                use = replace(self._credential_use, guard=operation.authorize)
                operation.lease = stack.enter_context(use.lease())
            session = self._sess(lease=operation.lease, bounded=operation)
            failed = False
            try:
                operation.check()
                yield operation
            except Exception as error:
                failed = True
                from winrm.exceptions import AuthenticationError
                if operation.lease is not None and isinstance(error, AuthenticationError):
                    operation.lease.authentication_failed()
                raise
            except BaseException:
                failed = True
                raise
            finally:
                try:
                    try:
                        operation.cleanup()
                    finally:
                        self._close_session(session, discard_password=True, strict=True)
                except Exception:
                    # Cleanup cannot make a cancelled/denied read successful or
                    # replace its kill signal with an ordinary provider failure.
                    if not failed:
                        raise

    @contextmanager
    def _operation_session(self):
        if self._credential_use is None:
            yield self._sess(), None
        else:
            with self._credential_use.lease() as lease:
                session = self._sess(lease=lease)
                try:
                    yield session, lease
                finally:
                    self._close_session(session, discard_password=True)

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        t0 = time.time()
        self._guard()
        m = ENCODED_RE.match(command)
        with self._operation_session() as (sess, lease):
            self._guard()
            failure = None
            try:
                if m:
                    args = [*m.group(2).split(), "-EncodedCommand", m.group(3)]
                    r = sess.run_cmd(m.group(1), args)
                else:
                    r = sess.run_ps(command)
            except TrustError:
                raise
            except Exception as exc:  # noqa: BLE001
                from requests.exceptions import SSLError
                from winrm.exceptions import AuthenticationError
                failure = "tls" if isinstance(exc, SSLError) else "authentication" if isinstance(exc, AuthenticationError) else "command"
            if failure == "tls":
                self._event("transport:tls_failed", "WinRM TLS trust or handshake failed", "high")
                raise TrustError("transport:tls_failed", "WinRM TLS trust or handshake failed") from None
            if failure is not None:
                if lease is not None and failure == "authentication":
                    lease.authentication_failed()
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
        self._close_session(s)

    @staticmethod
    def _close_session(s, *, discard_password=False, strict=False):
        proto = getattr(s, "protocol", None)
        tr = getattr(proto, "transport", None)
        closer = getattr(tr, "close_session", None)
        http_session = getattr(tr, "session", None)
        failed = False
        try:
            if callable(closer):
                try:
                    closer()
                except Exception:  # noqa: BLE001
                    failed = True
        finally:
            if discard_password:
                # Release known provider-owned references even if cancellation
                # interrupts SDK cleanup. This cannot zeroize immutable copies.
                if tr is not None and hasattr(tr, "password"):
                    tr.password = None
                if tr is not None and hasattr(tr, "encryption"):
                    tr.encryption = None
                if http_session is not None:
                    http_session.auth = None
                if proto is not None and hasattr(proto, "password"):
                    proto.password = None
        if failed and strict:
            raise TransportError("WinRM session cleanup failed") from None


class _BoundedWinRMRead:
    """Private operation capability; no unguarded collection or reusable session."""

    def __init__(self, owner, guard, deadline, cleanup_timeout):
        self.owner, self.guard, self.deadline = owner, guard, deadline
        self.cleanup_timeout = cleanup_timeout
        self.lease = self.session = self.sender = self.http = None
        self.shell = self.command = None
        self.collecting, self.cleaning = True, False
        self.cleanup_deadline, self.cleanup_sends = 0, 0
        self.cleanup_action = None
        self.adapters = weakref.WeakKeyDictionary()
        self.cleanup_wire_actions = set()

    def authorize(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WinRM bounded read deadline expired")
        self.owner._guard()
        self.guard()
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WinRM bounded read deadline expired")

    def check(self):
        if not self.collecting:
            raise TransportError("WinRM bounded collection is closed")
        self.authorize()
        if self.lease is not None:
            self.lease.check()
        if time.monotonic() >= self.deadline:
            raise TimeoutError("WinRM bounded read deadline expired")

    def attach(self, session):
        self.session = session
        provider = session.protocol.transport
        self.sender = weakref.WeakMethod(provider.send_message)
        provider.send_message = self.send_message
        builder = weakref.WeakMethod(provider.build_session)

        def build_session():
            if not self.collecting:
                self._remaining()
                # Cleanup must never invoke SDK authentication/session setup.
                return self.http
            self.check()
            build = builder()
            if build is None:
                raise TransportError("WinRM session is closed")
            http = build()
            if self.http is not None and http is not self.http:
                raise TransportError("WinRM bounded session changed")
            self.http = http
            # Requests authentication retries use adapter.send directly. Guard
            # that boundary too, after preparation and on every retry. Fleet
            # TLS hardening can replace adapters after the first build.
            for adapter in set(http.adapters.values()):
                if adapter in self.adapters:
                    continue
                sender = weakref.WeakMethod(adapter.send)

                def send(request, _sender=sender, **kwargs):
                    if request.url != self.owner.endpoint or request.method != "POST":
                        raise TransportError("WinRM bounded request was refused")
                    remaining = self._remaining()
                    if not self.collecting:
                        if self.cleanup_action in self.cleanup_wire_actions:
                            raise TransportError("WinRM cleanup retry was refused")
                        self.cleanup_wire_actions.add(self.cleanup_action)
                    kwargs["timeout"] = min(1.5, remaining / 2)
                    return _sender()(request, **kwargs)

                adapter.send = send
                self.adapters[adapter] = True
            return http

        provider.build_session = build_session

    def _remaining(self):
        provider = self.session.protocol.transport
        if self.collecting:
            self.check()
            lease_remaining = self.lease.remaining() if self.lease is not None else math.inf
            # remaining() itself runs authorization; use the clock after it.
            remaining = min(self.deadline - time.monotonic(), lease_remaining)
        else:
            if (not self.cleaning or self.http is None or provider.session is not self.http):
                raise TransportError("WinRM cleanup session is unavailable")
            remaining = self.cleanup_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WinRM bounded operation deadline expired")
        return remaining

    def send_message(self, *args, **kwargs):
        provider = self.session.protocol.transport
        if not self.collecting:
            # Only cleanup()/the two SDK release methods enter this state. Never
            # acquire another lease or rebuild a missing/changed HTTP session.
            if (not self.cleaning or self.cleanup_sends >= 2 or self.http is None
                    or provider.session is not self.http):
                raise TransportError("WinRM cleanup session is unavailable")
            self._validate_cleanup(args[0] if len(args) == 1 and not kwargs else None)
            self.cleanup_sends += 1
        remaining = self._remaining()
        # Requests applies this per connect/read; leave room for both phases.
        provider.read_timeout_sec = min(1.5, remaining / 2)
        self.session.protocol.operation_timeout_sec = 1
        sender = self.sender()
        if sender is None:
            raise TransportError("WinRM session is closed")
        response = sender(*args, **kwargs)
        self.http = provider.session
        if not self.collecting and time.monotonic() >= self.cleanup_deadline:
            raise TimeoutError("WinRM cleanup deadline expired")
        # The caller captures returned IDs before the post-operation guard, so
        # revocation after creation still permits release of those exact IDs.
        return response

    def _validate_cleanup(self, message):
        """Never let the cleanup exception send Receive/Command or foreign IDs."""
        env = "{http://www.w3.org/2003/05/soap-envelope}"
        wsa = "{http://schemas.xmlsoap.org/ws/2004/08/addressing}"
        wsman = "{http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd}"
        rsp = "{http://schemas.microsoft.com/wbem/wsman/1/windows/shell}"
        valid = False
        try:
            if not isinstance(message, (str, bytes)) or len(message) > 16384:
                raise ValueError
            root = ET.fromstring(message)
            actions = root.findall(f"{env}Header/{wsa}Action")
            selectors = root.findall(f"{env}Header/{wsman}SelectorSet/{wsman}Selector")
            body = root.find(env + "Body")
            valid = (root.tag == env + "Envelope" and len(root) == 2
                     and len(root.findall(env + "Header")) == len(root.findall(env + "Body")) == 1
                     and len(actions) == len(selectors) == 1
                     and actions[0].text == self.cleanup_action and selectors[0].attrib == {"Name": "ShellId"}
                     and selectors[0].text == self.shell and body is not None)
            if valid and self.cleanup_action.endswith("/Signal"):
                signal = body.find(rsp + "Signal")
                valid = (len(body) == 1 and signal is not None and signal.attrib == {"CommandId": self.command}
                         and len(signal) == 1 and signal[0].tag == rsp + "Code"
                         and signal[0].text == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate")
            elif valid:
                valid = len(body) == 0
        except (ValueError, TypeError, ET.ParseError):
            valid = False
        if not valid:
            raise TransportError("WinRM cleanup message was refused") from None

    def open(self):
        self.check()
        self.shell = self._identifier(self.session.protocol.open_shell(noprofile=True, codepage=65001))
        self.check()

    def run(self, program, arguments):
        self.check()
        self.command = self._identifier(self.session.protocol.run_command(self.shell, program, arguments))
        self.check()

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str) or not 0 < len(value) <= 512 or any(ord(c) < 32 for c in value):
            raise TransportError("WinRM resource identity is unavailable")
        return value

    def receive(self):
        self.check()
        try:
            result = self.session.protocol.get_command_output_raw(self.shell, self.command)
        finally:
            self.check()
        return result

    def cleanup(self):
        self.collecting = False
        self.cleanup_deadline = time.monotonic() + self.cleanup_timeout
        self.cleaning = True
        failed = False
        try:
            for method, args, kwargs, action in (
                (self.session.protocol.cleanup_command, (self.shell, self.command), {},
                 "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"),
                (self.session.protocol.close_shell, (self.shell,), {"close_session": False},
                 "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"),
            ):
                if self.shell is None or len(args) == 2 and self.command is None:
                    continue
                try:
                    self.cleanup_action = action
                    if time.monotonic() >= self.cleanup_deadline:
                        raise TimeoutError
                    method(*args, **kwargs)
                except Exception:
                    failed = True
        finally:
            self.cleaning = False
            self.cleanup_action = None
        if failed:
            raise TransportError("WinRM bounded read cleanup failed") from None
