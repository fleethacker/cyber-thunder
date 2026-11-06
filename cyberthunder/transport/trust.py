"""Shared target trust policy and sanitized integration events.

Events describe failures or exceptions, never proof of a verified identity. The
application owns binding them to a target, durable audit, and warning findings.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import logging
import re
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path

from .base import TransportError

log = logging.getLogger(__name__)
MAX_TRUST_FILE = 1024 * 1024
_UNSET = object()


class TrustError(TransportError):
    """Fixed error code and safe text; no underlying protocol error or secret."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class SecurityEvent:
    code: str
    severity: str
    message: str
    verified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class TrustEvents:
    def _init_events(self, on_security_event=None):
        self.security_events: list[SecurityEvent] = []
        self._on_security_event = on_security_event

    def _event(self, code: str, message: str, severity: str = "medium"):
        event = SecurityEvent(code, severity, message)
        if event not in self.security_events:
            log.warning("%s: %s", code, message)
            if self._on_security_event is not None:
                try:
                    self._on_security_event(event)
                except Exception:
                    # An unavailable audit sink must not permit an unsafe connection.
                    raise TrustError("transport:event_sink_failed", "Transport security event could not be recorded") from None
            self.security_events.append(event)

    def check_output(self, command: str, *, timeout: int = 120, sudo: bool = False) -> str:
        result = self.run(command, timeout=timeout, sudo=sudo)
        if not result.ok:
            raise TransportError("Remote command returned a nonzero status")
        return result.stdout


class GuardedShell:
    """Keep the scope/kill callback on each operation after open_shell returns."""

    def __init__(self, channel, guard):
        self._channel, self._guard = channel, guard

    def close(self):
        # Closing our own channel is permitted after revocation.
        self._channel.close()

    def __getattr__(self, name):
        value = getattr(self._channel, name)
        if not callable(value):
            return value

        def guarded(*args, **kwargs):
            self._guard()
            try:
                result = value(*args, **kwargs)
            except Exception:
                raise TransportError("SSH interactive channel operation failed") from None
            self._guard()
            return result

        return guarded


def security_mode(settings=None, *, value=_UNSET) -> str:
    mode = getattr(settings, "security_mode", "range") if value is _UNSET else value
    if mode not in ("range", "fleet"):
        raise TrustError("transport:invalid_mode", "security_mode must be range or fleet")
    return mode


def boolean(value, name: str) -> bool:
    if type(value) is not bool:
        raise TrustError("transport:invalid_option", f"{name} must be a boolean")
    return value


def bound_account(target) -> bool:
    """Validate the transport portion of a selected account's detached target.

    This marker is not an authorization proof; policy selection and fresh
    principal/target checks remain the caller's responsibility.
    """
    options = target.options or {}
    bound = boolean(options.get("credential_bound", False), "credential_bound")
    if bound and (not isinstance(target.username, str) or not target.username
                  or type(target.sudo) is not bool
                  or options.get("credential_source") not in ("environment", "key_file")
                  or any(options.get(name) is not False
                         for name in ("allow_agent", "look_for_keys", "interactive_auth"))):
        raise TrustError("transport:invalid_credential_binding", "Selected account requires an explicit source and disabled ambient authentication")
    return bound


def endpoint_host(host: str) -> str:
    """Accept one DNS name or IP literal; URLs/userinfo cannot change the peer."""
    if not isinstance(host, str) or not host or len(host) > 253 or any(c in host for c in "/\\@[]%"):
        raise TrustError("transport:invalid_host", "Target address must be a DNS name or IP literal")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
        pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if re.fullmatch(r"[0-9.]+", host) or not all(re.fullmatch(pattern, label) for label in labels):
            raise TrustError("transport:invalid_host", "Target address must be a DNS name or IP literal") from None
    return host.lower()


def endpoint_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise TrustError("transport:invalid_port", "Target port must be an integer from 1 through 65535")
    return port


def trust_file(value, kind: str) -> str:
    try:
        if not isinstance(value, (str, Path)) or not str(value) or str(value) == "legacy_requests":
            raise ValueError
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_TRUST_FILE:
            raise ValueError
        return str(path)
    except (ValueError, OSError, RuntimeError):
        raise TrustError("transport:invalid_trust_file", f"An explicit readable {kind} file is required (maximum 1 MiB)") from None


def sha256_pin(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}=?", value):
        raise TrustError("transport:invalid_pin", "SSH host key pin must be a SHA256 fingerprint")
    try:
        raw = base64.b64decode(value[7:].rstrip("=") + "=", validate=True)
    except (ValueError, binascii.Error):
        raise TrustError("transport:invalid_pin", "SSH host key pin must be a SHA256 fingerprint") from None
    normalized = "SHA256:" + base64.b64encode(raw).decode("ascii").rstrip("=")
    if len(raw) != 32 or normalized != value.rstrip("="):
        raise TrustError("transport:invalid_pin", "SSH host key pin must be a SHA256 fingerprint")
    return normalized


def key_fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


def configure_ssh_client(client, *, host: str, port: int, pin: str | None,
                         known_hosts: str | None, allow_unverified: bool, event):
    """Configure host checking before Paramiko can send authentication material."""
    import paramiko

    if pin and known_hosts:
        raise TrustError("transport:ambiguous_trust", "Choose one SSH host key pin or known_hosts file")
    expected_host = host if port == 22 else f"[{host}]:{port}"

    class PinPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, hostname, key):
            if hostname != expected_host or not hmac.compare_digest(key_fingerprint(key), pin):
                event("discovery:identity_changed", "SSH host key differs from the provisioned pin", "high")
                raise TrustError("discovery:identity_changed", "SSH host key does not match the provisioned pin")

    class RangePolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, _hostname, _key):
            event("transport:ssh_unverified", "Range exception: SSH host identity is unverified")
            # No persistence and no claim that an observed key is trustworthy.

    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    if pin:
        client.set_missing_host_key_policy(PinPolicy())
    elif known_hosts:
        path = trust_file(known_hosts, "known_hosts")
        try:
            client.load_host_keys(path)
            entry = client.get_host_keys().lookup(expected_host)
        except Exception:
            raise TrustError("transport:invalid_trust_file", "SSH known_hosts file could not be loaded") from None
        if not entry:
            event("transport:unknown_host_key", "SSH endpoint is absent from provisioned known_hosts", "high")
            raise TrustError("transport:unknown_host_key", "SSH endpoint is absent from provisioned known_hosts")
    elif allow_unverified:
        client.set_missing_host_key_policy(RangePolicy())
    else:
        raise TrustError("transport:ssh_trust_required", "SSH requires a host key pin or provisioned known_hosts file")


def ca_context(path: str) -> ssl.SSLContext:
    """Use only the supplied CA bundle, with SAN identity checking and TLS >=1.2."""
    path = trust_file(path, "CA bundle")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.hostname_checks_common_name = False
    try:
        context.load_verify_locations(cafile=path)
        if context.cert_store_stats()["x509_ca"] == 0:
            raise ValueError
    except (ValueError, OSError, ssl.SSLError):
        raise TrustError("transport:invalid_ca", "CA bundle must contain usable CA certificates") from None
    return context


def harden_winrm_session(session, *, endpoint: str, ca_path: str, context: ssl.SSLContext, event):
    """Constrain the actual authenticated HTTP session; never preflight another socket."""
    from requests.adapters import HTTPAdapter
    from requests.exceptions import SSLError

    class TargetTLSAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["ssl_context"] = context
            return super().init_poolmanager(*args, **kwargs)

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            # Requests >=2.32 may otherwise supply its own default SSLContext.
            host, kwargs = super().build_connection_pool_key_attributes(request, ca_path, cert)
            kwargs["ssl_context"] = context
            return host, kwargs

        def send(self, request, **kwargs):
            if request.url != endpoint:
                raise TrustError("transport:redirect_refused", "WinRM requests must use the configured HTTPS endpoint")
            kwargs["verify"] = ca_path
            kwargs["proxies"] = {}
            try:
                response = super().send(request, **kwargs)
            except SSLError:
                event("transport:tls_failed", "WinRM TLS trust or handshake failed", "high")
                raise TrustError("transport:tls_failed", "WinRM TLS trust or handshake failed") from None
            if 300 <= response.status_code < 400:
                response.close()
                raise TrustError("transport:redirect_refused", "WinRM redirects are refused")
            return response

    session.trust_env = False
    session.proxies = {}
    session.verify = ca_path
    adapter = TargetTLSAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
