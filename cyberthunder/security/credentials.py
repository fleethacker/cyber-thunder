"""Immutable account selection and detached target copies; never resolve secrets."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Mapping


class CredentialError(PermissionError):
    """An account binding cannot safely be used for this target."""


AUTH_OPTIONS = frozenset({"key_file", "kubeconfig", "context", "transport"})
_REF = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Includes aliases which must not survive from inventory or a previously bound copy.
# Transport trust and collection options are independent of account selection.
_INVENTORY_AUTH = AUTH_OPTIONS | frozenset({
    "username", "user", "credential_ref", "sudo", "password", "password_env",
    "password_ref", "passphrase", "private_key", "private_key_file", "key_filename",
    "ssh_key", "ssh_key_file", "identity_file", "pkey", "token", "token_file",
    "bearer_token", "access_token", "client_key", "client_cert", "client_certificate",
    "credentials", "auth", "auth_type", "auth_provider", "exec", "exec_provider",
    "allow_agent", "look_for_keys", "interactive_auth", "ssh_agent", "agent_forwarding",
    "forward_agent", "kerberos_delegation", "kerberos_ccache", "ccache", "kube_context",
    "kubeconfig_path", "credential_bound", "credential_source", "env", "environment",
    "kubectl",  # An inventory-controlled executable can bypass the selected kubeconfig.
})


def _text(value, maximum=512):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError("invalid binding text")
    return value


def _absolute_path(value):
    value = _text(value, 2048)
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        raise ValueError("credential path must be absolute")
    # Shell/environment expansion and device paths are not part of the contract.
    if any(c in value for c in ("\x00", "$", "%", "*", "?")) or value.startswith("\\\\.\\"):
        raise ValueError("invalid credential path")
    return value


def _reference(value):
    value = _text(value, 2048)
    if _REF.fullmatch(value) and value not in {".", ".."}:
        return value
    return _absolute_path(value)


def target_identity(target) -> tuple:
    """Non-secret endpoint stamp, also checked when applying a selected binding."""
    tid = _text(target.id)
    environment = _text(getattr(target, "environment", "default"))
    asset_type = _text(target.asset_type)
    transport = _text(target.transport)
    address = target.address
    if address is not None:
        _text(address)
    port = target.port
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("invalid endpoint port")
    if type(target.simulated) is not bool or type(target.in_scope) is not bool:
        raise ValueError("invalid endpoint flags")
    identity = tid, environment, asset_type, transport, address, port, target.simulated, target.in_scope
    if transport == "vsphere":
        generation = _text(target.authorization_id)
        if not re.fullmatch(r"[a-f0-9]{32,64}", generation):
            raise ValueError("invalid target authorization identity")
        options = target.options
        source = options.get("vsphere") if isinstance(options, dict) else None
        if (options.get("hypervisor") != "vsphere" or not isinstance(source, dict)
                or source.keys() - {"endpoint", "tls_trust", "ca_file", "username", "credential_ref"}):
            raise ValueError("invalid vSphere source declaration")
        # Pure selection: no file, network or secret lookup. The source validates
        # the URL and CA material before use. Pin the exact declaration and owner.
        trust = {key: source.get(key) for key in ("endpoint", "tls_trust", "ca_file")}
        for key, value in trust.items():
            if value is not None:
                _text(value, 2048 if key == "ca_file" else 512)
        digest = hashlib.sha256(json.dumps(trust, sort_keys=True).encode()).hexdigest()
        return (*identity, generation, digest)
    return identity


@dataclass(frozen=True)
class BindingProvenance:
    issuer: str
    subject: str
    action: str
    target: tuple
    policy_sha256: str
    selectors: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True)
class CredentialBinding:
    username: str | None
    credential_ref: str | None
    sudo: bool
    options: Mapping[str, str] = field(default_factory=dict)
    provenance: BindingProvenance | None = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        if self.username is not None:
            _text(self.username)
        if self.credential_ref is not None:
            _reference(self.credential_ref)
        if type(self.sudo) is not bool or not isinstance(self.options, Mapping):
            raise ValueError("invalid credential binding")
        options = dict(self.options)
        if options.keys() - AUTH_OPTIONS:
            raise ValueError("unknown credential option")
        for key, value in options.items():
            if key in {"key_file", "kubeconfig"}:
                _absolute_path(value)
            else:
                _text(value)
        if "transport" in options and options["transport"] not in {"ntlm", "vsphere"}:
            raise ValueError("unsupported account transport")
        if "kubeconfig" in options:
            if (set(options) != {"kubeconfig", "context"} or self.username is not None
                    or self.credential_ref is not None or self.sudo):
                raise ValueError("conflicting kubeconfig credential fields")
        elif "key_file" in options:
            if set(options) != {"key_file"} or self.username is None or self.credential_ref is not None:
                raise ValueError("conflicting key credential fields")
        elif self.credential_ref is not None:
            if self.username is None or options.keys() - {"transport"}:
                raise ValueError("account and credential source must be explicit")
            if "transport" in options and (not _REF.fullmatch(self.credential_ref) or self.sudo):
                raise ValueError("invalid account transport credential fields")
        elif self.username is not None or self.sudo or options:
            raise ValueError("missing credential source")
        object.__setattr__(self, "options", MappingProxyType(options))

    def evidence(self) -> dict:
        """Audit references and identity, never credential contents or filesystem paths."""
        p = self.provenance
        source = _source(self)
        reference = json.dumps([self.credential_ref, dict(self.options)], sort_keys=True,
                               separators=(",", ":")).encode()
        result = {"username": self.username, "sudo": self.sudo, "credential_source": source,
                  "credential_fingerprint": hashlib.sha256(reference).hexdigest()}
        if p is not None:
            tid, environment, asset_type, transport, address, port, simulated, in_scope = p.target[:8]
            result.update({"issuer": p.issuer, "subject": p.subject, "action": p.action,
                           "policy_sha256": p.policy_sha256,
                           "target": {"id": tid, "environment": environment, "asset_type": asset_type,
                                      "transport": transport, "address": address, "port": port,
                                      "simulated": simulated, "in_scope": in_scope},
                           "selectors": [{"issuer": issuer, kind: value}
                                         for issuer, kind, value in p.selectors]})
            if transport == "vsphere":
                result["target"].update(authorization_id=p.target[8], source_sha256=p.target[9])
        return result


def _source(binding):
    if "kubeconfig" in binding.options:
        return "kubeconfig"
    if "key_file" in binding.options or (binding.credential_ref is not None
                                         and not _REF.fullmatch(binding.credential_ref)):
        return "key_file"
    return "environment" if binding.credential_ref is not None else "none"


def bind_target(target, binding: CredentialBinding):
    """Apply a freshly authorized binding without touching the inventory or secrets.

    This helper requires provenance from AccessPolicy.credential; it does not
    establish identity, enforce application roles, or replace a transport guard.
    """
    try:
        return _bind_target(target, binding)
    except (AttributeError, TypeError, ValueError):
        raise CredentialError("credential binding is invalid for this target") from None


def _bind_target(target, binding):
    if not isinstance(binding, CredentialBinding) or binding.provenance is None:
        raise CredentialError("a policy-selected credential binding is required")
    identity = target_identity(target)
    if identity != binding.provenance.target or not target.in_scope:
        raise CredentialError("credential binding does not match the current target")
    kind = target.transport
    if kind not in {"ssh", "winrm", "kubeconfig", "simulated", "vsphere"}:
        raise CredentialError("this transport has no delegated account design")
    # The simulated flag on a real transport never disables account validation.
    options = dict(binding.options)
    ref = binding.credential_ref
    if kind == "ssh":
        if binding.username is None or options.keys() - {"key_file"}:
            raise CredentialError("SSH requires an explicit account and SSH-only options")
        if (ref is None) == ("key_file" not in options):
            raise CredentialError("SSH requires exactly one credential source")
        if ref is not None and not _REF.fullmatch(ref):
            options["key_file"], ref = ref, None
    elif kind == "winrm":
        if (binding.username is None or ref is None or not _REF.fullmatch(ref)
                or options.keys() - {"transport"} or options.get("transport", "ntlm") != "ntlm" or binding.sudo):
            raise CredentialError("WinRM requires an explicit environment credential and account")
        options["transport"] = "ntlm"
    elif kind == "vsphere":
        if (binding.provenance.action != "discover" or binding.username is None or ref is None
                or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", ref)
                or options != {"transport": "vsphere"} or binding.sudo or target.simulated):
            raise CredentialError("vSphere requires an explicit discover-only environment account")
    elif kind == "kubeconfig":
        if (set(options) != {"kubeconfig", "context"} or ref is not None
                or binding.username is not None or binding.sudo):
            raise CredentialError("kubeconfig requires only an explicit file and context")
    elif binding.username is not None or ref is not None or binding.sudo or options:
        raise CredentialError("simulated transports do not accept OS credentials")
    if not isinstance(target.options, dict):
        raise CredentialError("invalid inventory options")
    operational = copy.deepcopy({k: v for k, v in target.options.items()
                                 if isinstance(k, str) and k.casefold() not in _INVENTORY_AUTH})
    operational.update(options)
    if kind == "vsphere":
        operational["vsphere"] = {key: value for key, value in operational["vsphere"].items()
                                  if key in {"endpoint", "tls_trust", "ca_file"}}
    operational.update(credential_bound=True, credential_source=_source(binding),
                       allow_agent=False, look_for_keys=False, interactive_auth=False)
    result = replace(target, username=binding.username, credential_ref=ref,
                     sudo=binding.sudo, options=operational)
    # Before Target.environment lands, a caller may carry the attribute separately.
    if hasattr(target, "environment") and not hasattr(result, "environment"):
        result.environment = target.environment
    return result
