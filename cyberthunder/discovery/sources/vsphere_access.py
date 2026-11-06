"""One immutable vSphere account selection, rechecked through collection and publication."""
from __future__ import annotations

import copy
import hashlib
import os
import re
import stat

from cyberthunder.control.principal import current_operation, current_principal
from cyberthunder.inventory.host import persisted_target
from cyberthunder.security.credentials import bind_target

from .vsphere_client import Endpoint, VsphereError, text

OPTIONS = {"endpoint", "tls_trust", "ca_file", "username", "credential_ref"}
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
MAX_CA_BYTES = 1024 * 1024


def _configuration(target):
    return copy.deepcopy({k: v for k, v in target.to_dict().items()
                          if k not in {"last_scan", "notes", "added_at"}})


def _ca_bytes(path):
    """Read only bounded local regular CA material; no credential or path in errors."""
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or getattr(before, "st_reparse_tag", 0):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_CA_BYTES
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise ValueError
            raw = stream.read(MAX_CA_BYTES + 1)
        if not raw or len(raw) > MAX_CA_BYTES:
            raise ValueError
        return raw
    except (OSError, ValueError):
        raise VsphereError("vsphere:invalid_tls_trust") from None


class SourceAccess:
    def __init__(self, ctx, target, scopes, actor, scope_guard):
        self.ctx, self.target, self.scopes = ctx, copy.deepcopy(target), copy.deepcopy(scopes)
        self.actor, self.scope_guard = actor, scope_guard
        self.mode = getattr(ctx.settings, "auth_mode", "dev")
        self.configuration = _configuration(target)
        self.principal = current_principal() if self.mode != "dev" else None
        self.binding = self.evidence = self.ca_sha256 = None
        self.endpoint = None
        self._base_guard()
        if self.mode != "dev":
            # A legacy SSH inventory entry cannot silently acquire HTTPS access.
            if target.transport != "vsphere":
                raise VsphereError("vsphere:verified_binding_unavailable")
            self.binding = ctx.access.credential(self.principal, "discover", self.target)
            selected = bind_target(self.target, self.binding)
            self.evidence = self.binding.evidence()
            self.username, self.ref = selected.username, selected.credential_ref
        options = (self.target.options or {}).get("vsphere")
        if not isinstance(options, dict) or options.keys() - OPTIONS:
            raise VsphereError("vsphere:invalid_source_options")
        self.endpoint = Endpoint.parse(options.get("endpoint"), self.target.address,
                                       tls_trust=options.get("tls_trust"), ca_file=options.get("ca_file"))
        if self.mode != "dev" and target.port not in {None, self.endpoint.port}:
            raise VsphereError("vsphere:conflicting_endpoint_port")
        if not any(s.contains(self.endpoint.address) for s in self.scopes):
            raise PermissionError("vsphere:endpoint_outside_sweep_scope")
        if self.mode == "dev":
            self.username, self.ref = options.get("username"), options.get("credential_ref")
        text(self.username, 256)
        if not isinstance(self.ref, str) or not REF.fullmatch(self.ref):
            raise VsphereError("vsphere:explicit_credential_required")
        ca = _ca_bytes(self.endpoint.ca_file) if self.endpoint.ca_file else None
        self.ca_sha256 = hashlib.sha256(ca).hexdigest() if ca is not None else None
        self.context = self.endpoint.tls_context(ca_data=ca)
        self()

    def _base_guard(self):
        if getattr(self.ctx.settings, "auth_mode", "dev") != self.mode:
            raise VsphereError("vsphere:authentication_mode_changed")
        if self.mode != "dev":
            if current_operation() != "discover":
                raise PermissionError("vsphere:discover_operation_required")
            if self.principal is None or current_principal() != self.principal:
                raise PermissionError("vsphere:authenticated_session_changed")
            self.ctx.authorize("discover", actor=self.actor, target=self.target)
        self.ctx.killswitch.guard("discovery.vsphere", self.actor)
        try:
            current = persisted_target(self.ctx.inventory, self.target.id, require_scope=True)
        except (KeyError, PermissionError, OSError, ValueError):
            raise PermissionError("vsphere:target_scope_revoked") from None
        if _configuration(current) != self.configuration:
            raise PermissionError("vsphere:target_configuration_changed")
        for scope in self.scopes:
            self.scope_guard(scope)
        return current

    def __call__(self):
        current = self._base_guard()
        if self.binding is not None:
            fresh = self.ctx.access.credential(self.principal, "discover", current)
            if fresh.evidence() != self.evidence:
                raise PermissionError("vsphere:account_binding_changed")
        if self.ca_sha256 is not None:
            if hashlib.sha256(_ca_bytes(self.endpoint.ca_file)).hexdigest() != self.ca_sha256:
                raise PermissionError("vsphere:tls_trust_changed")

    def credentials(self):
        self()
        password = os.environ.get("CT_CRED_" + self.ref)
        if not password:
            raise VsphereError("vsphere:credential_unavailable")
        text(password, 16384)
        self()
        return self.username, password

    def matches(self, ctx, target, scopes, actor):
        return (ctx is self.ctx and actor == self.actor and _configuration(target) == self.configuration
                and [s.to_dict() for s in scopes] == [s.to_dict() for s in self.scopes])
