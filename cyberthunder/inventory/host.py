"""Guided host declarations and local readiness; remote access remains an explicit action."""
from __future__ import annotations

import ipaddress
import re

from .deployment import runtime_context
from .targets import ScopeViolation, Target
from cyberthunder.transport.base import Transport

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
CREDENTIAL_REF = re.compile(r"[A-Za-z0-9_.-]{1,64}")
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
PAIRS = {"linux": "ssh", "windows": "winrm"}
FIELDS = {"id", "name", "asset_type", "transport", "address", "port", "username", "credential_ref", "sudo", "in_scope", "reason"}


def _text(value, field, limit=256):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field} must be nonempty text of at most {limit} characters without control characters")
    return value.strip()


def address(value):
    value = _text(value, "address", 253)
    if "%" in value or "://" in value or any(c in value for c in "/\\@[]"):
        raise ValueError("address must be one IP literal or hostname, without URL, port or zone id")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError("invalid IP address") from None
        if not all(HOST_LABEL.fullmatch(label) for label in value.rstrip(".").split(".")):
            raise ValueError("invalid hostname") from None
        return value.lower()  # a trailing dot explicitly disables DNS search-domain expansion


def host_registration(data):
    if not isinstance(data, dict) or set(data) - FIELDS:
        raise ValueError("unsupported host registration fields; use named credential references, never inline secrets")
    tid = _text(data.get("id"), "id", 64)
    if not ID.fullmatch(tid):
        raise ValueError("id must be a plain name using letters, digits, '.', '_' or '-'")
    name = _text(data.get("name"), "name")
    asset_type, transport = data.get("asset_type"), data.get("transport")
    if not isinstance(asset_type, str) or PAIRS.get(asset_type) != transport:
        raise ValueError("declare the actual intended host OS: linux requires ssh; windows requires winrm")
    username = _text(data.get("username"), "username")
    credential = _text(data.get("credential_ref"), "credential_ref", 64)
    if not CREDENTIAL_REF.fullmatch(credential):
        raise ValueError("credential_ref must be a named CT_CRED reference using letters, digits, '.', '_' or '-'")
    if type(data.get("in_scope")) is not bool or type(data.get("sudo", False)) is not bool:
        raise ValueError("in_scope must be chosen explicitly as true or false; sudo must be a boolean")
    port = data.get("port")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("port must be an integer from 1 through 65535")
    reason = _text(data.get("reason"), "reason", 1000)
    return Target(id=tid, name=name, asset_type=asset_type, transport=transport, address=address(data.get("address")),
                  port=port or (22 if transport == "ssh" else 5986), username=username, credential_ref=credential,
                  sudo=data.get("sudo", False), in_scope=data["in_scope"], simulated=False,
                  tags=["deployment-host"]), reason


def persisted_target(inventory, target_id, *, require_scope=False):
    """Fresh persisted scope for explicit connection tests; no cached proof after file loss."""
    if inventory.path is None:  # explicitly in-memory test inventory
        target = inventory.get(target_id)
    else:
        rows = inventory.read_persisted(inventory.path)
        if target_id not in rows:
            raise KeyError(target_id)
        target = Target.from_dict(rows[target_id])
        cached = inventory._targets.get(target_id)
        if cached is not None and cached.in_scope is False:
            target.in_scope = False  # local revocations remain conservative until saved/refreshed
    if require_scope and target.in_scope is not True:
        raise ScopeViolation(f"target {target_id!r} is out of scope")
    return target


class HostConnectionTransport(Transport):
    """Recheck authorization for each Linux/Windows discovery operation, including lazy connects."""

    def __init__(self, transport, guard):
        self._transport, self._guard = transport, guard
        self.kind = transport.kind

    def run(self, command, **kwargs):
        self._guard()
        result = self._transport.run(command, **kwargs)
        self._guard()
        return result

    def read_file(self, path):
        self._guard()
        result = self._transport.read_file(path)
        self._guard()
        return result

    def write_file(self, path, data, **kwargs):
        raise ScopeViolation("host connection testing does not permit file writes")


def readiness(ctx, target):
    runtime = runtime_context()
    checks = []
    def check(code, okay, message):
        checks.append({"code": code, "status": "ok" if okay else "blocked", "message": message})
    check("scope", target.in_scope is True, "An explicit in-scope inventory decision is required for connection testing.")
    check("kill_switch", not ctx.killswitch.is_engaged(), "The kill switch must be released before connection testing.")
    check("os_transport", PAIRS.get(target.asset_type) == target.transport and not target.simulated,
          "Host registration uses the declared actual OS: Linux over SSH or Windows over WinRM.")
    try:
        normalized = address(target.address)
        valid_address = True
    except ValueError:
        normalized, valid_address = None, False
    check("address", valid_address, "Supply one reachable authorized host IP or hostname; no DNS lookup was performed.")
    check("username", isinstance(target.username, str) and bool(target.username.strip()), "An explicit account is required.")
    check("credential_ref", isinstance(target.credential_ref, str) and bool(CREDENTIAL_REF.fullmatch(target.credential_ref)),
          "Use a named credential reference; its value and permissions were not checked.")
    check("port", target.port is None or (type(target.port) is int and 1 <= target.port <= 65535), "Port must be 1 through 65535.")
    checks.append({"code": "connection", "status": "unknown", "message": "Connectivity, credentials, effective privileges and detected OS require an explicit connection test."})
    warnings = []
    if target.transport == "local":
        warnings.append(runtime["local_transport"]["description"])
    try:
        loopback = (normalized and normalized.rstrip(".") == "localhost") or (normalized and ipaddress.ip_address(normalized).is_loopback)
    except ValueError:
        loopback = False
    if loopback:
        warnings.append("Loopback addresses refer to this runtime's network environment; they do not identify a physical host.")
    return {"target_id": target.id, "ready_for_connection_test": not any(c["status"] == "blocked" for c in checks),
            "checked": "declarations_only", "connection_test_route": f"/api/v1/targets/{target.id}/discover",
            "checks": checks, "warnings": warnings, "runtime": runtime}
