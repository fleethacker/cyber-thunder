"""Explicit vCenter/ESXi inventory source, separate from Workstation vmrun discovery."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import os
import re

from cyberthunder.control.principal import current_operation
from cyberthunder.inventory.host import persisted_target

from ..models import DiscoveredAsset
from ..oui import tag_virtual
from .vsphere_client import Endpoint, InventoryClient, VsphereError, text

_OPTIONS = {"endpoint", "tls_trust", "ca_file", "username", "credential_ref"}
_REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")


def is_observation(asset):
    return "vsphere" in asset.sources and bool(asset.facts.get("vsphere_identity"))


def _ip(value):
    try:
        if not isinstance(value, str) or "%" in value:
            return None
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
            return None
        return str(ip)
    except ValueError:
        return None


def observations(instance, api_type, rows, *, endpoint, reported_by, scopes):
    """Stable endpoint/object IDs, no name-based joins, and no inference of guest liveness."""
    out = []
    identity_prefix = f"{endpoint}\0{instance}\0"
    for row in rows:
        kind, ref, p = row["kind"], row["ref"], row["properties"]
        identity = identity_prefix + kind + "\0" + ref
        aid = "vsphere-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        name = p.get("name") or ref
        raw_ips = p.get("config.network.vnic", []) if kind == "HostSystem" else [p.get("guest.ipAddress")]
        ips = sorted({ip for value in raw_ips if (ip := _ip(value))})
        allowed = [ip for ip in ips if any(s.contains(ip) for s in scopes)]
        if ips and not allowed:
            continue
        state = p.get("runtime.powerState") or "unknown"
        # Powered-off and missing-IP VMs remain metadata-only observations. Even a
        # powered-on guest IP is reported inventory data, never a probe result.
        address = allowed[0] if allowed and (kind == "HostSystem" or state == "poweredOn") else None
        a = DiscoveredAsset(id=aid, address=address, hostname=name, sources=["vsphere"],
                            os_guess=p.get("config.guestFullName") if kind == "VirtualMachine" else None)
        a.facts = {"vsphere_identity": aid, "vsphere_kind": kind, "vsphere_ref": ref,
                   "vsphere_endpoint": endpoint, "vsphere_api_type": api_type,
                   "reported_by": reported_by, "power_state": state, "reported_addresses": allowed,
                   "address_basis": "inventory report; reachability untested"}
        if kind == "VirtualMachine":
            a.facts.update(vm_name=name, hypervisor_host=p.get("runtime.host"),
                           instance_uuid=p.get("config.instanceUuid"), bios_uuid=p.get("config.uuid"))
            if state == "poweredOff":
                a.facts["offline"] = True
            tag_virtual(a, "vmware")
            a.evidence.append(f"vSphere inventory: VM {ref}; power state {state}; "
                              f"host reference {p.get('runtime.host') or 'not reported'}; guest reachability untested")
        else:
            a.facts.update(hypervisor="esxi", hardware_uuid=p.get("hardware.systemInfo.uuid"),
                           product=p.get("summary.config.product.fullName"),
                           connection_state=p.get("runtime.connectionState") or "unknown")
            a.evidence.append(f"vSphere inventory: ESXi host {ref}; power state {state}; "
                              "inventory connection state is not an active reachability test")
        if not address:
            a.notes += ("; " if a.notes else "") + "No current scoped address; metadata only"
        out.append(a)
    # Clones and independent hosts can report the same IP. Never flatten them or
    # attach either one to an inventory target solely through that ambiguous IP.
    owners = {}
    for a in out:
        for ip in a.facts["reported_addresses"]:
            owners.setdefault(ip, set()).add(a.id)
    for a in out:
        conflicts = [ip for ip in a.facts["reported_addresses"] if len(owners[ip]) > 1]
        if conflicts:
            a.address = None
            a.facts["address_conflicts"] = conflicts
            a.notes += ("; " if a.notes else "") + "Shared reported address; resolve identity before acceptance"
    return out


def source_guard(ctx, target, scopes, actor, scope_guard):
    """Capture the source grant for both requests and later candidate publication."""
    snapshot = copy.deepcopy({k: v for k, v in target.to_dict().items()
                              if k not in {"last_scan", "notes", "added_at"}})

    def guard():
        if getattr(ctx.settings, "auth_mode", "dev") != "dev":
            if current_operation() != "discover":
                raise PermissionError("vsphere:discover_operation_required")
            ctx.authorize("discover", actor=actor, target=target)
            # Inventory credentials and SSH grants cannot authorize HTTPS API access.
            raise VsphereError("vsphere:verified_binding_unavailable")
        ctx.killswitch.guard("discovery.vsphere", actor)
        try:
            current = persisted_target(ctx.inventory, target.id, require_scope=True)
        except (KeyError, PermissionError, OSError, ValueError):
            raise PermissionError("vsphere:target_scope_revoked") from None
        now = {k: v for k, v in current.to_dict().items() if k not in {"last_scan", "notes", "added_at"}}
        if now != snapshot:
            raise PermissionError("vsphere:target_configuration_changed")
        for scope in scopes:
            scope_guard(scope)

    return guard


def collect(ctx, target, scopes, actor, scope_guard):
    """Use only an explicit dev account until vSphere has a delegated credential binding."""
    guard = source_guard(ctx, target, scopes, actor, scope_guard)
    guard()
    options = (target.options or {}).get("vsphere")
    if not isinstance(options, dict) or options.keys() - _OPTIONS:
        raise VsphereError("vsphere:invalid_source_options")
    endpoint = Endpoint.parse(options.get("endpoint"), target.address,
                              tls_trust=options.get("tls_trust"), ca_file=options.get("ca_file"))
    if not any(s.contains(endpoint.address) for s in scopes):
        raise PermissionError("vsphere:endpoint_outside_sweep_scope")
    username, ref = options.get("username"), options.get("credential_ref")
    text(username, 256)
    if not isinstance(ref, str) or not _REF.fullmatch(ref):
        raise VsphereError("vsphere:explicit_credential_required")

    def credentials():
        guard()
        password = os.environ.get("CT_CRED_" + ref)
        if not password:
            raise VsphereError("vsphere:credential_unavailable")
        return username, password

    ctx.audit.append("discovery.vsphere.start", actor,
                     {"target": target.id, "endpoint": endpoint.url, "auth_mode": "dev",
                      "tls_trust": options["tls_trust"], "read_only": True}, subject=target.id)
    client = InventoryClient(endpoint, guard)
    instance, api_type, rows = client.inventory(credentials)
    guard()
    assets = observations(instance, api_type, rows, endpoint=endpoint.url, reported_by=target.id, scopes=scopes)
    guard()
    ctx.audit.append("discovery.vsphere.finish", actor,
                     {"target": target.id, "objects_received": len(rows), "candidates": len(assets),
                      "auto_accepted": 0}, subject=target.id)
    return assets
