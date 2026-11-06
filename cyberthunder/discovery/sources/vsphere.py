"""Explicit vCenter/ESXi inventory source, separate from Workstation vmrun discovery."""
from __future__ import annotations

import hashlib
import ipaddress

from ..models import DiscoveredAsset
from ..oui import tag_virtual
from .vsphere_access import SourceAccess
from .vsphere_client import InventoryClient


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
    return SourceAccess(ctx, target, scopes, actor, scope_guard)


def collect(ctx, target, scopes, actor, scope_guard, *, access=None):
    """Collect using the same requester/account grant retained for publication."""
    guard = access if access is not None else source_guard(ctx, target, scopes, actor, scope_guard)
    if not guard.matches(ctx, target, scopes, actor):
        raise PermissionError("vsphere:source_request_changed")
    guard()
    endpoint, target, scopes = guard.endpoint, guard.target, guard.scopes
    if guard.evidence is not None:
        ctx.audit.append("credential.use", actor,
                         {**guard.evidence, "source": "vsphere", "endpoint": endpoint.url,
                          "ca_sha256": guard.ca_sha256}, subject=target.id)
    ctx.audit.append("discovery.vsphere.start", actor,
                     {"target": target.id, "endpoint": endpoint.url, "auth_mode": guard.mode,
                      "tls_trust": target.options["vsphere"]["tls_trust"], "read_only": True}, subject=target.id)
    guard()
    client = InventoryClient(endpoint, guard, context=guard.context)
    instance, api_type, rows = client.inventory(guard.credentials)
    guard()
    assets = observations(instance, api_type, rows, endpoint=endpoint.url, reported_by=target.id, scopes=scopes)
    guard()
    ctx.audit.append("discovery.vsphere.finish", actor,
                     {"target": target.id, "objects_received": len(rows), "candidates": len(assets),
                      "auto_accepted": 0}, subject=target.id)
    guard()
    return assets
