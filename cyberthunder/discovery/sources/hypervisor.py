"""Hypervisors as a discovery source: the VMs a host is running, including the ones that are switched off.

A powered-off VM never answers a sweep, yet it boots with whatever configuration it had the day it was
shut down. Listing VMs from the hypervisor puts them in front of the operator anyway.

  Hyper-V            fixed Get-VM query over the WinRM transport of a Windows inventory target with
                     options.hypervisor = "hyperv"
  VMware Workstation `vmrun list` on a target with options.hypervisor = "vmware", then each running VM's
                     .vmx file read with Transport.read_file (paths come from vmrun's own output and are
                     only ever read, never executed)

vCenter / ESXi inventory is a follow-up (it needs the vSphere API and a read-only role); see DISCOVERY.md.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Callable

from ..models import DiscoveredAsset, asset_id_for, normalize_mac
from ..oui import tag_virtual, vendor_for

HYPERV_COMMAND = ('Get-VM | Select-Object Name,State,Generation,'
                  '@{n="MAC";e={($_ | Get-VMNetworkAdapter).MacAddress -join ","}},'
                  '@{n="IP";e={($_ | Get-VMNetworkAdapter).IPAddresses -join ","}} | ConvertTo-Json')
VMRUN_LIST = "vmrun list"

# Microsoft.HyperV.PowerShell.VMState as Windows PowerShell 5.1 serializes it (PowerShell 7 writes names)
HYPERV_STATES = {2: "Running", 3: "Off", 6: "Saved", 9: "Paused", 10: "Starting", 32773: "Saving",
                 32776: "Pausing", 32777: "Resuming"}
ONLINE_STATES = {"running"}

# vmx guestOS identifiers to a readable OS name (enough for the classifier and applicability)
VMX_GUEST_OS = (
    (r"^rhel(\d+)", "Red Hat Enterprise Linux {0}"),
    (r"^rocky", "Rocky Linux"),
    (r"^centos", "CentOS Linux"),
    (r"^ubuntu", "Ubuntu Linux"),
    (r"^debian(\d+)?", "Debian Linux"),
    (r"^other\d*x?linux|^linux", "Linux"),
    (r"^windows2019srvnext|^windows2022srv", "Windows Server 2022"),
    (r"^windows2019srv", "Windows Server 2019"),
    (r"^windows11", "Windows 11"),
    (r"^windows9", "Windows 10"),
)


def _first_ipv4(value: str | None) -> str | None:
    for part in str(value or "").replace(";", ",").split(","):
        try:
            ip = ipaddress.ip_address(part.strip())
        except ValueError:
            continue
        if ip.version == 4:
            return str(ip)
    return None


def _id_for(mac: str | None, address: str | None, name: str) -> str:
    if mac or address:
        return asset_id_for(mac, address)
    return asset_id_for(None, f"vm:{name.lower()}")


def _state(value) -> str:
    if isinstance(value, int):
        return HYPERV_STATES.get(value, str(value))
    return str(value or "Unknown")


def parse_hyperv_vms(text: str, *, host: str | None = None) -> list[DiscoveredAsset]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    out = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("Name"):
            continue
        name = str(r["Name"])
        macs = [m for m in (normalize_mac(x) for x in str(r.get("MAC") or "").split(",")) if m]
        mac = macs[0] if macs else None
        state = _state(r.get("State"))
        online = state.lower() in ONLINE_STATES
        address = _first_ipv4(r.get("IP")) if online else None
        a = DiscoveredAsset(address=address, hostname=name, mac=mac, vendor=vendor_for(mac), sources=["hyperv"])
        a.id = _id_for(mac, address, name)
        a.facts.update({k: v for k, v in {
            "vm_name": name, "power_state": state, "vm_generation": r.get("Generation"),
            "hypervisor_host": host, "vm_macs": macs if len(macs) > 1 else None,
        }.items() if v is not None})
        a.evidence.append(f"hyper-v: VM {name} state {state}" + (f" on {host}" if host else ""))
        if not online:
            a.evidence.append(f"status offline: VM {name} is {state.lower()}; it cannot be swept until it is started")
            a.facts["offline"] = True
        tag_virtual(a, "hyperv")
        out.append(a)
    return out


def parse_vmrun_list(text: str) -> list[str]:
    """Paths of running VMs from `vmrun list`. Only lines naming a .vmx file are kept."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.lower().startswith("total running") and line.lower().endswith(".vmx"):
            out.append(line)
    return out


def parse_vmx(text: str) -> dict[str, str]:
    """key = "value" pairs of a .vmx file, keys lower-cased."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r'^\s*([A-Za-z0-9_.:]+)\s*=\s*"(.*)"\s*$', line)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out


def guest_os_name(guest_os: str | None) -> str | None:
    g = (guest_os or "").lower()
    if not g:
        return None
    for rx, name in VMX_GUEST_OS:
        m = re.match(rx, g)
        if m:
            return name.format(*(x for x in m.groups() if x)) if m.groups() else name
    return None


def asset_from_vmx(path: str, text: str, *, host: str | None = None) -> DiscoveredAsset:
    vmx = parse_vmx(text)
    name = vmx.get("displayname") or re.split(r"[\\/]", path)[-1].rsplit(".", 1)[0]
    mac = normalize_mac(vmx.get("ethernet0.generatedaddress") or vmx.get("ethernet0.address"))
    guest = vmx.get("guestos")
    a = DiscoveredAsset(hostname=name, mac=mac, vendor=vendor_for(mac), sources=["vmware"],
                        os_guess=guest_os_name(guest))
    a.id = _id_for(mac, None, name)
    a.facts.update({k: v for k, v in {"vm_name": name, "vmx_path": path, "guest_os": guest,
                                      "power_state": "Running", "hypervisor_host": host}.items() if v})
    a.evidence.append(f"vmware workstation: running VM {name} guestOS {guest or '?'}" + (f" on {host}" if host else ""))
    tag_virtual(a, "vmware")
    return a


def assets_from_vmware(list_text: str, read_file: Callable[[str], bytes], *,
                       host: str | None = None) -> tuple[list[DiscoveredAsset], list[str]]:
    """vmrun list output plus a reader for the .vmx files it names. Returns (assets, errors)."""
    assets, errors = [], []
    for path in parse_vmrun_list(list_text):
        try:
            text = read_file(path).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - one unreadable vmx must not hide the others
            errors.append(f"vmware: cannot read {path}: {e}")
            continue
        assets.append(asset_from_vmx(path, text, host=host))
    return assets, errors
