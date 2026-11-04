"""Active Directory as a discovery source: the computer objects the domain already knows about.

The command is a fixed, read-only query run over the WinRM transport of a Windows inventory target that
has options.directory_source set (normally a domain controller or a management server with RSAT). It
lists every computer account with its OS and last logon; nothing is written to the directory.

Each computer with an IPv4 address becomes a windows asset. Servers and workstations are told apart by
the OperatingSystem string; disabled computer accounts are kept and flagged, because a disabled account
that still answers on the network is worth a look.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone

from ..models import DiscoveredAsset, asset_id_for

AD_COMMAND = ("Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,IPv4Address,"
              "LastLogonDate,Enabled,DNSHostName | Select-Object Name,DNSHostName,IPv4Address,OperatingSystem,"
              "OperatingSystemVersion,LastLogonDate,Enabled | ConvertTo-Json -Depth 3")

_MS_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def _date(value) -> str | None:
    """LastLogonDate arrives as /Date(ms)/ from Windows PowerShell 5.1 and as ISO 8601 from PowerShell 7."""
    if value in (None, ""):
        return None
    if isinstance(value, dict):          # -Depth 3 can expand a DateTime into {value, DateTime}
        value = value.get("value") or value.get("DateTime")
    m = _MS_DATE.search(str(value))
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def role_from_os(os_name: str | None) -> str:
    """server | workstation | unknown, from the AD OperatingSystem attribute."""
    t = (os_name or "").lower()
    if "server" in t:
        return "server"
    if "windows" in t:
        return "workstation"
    return "unknown"


def parse_ad_computers(text: str) -> list[DiscoveredAsset]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    out: list[DiscoveredAsset] = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("Name"):
            continue
        name, dns = str(r["Name"]), r.get("DNSHostName") or None
        os_name, os_ver = r.get("OperatingSystem") or None, r.get("OperatingSystemVersion") or None
        enabled = r.get("Enabled")
        enabled = True if enabled is None else bool(enabled)
        role = role_from_os(os_name)
        address = _ip(r.get("IPv4Address"))
        a = DiscoveredAsset(address=address, hostname=dns or name, os_guess=os_name, sources=["active_directory"])
        if not address:
            a.id = asset_id_for(None, f"ad:{(dns or name).lower()}")
        a.facts.update({k: v for k, v in {
            "ad_name": name, "dns_hostname": dns, "os_name": os_name, "os_version": os_ver,
            "last_logon": _date(r.get("LastLogonDate")), "ad_enabled": enabled, "windows_role": role,
        }.items() if v is not None})
        if os_name and "windows" in os_name.lower():
            a.facts["platform_type"] = "windows"
        a.evidence.append(f"active directory: computer {name} OperatingSystem '{os_name or '?'}'"
                          f"{(' ' + os_ver) if os_ver else ''} ({role})")
        notes = [role] if role != "unknown" else []
        if not enabled:
            a.evidence.append(f"active directory: computer account {name} is disabled")
            notes.append("disabled computer account")
        a.notes = "; ".join(notes)
        out.append(a)
    return out
