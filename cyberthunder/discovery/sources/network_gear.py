"""Network gear as a discovery source: what the switches already know.

A managed Cisco switch sees every neighbor that speaks CDP or LLDP and every MAC on its ports. Reading
that is read-only and catches devices that drop ping. The commands are fixed show commands run over
the switch's own inventory transport; their output is parsed here.

  show cdp neighbors detail     device id, platform, capabilities, IP, software version
  show lldp neighbors detail    system name/description, chassis id, capabilities, management IP
  show ip arp                   IP to MAC bindings on routed interfaces / SVIs
  show mac address-table        MAC to port/VLAN (joined with the ARP table by MAC)
"""
from __future__ import annotations

import ipaddress
import re

from ..models import DiscoveredAsset, normalize_mac
from ..oui import vendor_for

GEAR_COMMANDS = {
    "cdp": "show cdp neighbors detail",
    "lldp": "show lldp neighbors detail",
    "arp": "show ip arp",
    "mac": "show mac address-table",
}

_SEP = re.compile(r"(?m)^-{5,}\s*$")


def _ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def type_from_platform(*texts: str | None) -> str | None:
    """Asset type implied by a CDP platform / LLDP system description."""
    t = " ".join(x for x in texts if x).lower()
    if not t:
        return None
    if "cisco" in t and any(k in t for k in ("ios", "catalyst", "nexus", "c9", "ws-c", "isr", "switch", "router")):
        return "cisco_ios"
    if "windows" in t:
        return "windows"
    if any(k in t for k in ("linux", "rocky", "red hat", "ubuntu", "debian", "alma")):
        return "linux"
    return None


def _field(block: str, pattern: str) -> str | None:
    m = re.search(pattern, block, re.I | re.M)
    return m.group(1).strip() if m else None


def parse_cdp_detail(text: str) -> list[DiscoveredAsset]:
    out = []
    for block in _SEP.split(text or ""):
        device = _field(block, r"^Device ID:\s*(\S+)")
        if not device:
            continue
        ips = re.findall(r"IP(?:v4)? address:\s*(\S+)", block, re.I)
        address = next((ip for ip in (_ip(x) for x in ips) if ip), None)
        platform = _field(block, r"^Platform:\s*([^,\n]+)")
        caps = (_field(block, r"Capabilities:\s*(.+)$") or "").split()
        version = None
        m = re.search(r"^Version\s*:\s*\n(.+)$", block, re.I | re.M)
        if m:
            version = m.group(1).strip()
        a = DiscoveredAsset(address=address, hostname=device, sources=["cdp"])
        a.facts.update({k: v for k, v in {
            "cdp_device_id": device, "platform": platform, "capabilities": caps,
            "local_interface": _field(block, r"^Interface:\s*([^,\n]+)"),
            "remote_port": _field(block, r"Port ID \(outgoing port\):\s*(\S+)"),
            "software": version, "native_vlan": _field(block, r"^Native VLAN:\s*(\S+)"),
        }.items() if v})
        a.evidence.append(f"cdp: neighbor {device} platform '{platform or '?'}' capabilities {' '.join(caps) or '-'}")
        guess = type_from_platform(platform, version)
        if guess:
            a.facts["platform_type"] = guess
        out.append(a)
    return out


def parse_lldp_detail(text: str) -> list[DiscoveredAsset]:
    out = []
    for block in _SEP.split(text or ""):
        name = _field(block, r"^System Name:\s*(\S+)")
        chassis = _field(block, r"^Chassis id:\s*(\S+)")
        if not name and not chassis:
            continue
        desc = None
        m = re.search(r"^System Description:\s*\n(.+?)(?:\n\s*\n|\Z)", block, re.I | re.M | re.S)
        if m:
            desc = " ".join(m.group(1).split())
        mgmt = re.findall(r"^\s*IP(?:v4)?:\s*(\S+)", block, re.I | re.M)
        address = next((ip for ip in (_ip(x) for x in mgmt) if ip), None)
        mac = normalize_mac(chassis)
        a = DiscoveredAsset(address=address, hostname=name, mac=mac, vendor=vendor_for(mac), sources=["lldp"])
        a.facts.update({k: v for k, v in {
            "lldp_system_name": name, "system_description": desc,
            "local_interface": _field(block, r"^Local Intf:\s*(\S+)"),
            "remote_port": _field(block, r"^Port id:\s*(\S+)"),
            "capabilities": (_field(block, r"^System Capabilities:\s*(\S+)") or "").split(","),
            "enabled_capabilities": (_field(block, r"^Enabled Capabilities:\s*(\S+)") or "").split(","),
        }.items() if v and v != [""]})
        a.evidence.append(f"lldp: neighbor {name or chassis} '{(desc or '?')[:80]}'")
        guess = type_from_platform(desc)
        if guess:
            a.facts["platform_type"] = guess
        out.append(a)
    return out


def parse_show_ip_arp(text: str) -> list[dict]:
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].lower() == "internet":
            ip, mac = _ip(parts[1]), normalize_mac(parts[3])
            if ip and mac:
                rows.append({"address": ip, "mac": mac, "age": parts[2],
                             "interface": parts[5] if len(parts) > 5 else None, "own": parts[2] == "-"})
    return rows


def parse_mac_table(text: str) -> list[dict]:
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or not (parts[0].isdigit()):
            continue
        mac = normalize_mac(parts[1])
        if not mac or int(mac[:2], 16) & 0x01 or parts[-1].upper() == "CPU":
            continue
        rows.append({"vlan": int(parts[0]), "mac": mac, "type": parts[2].lower(), "port": parts[-1]})
    return rows


def assets_from_gear(outputs: dict[str, str], *, seen_by: str | None = None) -> list[DiscoveredAsset]:
    """Combine the four show outputs (any may be missing) into assets keyed by address."""
    by_addr: dict[str, DiscoveredAsset] = {}

    def add(a: DiscoveredAsset) -> None:
        if not a.address:
            return
        if seen_by:
            a.facts.setdefault("seen_by", seen_by)
        cur = by_addr.get(a.address)
        by_addr[a.address] = cur.merge(a) if cur else a

    for a in parse_cdp_detail(outputs.get("cdp", "")):
        add(a)
    for a in parse_lldp_detail(outputs.get("lldp", "")):
        add(a)
    ports = {r["mac"]: r for r in parse_mac_table(outputs.get("mac", ""))}
    for r in parse_show_ip_arp(outputs.get("arp", "")):
        if r["own"]:
            continue    # the switch's own SVI
        a = DiscoveredAsset(address=r["address"], mac=r["mac"], vendor=vendor_for(r["mac"]), sources=["switch_arp"])
        a.evidence.append(f"switch arp: {r['address']} at {r['mac']} on {r.get('interface') or '?'}")
        p = ports.get(r["mac"])
        if p:
            a.facts.update(switch_port=p["port"], vlan=p["vlan"])
            a.evidence.append(f"switch mac table: {r['mac']} on port {p['port']} vlan {p['vlan']}")
        add(a)
    return list(by_addr.values())
