"""Passive sources: neighbor (ARP/NDP) caches, hosts files and SSH known_hosts.

Reading these sends no packets onto the enclave, so passive mode is safe to run anywhere a scanner
transport exists. Each parser returns DiscoveredAsset stubs (address, mac, vendor, maybe hostname).

Formats understood:
  ip neigh                     192.168.56.10 dev eth0 lladdr 52:54:00:12:34:10 REACHABLE
  arp -a / arp -an (Linux)     ? (192.168.56.2) at 70:10:5c:aa:bb:01 [ether] on eth0
  arp -a (Windows)             192.168.56.2          70-10-5c-aa-bb-01     dynamic
  Get-NetNeighbor | ConvertTo-Json   [{"IPAddress": ..., "LinkLayerAddress": ..., "State": ...}]
  /etc/hosts                   192.168.56.10  rocky9-app01 rocky9
  ~/.ssh/known_hosts           rocky9-app01,192.168.56.10 ssh-ed25519 AAAA...   (names/IPs only; keys ignored)
"""
from __future__ import annotations

import ipaddress
import json
import re

from ..models import DiscoveredAsset, normalize_mac
from ..oui import vendor_for

# Read-only commands, fixed. PowerShell form is used for a Windows scanner, the others for Linux.
NEIGHBOR_COMMANDS = {
    "powershell": ("Get-NetNeighbor -AddressFamily IPv4 | "
                   "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Json"),
    "posix": "ip neigh show",
    "posix_fallback": "arp -an",
}

_RE_ARP_LINUX = re.compile(r"^(?P<name>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>\S+)(?:\s+\[\w+\])?(?:\s+\w+)*\s+on\s+(?P<dev>\S+)")
_RE_ARP_WIN = re.compile(r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(?P<type>\w+)")
_BAD_NEIGH_STATES = {"FAILED", "INCOMPLETE"}
# Get-NetNeighbor State enum: 0 Unreachable, 1 Incomplete, 2 Probe, 3 Delay, 4 Stale, 5 Reachable, 6 Permanent
_BAD_PS_STATES = {0, 1, "Unreachable", "Incomplete"}


def _ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).split("%")[0].strip()))
    except ValueError:
        return None


def _unicast(mac: str | None) -> str | None:
    m = normalize_mac(mac)
    if not m or int(m[:2], 16) & 0x01:      # multicast / broadcast
        return None
    return m


def _stub(address: str, mac: str | None, source: str, **facts) -> DiscoveredAsset:
    a = DiscoveredAsset(address=address, mac=mac, vendor=vendor_for(mac), sources=[source])
    a.evidence.append(f"{source}: {address}" + (f" at {mac}" if mac else ""))
    a.facts.update({k: v for k, v in facts.items() if v})
    return a


def parse_ip_neigh(text: str) -> list[DiscoveredAsset]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or "dev" not in parts:
            continue
        def after(word: str) -> str | None:
            return parts[parts.index(word) + 1] if word in parts[:-1] else None
        ip, mac = _ip(parts[0]), _unicast(after("lladdr"))
        state = parts[-1].upper()
        if not ip or not mac or state in _BAD_NEIGH_STATES:
            continue
        out.append(_stub(ip, mac, "neighbors", interface=after("dev"), neighbor_state=state))
    return out


def parse_arp_linux(text: str) -> list[DiscoveredAsset]:
    out = []
    for line in text.splitlines():
        m = _RE_ARP_LINUX.match(line.strip())
        if not m:
            continue
        ip, mac = _ip(m.group("ip")), _unicast(m.group("mac"))
        if not ip or not mac:
            continue
        a = _stub(ip, mac, "neighbors", interface=m.group("dev"))
        if m.group("name") != "?":
            a.hostname = m.group("name")
        out.append(a)
    return out


def parse_arp_windows(text: str) -> list[DiscoveredAsset]:
    out = []
    interface = None
    for line in text.splitlines():
        if line.strip().lower().startswith("interface:"):
            interface = line.split(":", 1)[1].split("---")[0].strip()
            continue
        m = _RE_ARP_WIN.match(line)
        if not m:
            continue
        ip, mac = _ip(m.group("ip")), _unicast(m.group("mac"))
        if not ip or not mac:
            continue
        out.append(_stub(ip, mac, "neighbors", interface=interface, arp_type=m.group("type").lower()))
    return out


def parse_get_netneighbor(text: str) -> list[DiscoveredAsset]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    out = []
    for r in rows:
        if not isinstance(r, dict) or r.get("State") in _BAD_PS_STATES:
            continue
        ip, mac = _ip(r.get("IPAddress")), _unicast(r.get("LinkLayerAddress"))
        if not ip or not mac:
            continue
        out.append(_stub(ip, mac, "neighbors", interface=r.get("InterfaceAlias")))
    return out


def parse_neighbors(text: str) -> list[DiscoveredAsset]:
    """Detect the format and parse it."""
    t = (text or "").lstrip()
    if not t:
        return []
    if t[0] in "[{":
        return parse_get_netneighbor(t)
    if re.search(r"(?mi)^\s*interface:\s", t):
        return parse_arp_windows(t)
    if re.search(r"(?m)\)\s+at\s+", t):
        return parse_arp_linux(t)
    return parse_ip_neigh(t)


def parse_hosts_file(text: str) -> list[DiscoveredAsset]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        ip = _ip(parts[0])
        if not ip or len(parts) < 2:
            continue
        a = DiscoveredAsset(address=ip, hostname=parts[1], sources=["hosts_file"])
        if len(parts) > 2:
            a.facts["aliases"] = parts[2:]
        a.evidence.append(f"hosts file: {ip} {parts[1]}")
        out.append(a)
    return out


def parse_known_hosts(text: str) -> list[DiscoveredAsset]:
    """Only host names and addresses are read; key material is never kept. Hashed entries (|1|...) carry no
    readable host and are skipped."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0].startswith("@"):          # @cert-authority / @revoked marker lines
            parts = parts[1:]
        if len(parts) < 2 or parts[0].startswith("|"):
            continue
        names, ips, ssh_port = [], [], None
        for h in parts[0].split(","):
            m = re.match(r"^\[(?P<h>[^\]]+)\]:(?P<p>\d+)$", h)
            if m:
                h, ssh_port = m.group("h"), int(m.group("p"))
            ip = _ip(h)
            (ips if ip else names).append(ip or h)
        for ip in ips:
            a = DiscoveredAsset(address=ip, hostname=names[0] if names else None, sources=["known_hosts"])
            a.facts["ssh_key_type"] = parts[1]
            if ssh_port:
                a.facts["ssh_port"] = ssh_port
            a.evidence.append(f"known_hosts: operator has connected to {ip} over SSH before")
            out.append(a)
    return out
