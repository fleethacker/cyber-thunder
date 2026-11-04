"""Simulated sweep: a realistic discovery run with no packets sent, for the demo and the tests.

The simulated enclave is 192.168.56.0/24. It holds one asset per inventory target (or, with an empty
inventory, the standard demo set below) plus three seeded surprises that the answer key
(range/answer_key/discovery.json) expects discovery to catch:

  D1  a Raspberry Pi at 192.168.56.66 with telnet and a web server   rogue device      discovery:unknown_asset
  D2  an unmanaged Cisco switch at 192.168.56.3 (seen over CDP)      not in inventory  discovery:unknown_asset
  D3  a new tcp/4444 listener on the first Linux host                new listener      discovery:new_listener

Any inventory target with address 192.168.56.99 is never answered, so it is reported missing.
The previous sweep of the simulated enclave is fixed (`baseline`), so the new listener shows every time.
"""
from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from .models import DiscoveredAsset, OpenPort
from .oui import vendor_for
from .sources.network_gear import parse_cdp_detail

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.inventory.targets import Target

DEMO_SCOPE = "192.168.56.0/24"
MISSING_ADDRESS = "192.168.56.99"
ROGUE_PI = "192.168.56.66"
UNMANAGED_SWITCH = "192.168.56.3"

STANDARD_SET = (
    ("sim-linux-01", "192.168.56.10", "linux"),
    ("sim-win-01", "192.168.56.11", "windows"),
    ("sim-switch-01", "192.168.56.2", "cisco_ios"),
    ("sim-k8s-01", "192.168.56.20", "kubernetes"),
    ("sim-docker-01", "192.168.56.30", "containers"),
)

# What the managed switch reports over CDP about the switch nobody put in the inventory.
_CDP_UNMANAGED = """-------------------------
Device ID: SW-SPARE-03
Entry address(es):
  IP address: 192.168.56.3
Platform: cisco WS-C2960X-24TS-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/23,  Port ID (outgoing port): GigabitEthernet0/1
Holdtime : 171 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc2)

advertisement version: 2
Native VLAN: 1
Duplex: full
Management address(es):
  IP address: 192.168.56.3
"""


def _ssh_linux() -> OpenPort:
    return OpenPort(22, "tcp", "ssh", "OpenSSH", "8.7", "OpenSSH 8.7 (protocol 2.0)")


TEMPLATES: dict[str, dict] = {
    "linux": {"mac_prefix": "52:54:00", "os": "Rocky Linux 9.4", "ostypes": ["Linux"],
              "ports": lambda: [_ssh_linux()]},
    "windows": {"mac_prefix": "00:15:5d", "os": "Microsoft Windows 11 Enterprise", "ostypes": ["Windows"],
                "ports": lambda: [OpenPort(135, "tcp", "msrpc", "Microsoft Windows RPC"),
                                  OpenPort(139, "tcp", "netbios-ssn", "Microsoft Windows netbios-ssn"),
                                  OpenPort(445, "tcp", "microsoft-ds"),
                                  OpenPort(3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services"),
                                  OpenPort(5985, "tcp", "http", "Microsoft HTTPAPI httpd", "2.0")]},
    "cisco_ios": {"mac_prefix": "70:10:5c", "os": "Cisco IOS XE 17.6", "ostypes": ["IOS"],
                  "ports": lambda: [OpenPort(22, "tcp", "ssh", "Cisco SSH", "1.25", "Cisco SSH 1.25 (protocol 2.0)"),
                                    OpenPort(23, "tcp", "telnet", "Cisco router telnetd")]},
    "kubernetes": {"mac_prefix": "52:54:00", "os": "Ubuntu 22.04.4 LTS", "ostypes": ["Linux"],
                   "ports": lambda: [OpenPort(22, "tcp", "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10"),
                                     OpenPort(6443, "tcp", "ssl/http", "Golang net/http server"),
                                     OpenPort(10250, "tcp", "ssl/http", "Golang net/http server")]},
    "containers": {"mac_prefix": "52:54:00", "os": "Rocky Linux 9.4", "ostypes": ["Linux"],
                   "ports": lambda: [_ssh_linux(), OpenPort(2375, "tcp", "docker", "Docker", "4.9.4"),
                                     OpenPort(8080, "tcp", "http", "nginx", "1.24.0")]},
}
NEW_LISTENER = OpenPort(4444, "tcp", "http", "SimpleHTTPServer", "0.6", "SimpleHTTPServer 0.6 (Python 3.9.18)")


def _mac(prefix: str, address: str) -> str:
    last = int(ipaddress.ip_address(address)) & 0xFF
    return f"{prefix}:56:00:{last:02x}"


def _asset(name: str, address: str, asset_type: str) -> DiscoveredAsset:
    t = TEMPLATES[asset_type]
    mac = _mac(t["mac_prefix"], address)
    a = DiscoveredAsset(address=address, hostname=name, mac=mac, vendor=vendor_for(mac),
                        open_ports=t["ports"](), os_guess=t["os"], sources=["simulated"])
    a.facts["service_ostypes"] = list(t["ostypes"])
    a.facts["simulated"] = True
    a.evidence.append(f"simulated sweep: {address} answered")
    return a


class SimulatedSweep:
    def __init__(self, targets: list["Target"] | None = None):
        self.targets = list(targets or [])
        self.baseline: dict[str, set[str]] = {}
        self._assets = self._build()

    def _plan(self) -> list[tuple[str, str, str]]:
        if not self.targets:
            return list(STANDARD_SET)
        def address_of(t) -> str | None:
            # adapters that reach a target by file or kubeconfig keep its address in options
            return t.address or (t.options or {}).get("address")

        used = {address_of(t) for t in self.targets if address_of(t)}
        standard_free = {typ: addr for _, addr, typ in STANDARD_SET if addr not in used}
        plan, extra = [], 100
        for t in self.targets:
            addr = address_of(t)
            if addr == MISSING_ADDRESS:
                continue
            try:
                addr = str(ipaddress.ip_address(addr)) if addr else None
            except ValueError:
                addr = None
            if not addr:
                addr = standard_free.pop(t.asset_type, None)
                while not addr or addr in used:
                    addr, extra = f"192.168.56.{extra}", extra + 1
                used.add(addr)
            plan.append((t.name, addr, t.asset_type))
        return plan

    def _build(self) -> list[DiscoveredAsset]:
        out: list[DiscoveredAsset] = []
        listener_placed = False
        for name, addr, typ in self._plan():
            a = _asset(name, addr, typ)
            self.baseline[addr] = set(a.port_keys)
            if typ == "linux" and not listener_placed:
                a.open_ports.append(NEW_LISTENER)
                listener_placed = True
            out.append(a)
        # D1: rogue single-board computer
        pi_mac = "b8:27:eb:5a:66:01"
        pi = DiscoveredAsset(address=ROGUE_PI, mac=pi_mac, vendor=vendor_for(pi_mac), sources=["simulated"],
                             open_ports=[OpenPort(23, "tcp", "telnet", "Linux telnetd"),
                                         OpenPort(80, "tcp", "http", "lighttpd", "1.4.59")])
        pi.facts.update(service_ostypes=["Linux"], simulated=True)
        pi.evidence.append(f"simulated sweep: {ROGUE_PI} answered")
        out.append(pi)
        # D2: unmanaged switch, learned over CDP from the managed one and confirmed by its open ports
        sw = parse_cdp_detail(_CDP_UNMANAGED)[0]
        sw.mac = "2c:31:24:56:00:03"
        sw.vendor = vendor_for(sw.mac)
        sw.merge(DiscoveredAsset(address=UNMANAGED_SWITCH, sources=["simulated"], open_ports=[
            OpenPort(22, "tcp", "ssh", "Cisco SSH", "1.99"), OpenPort(23, "tcp", "telnet", "Cisco router telnetd")]))
        sw.id = DiscoveredAsset(address=UNMANAGED_SWITCH, mac=sw.mac).id
        sw.facts["simulated"] = True
        out.append(sw)
        return out

    def assets(self) -> list[DiscoveredAsset]:
        return [DiscoveredAsset.from_dict(a.to_dict()) for a in self._assets]
