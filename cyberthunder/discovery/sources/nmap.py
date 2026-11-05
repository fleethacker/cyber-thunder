"""nmap: command table, runner and XML parser.

The command line is built from a fixed table per mode. The only variable parts are target addresses,
and those come from validated DiscoveryScope CIDRs or from addresses nmap itself reported inside them.

  ping   -sn -n -T3 --max-rate 50 -oX - <cidrs>                     live-host sweep, no port probes
  quick  -sV --top-ports 25 -T3 --max-rate 50 -n -oX - <hosts>      after the ping sweep
  full   -sV --top-ports 200 -T3 --max-rate 50 --script smb-os-discovery [-O] -n -oX - <hosts>
                                                                    (-O only when privileged)

smb-os-discovery is the only NSE script used. It is unauthenticated and asks a Windows host for its OS,
computer name and domain over SMB, the same answer any domain member gets when it browses the share.

-n is dropped only when the caller asks to resolve names (resolve=True). Output is XML on stdout.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from cyberthunder.findings.schema import utcnow

from ..models import DiscoveredAsset, DiscoveryScope, OpenPort
from ..oui import tag_virtual, vendor_for

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.transport.base import Transport

PING_OPTIONS = ("-sn", "-T3", "--max-rate", "50")
MODE_OPTIONS: dict[str, tuple[str, ...]] = {
    "quick": ("-sV", "--top-ports", "25", "-T3", "--max-rate", "50"),
    "full": ("-sV", "--top-ports", "200", "-T3", "--max-rate", "50", "--script", "smb-os-discovery"),
}
PRIVILEGED_OPTIONS: dict[str, tuple[str, ...]] = {"quick": (), "full": ("-O",)}
OUTPUT_OPTIONS = ("-oX", "-")
NO_RESOLVE = ("-n",)

NMAP_CANDIDATES = (Path(r"C:\Program Files (x86)\Nmap\nmap.exe"), Path(r"C:\Program Files\Nmap\nmap.exe"),
                   Path("/usr/bin/nmap"), Path("/usr/local/bin/nmap"))

_SAFE_ARG = re.compile(r"^[A-Za-z0-9._:/\-]+$")


class NmapError(RuntimeError):
    pass


def find_nmap() -> str | None:
    """PATH first, then the standard install locations on Windows and Linux."""
    found = shutil.which("nmap")
    if found:
        return found
    for c in NMAP_CANDIDATES:
        if c.exists():
            return str(c)
    return None


def _scopes(scopes: Iterable[DiscoveryScope | str]) -> list[DiscoveryScope]:
    out = []
    for s in scopes:
        sc = s if isinstance(s, DiscoveryScope) else DiscoveryScope(cidr=str(s))
        sc.validate()
        out.append(sc)
    if not out:
        raise ValueError("at least one scope is required")
    return out


def _hosts(hosts: Iterable[str], scopes: list[DiscoveryScope]) -> list[str]:
    out = []
    for h in hosts:
        try:
            addr = str(ipaddress.ip_address(str(h).strip()))
        except ValueError:
            raise ValueError(f"not an IP address: {h!r}") from None
        if not any(s.contains(addr) for s in scopes):
            raise ValueError(f"{addr} is outside the sweep scopes")
        out.append(addr)
    if not out:
        raise ValueError("no hosts to scan")
    return out


def build_ping_command(scopes: Iterable[DiscoveryScope | str], *, resolve: bool = False,
                       nmap: str = "nmap") -> list[str]:
    sc = _scopes(scopes)
    return [nmap, *_family_options(sc), *PING_OPTIONS, *(() if resolve else NO_RESOLVE), *OUTPUT_OPTIONS, *(s.cidr for s in sc)]


def _family_options(scopes):
    versions = {s.network.version for s in scopes}
    if len(versions) != 1:
        raise ValueError("IPv4 and IPv6 scopes must run in separate commands")
    return ("-6",) if versions == {6} else ()


def build_command(scopes: Iterable[DiscoveryScope | str], mode: str = "quick", privileged: bool = False, *,
                  resolve: bool = False, hosts: Iterable[str] | None = None, nmap: str = "nmap") -> list[str]:
    """argv for the port/service phase. `hosts` (from the ping sweep) must lie inside `scopes`;
    without it the scope CIDRs themselves are the targets."""
    if mode not in MODE_OPTIONS:
        raise ValueError(f"unknown nmap mode {mode!r}; expected one of {sorted(MODE_OPTIONS)}")
    sc = _scopes(scopes)
    targets = _hosts(hosts, sc) if hosts is not None else [s.cidr for s in sc]
    opts = [*MODE_OPTIONS[mode], *(PRIVILEGED_OPTIONS[mode] if privileged else ())]
    return [nmap, *_family_options(sc), *opts, *(() if resolve else NO_RESOLVE), *OUTPUT_OPTIONS, *targets]


def render(argv: list[str], transport: "Transport | None" = None) -> str:
    """Turn argv into the command string a Transport runs. Every argument after the executable must be a
    plain token (option, number, address or CIDR); anything else is refused."""
    exe, args = argv[0], argv[1:]
    for a in args:
        if not _SAFE_ARG.match(a):
            raise ValueError(f"refusing unsafe nmap argument {a!r}")
    if getattr(transport, "shell", None) == "powershell":
        return "& '" + exe.replace("'", "''") + "' " + " ".join(args)
    return shlex.join([exe, *args])


def run_nmap(transport: "Transport", argv: list[str], *, sudo: bool = False, timeout: int = 170) -> str:
    r = transport.run(render(argv, transport), timeout=timeout, sudo=sudo)
    if not r.ok or "<nmaprun" not in (r.stdout or ""):
        raise NmapError(f"nmap failed ({r.exit_code}): {(r.stderr or r.stdout or '').strip()[:300]}")
    return r.stdout


# -- parsing -----------------------------------------------------------------------------------------

def _root(text: str) -> ET.Element:
    if "<!ENTITY" in text:
        raise ValueError("nmap XML must not declare entities")
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text, count=1)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"not valid nmap XML: {e}") from None
    if root.tag != "nmaprun":
        raise ValueError(f"expected <nmaprun>, got <{root.tag}>")
    return root


def live_hosts(text: str) -> list[str]:
    """Addresses reported up in a ping sweep (or any nmap XML)."""
    out = []
    for h in _root(text).findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and a.get("addr"):
                out.append(a.get("addr"))
                break
    return out


def _int(value: str | None) -> int | None:
    """An nmap numeric attribute, or None when it is missing or not a number."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _port(p: ET.Element) -> tuple[OpenPort, dict] | None:
    st = p.find("state")
    if st is None or st.get("state") != "open":
        return None
    svc = p.find("service")
    name = product = version = extra = ostype = tunnel = ""
    if svc is not None:
        name, product, version = svc.get("name", ""), svc.get("product", ""), svc.get("version", "")
        extra, ostype, tunnel = svc.get("extrainfo", ""), svc.get("ostype", ""), svc.get("tunnel", "")
    scripts = {s.get("id", ""): (s.get("output") or "").strip() for s in p.findall("script")}
    cpes = [c.text.strip() for c in (svc.findall("cpe") if svc is not None else []) if c.text]
    banner = scripts.get("banner") or " ".join(x for x in (product, version, f"({extra})" if extra else "") if x)
    portid = _int(p.get("portid"))
    if portid is None:
        raise ValueError(f"port has no numeric portid ({p.get('portid')!r})")
    op = OpenPort(port=portid, proto=p.get("protocol", "tcp"),
                  service=(f"{tunnel}/{name}" if tunnel and name else name), product=product, version=version,
                  banner=banner)
    meta = {"ostype": ostype, "extrainfo": extra, "scripts": scripts, "cpes": cpes}
    return op, meta


def parse_xml(text: str, errors: list[str] | None = None) -> list[DiscoveredAsset]:
    """Up hosts as DiscoveredAssets. A host whose XML cannot be read is skipped and described in
    `errors` (when given) so one odd record does not cost the rest of the scope."""
    root = _root(text)
    scanned_at = utcnow()   # nmap's own timestr is locale-formatted; record when we read it instead
    assets: list[DiscoveredAsset] = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        try:
            asset = _host(h, scanned_at)
        except (ValueError, TypeError, AttributeError) as e:
            addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")),
                        None)
            if errors is not None:
                errors.append(f"skipped host {addr or '?'}: {e}")
            continue
        assets.append(asset)
    return assets


def _host(h: ET.Element, scanned_at: str) -> DiscoveredAsset:
    address = mac = vendor = None
    for a in h.findall("address"):
        t = a.get("addrtype")
        if t in ("ipv4", "ipv6") and not address:
            address = a.get("addr")
        elif t == "mac":
            mac, vendor = a.get("addr"), a.get("vendor")
    hostnames = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
    asset = DiscoveredAsset(address=address, mac=mac, vendor=vendor or vendor_for(mac),
                            hostname=hostnames[0] if hostnames else None,
                            first_seen=scanned_at, last_seen=scanned_at, sources=["nmap"])
    if len(hostnames) > 1:
        asset.facts["hostnames"] = hostnames
    ostypes: list[str] = []
    for p in h.findall("ports/port"):
        got = _port(p)
        if got is None:
            continue
        op, meta = got
        asset.open_ports.append(op)
        if meta["ostype"] and meta["ostype"] not in ostypes:
            ostypes.append(meta["ostype"])
        for c in meta["cpes"]:
            asset.facts.setdefault("cpes", [])
            if c not in asset.facts["cpes"]:
                asset.facts["cpes"].append(c)
        if "snmp-sysdescr" in meta["scripts"]:
            asset.facts["snmp_sysdescr"] = meta["scripts"]["snmp-sysdescr"]
    asset.open_ports.sort(key=lambda o: (o.proto, o.port))
    if ostypes:
        asset.facts["service_ostypes"] = ostypes
    matches = h.findall("os/osmatch")
    if matches:
        best = max(matches, key=lambda m: _int(m.get("accuracy")) or 0)
        asset.os_guess = best.get("name")
        asset.os_accuracy = _int(best.get("accuracy")) or 0
        asset.facts["osclass"] = [
            {"vendor": c.get("vendor", ""), "family": c.get("osfamily", ""), "gen": c.get("osgen", ""),
             "type": c.get("type", ""), "accuracy": _int(c.get("accuracy")) or 0}
            for c in best.findall("osclass")]
    up = h.find("uptime")
    if up is not None and _int(up.get("seconds")) is not None:
        asset.facts["uptime_s"] = _int(up.get("seconds"))
        if up.get("lastboot"):
            asset.facts["lastboot"] = up.get("lastboot")
    for s in h.findall("hostscript/script"):
        out = (s.get("output") or "").strip()
        if s.get("id") == "nbstat":
            m = re.search(r"NetBIOS name:\s*([^\s,]+)", out)
            if m:
                asset.facts["netbios_name"] = m.group(1)
                asset.hostname = asset.hostname or m.group(1)
        elif s.get("id") == "smb-os-discovery":
            _smb_os_discovery(asset, s, out)
    tag_virtual(asset)
    return asset


_SMB_LINES = {"os": r"^\s*OS:\s*(.+)$", "computer": r"^\s*Computer name:\s*(\S+)",
              "netbios": r"^\s*NetBIOS computer name:\s*([^\s\\]+)", "domain": r"^\s*Domain name:\s*(\S+)",
              "fqdn": r"^\s*FQDN:\s*(\S+)"}
_SMB_ELEMS = {"os": "os", "server": "netbios", "domain": "domain", "fqdn": "fqdn", "lanmanager": "lanmanager"}


def _smb_os_discovery(asset: DiscoveredAsset, script: ET.Element, output: str) -> None:
    """Fold the smb-os-discovery host script into the asset: OS, computer name and domain."""
    got: dict[str, str] = {}
    for e in script.findall("elem"):
        key = _SMB_ELEMS.get(e.get("key", ""))
        if key and e.text:
            got[key] = e.text.replace("\\x00", "").strip()   # nmap prints the NetBIOS NUL as text
    for key, rx in _SMB_LINES.items():
        if key not in got:
            m = re.search(rx, output, re.M)
            if m:
                got[key] = m.group(1).strip()
    computer = got.get("computer") or got.get("netbios") or (got.get("fqdn", "").split(".")[0] or None)
    if got.get("os"):
        # SMB names the exact edition and build; an -O match is a fingerprint range, so keep it as a fact
        if asset.os_guess and asset.os_guess != got["os"]:
            asset.facts["nmap_os_match"] = asset.os_guess
        asset.os_guess = got["os"]
    if computer:
        asset.facts["netbios_name"] = computer
        asset.hostname = asset.hostname or got.get("fqdn") or computer
    if got.get("domain"):
        asset.facts["domain"] = got["domain"]
    asset.facts["smb_os"] = {k: v for k, v in got.items()}
    asset.evidence.append("smb-os-discovery: " + ", ".join(
        f"{label} {got[k]}" for k, label in (("os", "OS"), ("computer", "computer name"), ("domain", "domain"))
        if got.get(k)))


def nmap_version(text: str) -> str | None:
    try:
        return _root(text).get("version")
    except ValueError:
        return None
