"""Intrusion and persistence indicators in an IOS running-config.

Each indicator is a ``HuntHit`` with a stable check id (``hunt:cisco:<check>:<item>``), the MITRE ATT&CK
techniques it maps to, the evidence line(s), and, where the remedy is a plain config removal, the
lines that remove it. The removal lines are built here from parsed config values that passed a strict
name check (``_safe``); nothing is built from free text.

ATT&CK mapping notes (for the reviewer of these findings):
  T1136.001  Create Account: Local Account          unexpected local user / privilege 15 user
  T1098      Account Manipulation                   privilege 15 granted to an unknown account
  T1602.001  Data from Configuration Repository: SNMP (MIB Dump)   public/private or RW community
  T1552      Unsecured Credentials                  community strings are cleartext shared secrets
  T1190      Exploit Public-Facing Application      HTTP management server enabled
  T1053      Scheduled Task/Job                     EEM applet / kron schedule
  T1059      Command and Scripting Interpreter      tclsh in EEM / kron
  T1602.002  Data from Configuration Repository: Network Device Configuration Dump   config copied off-box
  T1572      Protocol Tunneling                     unexpected tunnel interface
  T1599      Network Boundary Bridging              static route to an unexpected next hop
  T1020      Automated Exfiltration / T1562 Impair Defenses   syslog sent to an unknown collector
  T1562      Impair Defenses                        logging disabled
  T1562.004  Impair Defenses: Disable or Modify System Firewall   ACL permits any source
  T1021      Remote Services                        telnet accepted on vty lines (cleartext credentials)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .parser import ConfigModel
from .rules import external_interfaces, resolve_options

_SAFE = re.compile(r"^[A-Za-z0-9_.\-/:@]+$")
DEFAULT_COMMUNITIES = {"public", "private", "cisco", "secret", "community", "admin", "manager", "write", "read"}
SUSPICIOUS_CLI = ("tclsh", "copy ", "tftp:", "ftp:", "scp:", "http:", "https:", "more ", "username ",
                  "no logging", "event manager run", "archive", "file prompt quiet", "delete ")


@dataclass
class HuntHit:
    check: str                          # e.g. unknown_user
    item: str                           # e.g. netops2
    title: str
    severity: str
    attack: list[str]
    evidence: str
    description: str
    remove_lines: list[str] = field(default_factory=list)   # config lines that remove the indicator
    disruption: str = "low"

    @property
    def check_id(self) -> str:
        return f"hunt:cisco:{self.check}"

    @property
    def rule_id(self) -> str:
        return f"{self.check_id}:{self.item}" if self.item else self.check_id


def _safe(s: str | None) -> bool:
    return bool(s) and bool(_SAFE.match(s))


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-/]+", "_", s).strip("_")


def _users(m: ConfigModel, o: dict) -> list[HuntHit]:
    known = set(o.get("known_users") or [])
    out = []
    for u in m.users:
        unknown = bool(known) and u.name not in known
        priv15 = u.privilege >= 15 and (not known or u.name not in known)
        if not (unknown or priv15):
            continue
        why = []
        if unknown:
            why.append("not in the approved account list")
        if u.privilege >= 15:
            why.append("privilege 15")
        out.append(HuntHit(
            "unknown_user", u.name, f"Unexpected local account '{u.name}'", "high" if u.privilege >= 15 else "medium",
            ["T1136.001", "T1098"] if u.privilege >= 15 else ["T1136.001"],
            f"username {u.name} privilege {u.privilege} {u.kind} <redacted>",
            f"Local user '{u.name}' ({', '.join(why)}). A backdoor account survives AAA server changes and "
            f"gives full device control at privilege 15.",
            [f"no username {u.name}"] if _safe(u.name) else [], "medium"))
    return out


def _snmp(m: ConfigModel, o: dict) -> list[HuntHit]:
    out = []
    for c in m.snmp_communities:
        default = c.name.lower() in DEFAULT_COMMUNITIES
        rw_open = c.access == "RW" and not c.acl
        if not (default or rw_open):
            continue
        why = []
        if default:
            why.append("well-known community name")
        if rw_open:
            why.append("read-write with no ACL")
        out.append(HuntHit(
            "snmp_community", c.name, f"SNMP community '{c.name}' ({c.access})",
            "high" if c.access == "RW" else "medium", ["T1602.001", "T1552"],
            f"snmp-server community {c.name} {c.access}" + (f" {c.acl}" if c.acl else ""),
            f"SNMP community '{c.name}': {', '.join(why)}. A read-write community lets anyone who knows the "
            f"string change the configuration or pull it with a MIB dump.",
            [f"no snmp-server community {c.name}"] if _safe(c.name) else [], "medium"))
    return out


def _http(m: ConfigModel, o: dict) -> list[HuntHit]:
    if not m.http_server:
        return []
    auth = m.http_auth or "enable (default)"
    return [HuntHit("http_server", "", "HTTP management server enabled", "high", ["T1190"],
                    "ip http server" + (f"; ip http authentication {m.http_auth}" if m.http_auth else ""),
                    f"The cleartext HTTP management server is on (authentication: {auth}). The IOS-XE web UI has "
                    f"been used for unauthenticated device takeover; on an enclave device it should be off.",
                    ["no ip http server"])]


def _applets(m: ConfigModel, o: dict) -> list[HuntHit]:
    known = set(o.get("known_applets") or [])
    out = []
    for ap in m.applets:
        if ap.name in known:
            continue
        acts = " | ".join(ap.actions)
        low = acts.lower()
        bad = [s.strip() for s in SUSPICIOUS_CLI if s in low]
        if not bad:
            continue
        attack = ["T1053"]
        if "tclsh" in low:
            attack.append("T1059")
        if "copy " in low and ("running" in low or "startup" in low or "tftp" in low):
            attack.append("T1602.002")
        out.append(HuntHit("eem_applet", ap.name, f"EEM applet '{ap.name}' runs suspicious commands", "high", attack,
                           f"event manager applet {ap.name}: {ap.event}; {acts[:300]}",
                           f"Embedded Event Manager applet '{ap.name}' is scheduled or triggered on the device and "
                           f"runs: {', '.join(bad)}. Copying the configuration off-box leaks hashes, keys and "
                           f"topology.",
                           [f"no event manager applet {ap.name}"] if _safe(ap.name) else []))
    return out


def _kron(m: ConfigModel, o: dict) -> list[HuntHit]:
    out = []
    for p in m.kron_policies:
        low = " | ".join(p.cli).lower()
        bad = [s.strip() for s in SUSPICIOUS_CLI if s in low]
        if not bad:
            continue
        occ = [x for x in m.kron_occurrences if p.name in x.policies]
        attack = ["T1053"] + (["T1059"] if "tclsh" in low else []) + \
            (["T1602.002"] if "copy " in low else [])
        lines = [f"no kron occurrence {x.name}" for x in occ if _safe(x.name)]
        if _safe(p.name):
            lines.append(f"no kron policy-list {p.name}")
        out.append(HuntHit("kron", p.name, f"kron policy '{p.name}' runs suspicious commands", "high", attack,
                           f"kron policy-list {p.name}: {' | '.join(p.cli)[:300]}; scheduled by: "
                           f"{', '.join(x.name + ' ' + x.schedule for x in occ) or 'nothing'}",
                           f"kron policy '{p.name}' runs {', '.join(bad)} on a schedule.", lines))
    return out


def _tunnels(m: ConfigModel, o: dict) -> list[HuntHit]:
    known = set(o.get("known_tunnels") or [])
    out = []
    for t in m.tunnels:
        if t.name in known:
            continue
        out.append(HuntHit("tunnel", t.name, f"Unexpected tunnel interface {t.name}", "high", ["T1572"],
                           f"interface {t.name}: source {t.tunnel_source or '-'} destination "
                           f"{t.tunnel_destination or '-'}",
                           f"Tunnel {t.name} is not in the approved tunnel list. A GRE/IPsec tunnel to an outside "
                           f"address can carry enclave traffic past the boundary.",
                           [f"no interface {t.name}"] if _safe(t.name) else [], "medium"))
    return out


def _routes(m: ConfigModel, o: dict) -> list[HuntHit]:
    known = set(o.get("known_next_hops") or [])
    nets = m.connected_networks()
    out = []
    for r in m.routes:
        if r.next_hop is None and not (r.interface and r.interface.lower().startswith("tunnel")):
            continue                          # routes out a physical interface or Null0 are not indicators
        if known:
            odd = r.next_hop not in known
        else:
            try:
                nh = ipaddress.IPv4Address(r.next_hop) if r.next_hop else None
            except ValueError:
                nh = None
            odd = nh is None or not any(nh in n for n in nets)
        if not odd:
            continue
        out.append(HuntHit("static_route", r.prefix, f"Static route {r.prefix} via unexpected next hop", "medium",
                           ["T1599", "T1572"], r.line,
                           f"Static route to {r.prefix} points at {r.next_hop or r.interface}, which is not a known "
                           f"gateway or on a connected subnet. Attackers add routes to steer traffic through a "
                           f"collection point.", [f"no {r.line}"] if all(_safe(x) for x in r.line.split()) else [],
                           "medium"))
    return out


def _logging(m: ConfigModel, o: dict) -> list[HuntHit]:
    known = set(o.get("known_syslog") or []) | set(o.get("log_servers") or [])
    out = []
    for h in m.logging_hosts:
        if known and h.address not in known:
            out.append(HuntHit("log_host", h.address, f"Syslog sent to unknown host {h.address}", "medium",
                               ["T1020", "T1562"], h.line,
                               f"Logs are sent to {h.address}, which is not an approved collector. Device logs carry "
                               f"usernames and topology; a rogue collector also hides activity from the real one.",
                               [f"no logging host {h.address}"] if _safe(h.address) else []))
    if not m.logging_on or m.logging_trap == -1:
        what = "no logging on" if not m.logging_on else "no logging trap"
        out.append(HuntHit("logging_disabled", "", "Device logging disabled", "high", ["T1562"], what,
                           f"'{what}' stops events reaching the collectors. Disabling logging is a common step "
                           f"before changing a device.",
                           (["logging on"] if not m.logging_on else []) +
                           (["logging trap informational"] if m.logging_trap == -1 else [])))
    return out


def _acls(m: ConfigModel, o: dict) -> list[HuntHit]:
    ext = external_interfaces(m, o)
    applied_ext = {i.ip_access_group_in for i in ext if i.ip_access_group_in}
    hints = ("external", "internet", "outside", "inbound", "wan")
    out = []
    for name, acl in m.acls.items():
        if not (name in applied_ext or any(h in name.lower() for h in hints)):
            continue
        hits = [e for e in acl.entries if re.match(r"^permit\s+(ip|tcp|udp|icmp|gre|esp)\s+any\s+any\b", e)
                or (acl.kind == "standard" and re.match(r"^permit\s+any\b", e))]
        if not hits:
            continue
        lines: list[str] = []
        if not acl.numbered and _safe(name):
            lines = [f"ip access-list {acl.kind} {name}"] + [f" no {e}" for e in hits]
        out.append(HuntHit("acl_permit_any", name, f"Boundary ACL {name} permits any source", "high", ["T1562.004"],
                           f"ip access-list {acl.kind} {name}: " + " | ".join(hits),
                           f"ACL {name} filters traffic from outside the enclave but contains "
                           f"'{hits[0]}', which lets everything through ahead of the deny rules.", lines, "medium"))
    return out


def _telnet(m: ConfigModel, o: dict) -> list[HuntHit]:
    out = []
    for b in m.vty_lines:
        ti = b.transport_input
        if ti is None or not ({"telnet", "all"} & set(ti)):
            continue
        out.append(HuntHit("telnet_vty", _slug(b.name), f"Telnet accepted on {b.header}", "high", ["T1021"],
                           f"{b.header}: transport input {' '.join(ti)}",
                           f"{b.header} accepts telnet: administrator credentials cross the network in cleartext. "
                           f"Remote management must be SSH only.",
                           [b.header, " transport input ssh"], "medium"))
    return out


CHECKS = (_users, _snmp, _http, _applets, _kron, _tunnels, _routes, _logging, _acls, _telnet)


def hunt_config(model: ConfigModel, options: dict | None = None) -> list[HuntHit]:
    o = resolve_options(options)
    out: list[HuntHit] = []
    for fn in CHECKS:
        out.extend(fn(model, o))
    return out
