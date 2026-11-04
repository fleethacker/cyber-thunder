"""DISA STIG rules for Cisco IOS / IOS-XE, evaluated against a parsed running-config.

Identifiers (STIG ID, group V-id, SV rule id, severity, title, CCI) come from ``stig_rules.json`` next to
this file: Cisco IOS XE Switch NDM V3R6, Switch L2S V3R1 and Router RTR V3R3. The check and fix logic
below is ours; the JSON summaries are what the approver sees.

Each rule has:
  check(model, opts) -> (passed, evidence)   passed None = cannot decide from the config alone
  fix(model, opts)   -> [config lines]       IOS lines, indented under 'interface ...' / 'line ...' headers
  disruption                                  low, or medium where a mistake can cut off management access

Organization-defined values (session limit, servers, VLANs) come from target.options; ``resolve_options``
documents the keys and defaults.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

from .parser import ConfigModel, Interface, format_vlan_list, parse_vlan_list
from .snippet import apply_snippet, inverse_snippet

RULES_JSON = Path(__file__).with_name("stig_rules.json")

FAMILY_BENCHMARK = {
    "NDM": ("Cisco IOS XE Switch NDM STIG", "V3R6"),
    "L2S": ("Cisco IOS XE Switch L2S STIG", "V3R1"),
    "RTR": ("Cisco IOS XE Router RTR STIG", "V3R3"),
}

EXTERNAL_HINTS = ("external", "wan", "internet", "isp", "outside", "untrust")

DOD_BANNER = (
    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for "
    "USG-authorized use only.\n"
    "By using this IS (which includes any device attached to this IS), you consent to the following "
    "conditions:\n"
    "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not "
    "limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel "
    "misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n"
    "-At any time, the USG may inspect and seize data stored on this IS.\n"
    "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, "
    "interception, and search, and may be disclosed or used for any USG-authorized purpose.\n"
    "-This IS includes security measures (e.g., authentication and access controls) to protect USG "
    "interests--not for your personal benefit or privacy.\n"
    "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative "
    "searching or monitoring of the content of privileged communications, or work product, related to "
    "personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. "
    "Such communications and work product are private and confidential. See User Agreement for details."
)

INSECURE_SERVICES = (
    "ip http server", "service pad", "service finger", "ip finger", "service tcp-small-servers",
    "service udp-small-servers", "ip bootp server", "ip dns server", "ip identd", "ip rcmd rcp-enable",
    "ip rcmd rsh-enable", "service config", "boot network",
)

SHA2_MACS = {"hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"}
APPROVED_CIPHERS = {"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm", "aes256-gcm",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}


def resolve_options(options: dict | None) -> dict:
    """target.options with defaults for every organization-defined value the rules use."""
    o = dict(options or {})
    o.setdefault("max_sessions", 2)                 # CISC-ND-000010
    o.setdefault("min_password_length", 15)         # CISC-ND-000550
    o.setdefault("max_idle_minutes", 5)             # CISC-ND-000720
    o.setdefault("min_log_buffer", 4096)            # CISC-ND-000980 (bytes)
    o.setdefault("unused_vlan", 999)                # CISC-L2-000210
    o.setdefault("native_vlan", 998)                # CISC-L2-000260
    o.setdefault("non_user_vlans", [])              # CISC-L2-000130: management/infrastructure VLANs
    o.setdefault("known_users", [])
    o.setdefault("known_syslog", [])
    o.setdefault("log_servers", list(o.get("known_syslog") or []))   # CISC-ND-001450
    o.setdefault("ntp_servers", [])                 # CISC-ND-001030
    o.setdefault("aaa_servers", [])                 # CISC-ND-001370
    o.setdefault("external_interfaces", None)       # CISC-RT-000190/330/380
    o.setdefault("external_acl", None)              # CISC-RT-000330
    return o


def device_role(model: ConfigModel, opts: dict) -> str:
    role = (opts or {}).get("role")
    if role in ("switch", "router"):
        return role
    if any(i.switchport_mode or i.access_vlan for i in model.interfaces.values()):
        return "switch"
    if model.vtp or model.spanning_tree:
        return "switch"
    return "router"


def families_for(model: ConfigModel, opts: dict) -> tuple[str, ...]:
    fams = (opts or {}).get("stig_families")
    if fams:
        return tuple(fams)
    return ("NDM", "L2S") if device_role(model, opts) == "switch" else ("NDM", "RTR")


# -- small helpers used by checks -------------------------------------------------------------------

def _switch_ports(model: ConfigModel) -> list[Interface]:
    return [i for i in model.interfaces.values()
            if i.is_physical and not i.no_switchport and not i.ip_address
            and not any(x.startswith("vrf forwarding") for x in i.lines)]


def _access_ports(model: ConfigModel) -> list[Interface]:
    return [i for i in _switch_ports(model) if i.switchport_mode == "access" and not i.shutdown]


def _trunk_ports(model: ConfigModel) -> list[Interface]:
    return [i for i in _switch_ports(model) if i.switchport_mode == "trunk"]


def external_interfaces(model: ConfigModel, opts: dict) -> list[Interface]:
    names = opts.get("external_interfaces")
    if names:
        return [model.interfaces[n] for n in names if n in model.interfaces]
    return [i for i in model.interfaces.values()
            if i.description and any(h in i.description.lower() for h in EXTERNAL_HINTS) and not i.is_tunnel]


def _ext_undecided(model: ConfigModel, opts: dict) -> tuple[bool | None, str] | None:
    if not external_interfaces(model, opts):
        return None, ("no external interface identified: set options.external_interfaces or describe the "
                      "interface with 'description ... EXTERNAL/WAN ...'")
    return None


def _join(items: list[str], limit: int = 8) -> str:
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _block(header: str, lines: list[str]) -> list[str]:
    return [header] + [" " + x for x in lines]


# -- checks and fixes --------------------------------------------------------------------------------

def _nd010(m, o):
    lim = int(o["max_sessions"])
    bad = [b.header for b in m.vty_lines
           if b.accepts_input and not (b.session_limit is not None and b.session_limit <= lim)]
    if not m.vty_lines:
        return None, "no vty lines in the configuration"
    return (not bad), (f"vty ranges without session-limit <= {lim}: {_join(bad)}" if bad
                       else f"every vty range accepting input has session-limit <= {lim}")


def _nd010_fix(m, o):
    lim = int(o["max_sessions"])
    out = []
    for b in m.vty_lines:
        if b.accepts_input and not (b.session_limit is not None and b.session_limit <= lim):
            out += _block(b.header, [f"session-limit {lim}"])
    return out


def _nd150(m, o):
    b = m.login_block_for
    if not b:
        return False, "no 'login block-for' line: failed logons are not rate limited"
    ok = b["attempts"] and b["attempts"] <= 3 and b["block_for"] >= 900
    return bool(ok), (f"login block-for {b['block_for']} attempts {b['attempts']} within {b['within']}"
                      + ("" if ok else " (need attempts <= 3 and block-for >= 900 s)"))


def _nd150_fix(m, o):
    return ["login block-for 900 attempts 3 within 120"]


def _nd160(m, o):
    body = m.banners.get("login")
    if body is None:
        others = ", ".join(sorted(m.banners)) or "none"
        return False, f"no 'banner login' configured (other banners: {others})"
    ok = "U.S. Government" in body or "USG" in body or "consent to terms" in body
    return ok, ("banner login contains the DoD notice and consent text" if ok
                else "banner login does not contain the DoD notice and consent text: " + body[:80].replace("\n", " "))


def _nd160_fix(m, o):
    return ["banner login ^C\n" + DOD_BANNER + "\n^C"]


def _nd210(m, o):
    ok = m.archive_log_enabled
    return ok, ("archive / log config / logging enable present" if ok
                else "configuration change logging is off (no 'archive' / 'log config' / 'logging enable')")


def _nd210_fix(m, o):
    return ["archive", " log config", "  logging enable", "  notify syslog contenttype plaintext", "  hidekeys"]


def _nd470(m, o):
    on = [s for s in INSECURE_SERVICES if m.has_line(s)]
    return (not on), ("enabled: " + ", ".join(on) if on else "no unnecessary or nonsecure services enabled")


def _nd470_fix(m, o):
    return [f"no {s}" for s in INSECURE_SERVICES if m.has_line(s)]


def _keep_account(m, o) -> str | None:
    want = o.get("account_of_last_resort")
    names = [u.name for u in m.users]
    if want in names:
        return want
    for k in o.get("known_users") or []:
        if k in names:
            return k
    return names[0] if names else None


def _nd490(m, o):
    names = [u.name for u in m.users]
    if len(names) <= 1:
        return True, f"local accounts: {', '.join(names) or 'none'}"
    return False, f"{len(names)} local accounts ({', '.join(names)}); only the account of last resort may exist"


def _nd490_fix(m, o):
    keep = _keep_account(m, o)
    return [f"no username {u.name}" for u in m.users if u.name != keep]


def _nd550(m, o):
    need = int(o["min_password_length"])
    have = max(m.common_criteria_min_length or 0, m.security_min_length or 0)
    ok = have >= need
    return ok, (f"minimum password length {have}" if have else "no password length policy configured") + \
        ("" if ok else f" (need {need})")


def _nd550_fix(m, o):
    return ["aaa common-criteria policy PASSWORD_POLICY", f" min-length {int(o['min_password_length'])}"]


def _nd620(m, o):
    bad = []
    if not m.services.get("password-encryption"):
        bad.append("service password-encryption is off")
    if m.enable_password:
        bad.append("'enable password' is set (reversible)")
    bad += [f"username {u.name} uses 'password' (type {u.secret_type})" for u in m.users if u.kind == "password"]
    return (not bad), ("; ".join(bad) if bad else "only hashed secrets stored; password-encryption on")


def _nd620_fix(m, o):
    out = []
    if not m.services.get("password-encryption"):
        out.append("service password-encryption")
    if m.enable_password and m.enable_secret:
        out.append("no enable password")
    return out


def _idle_ok(b, maxmin: int) -> bool:
    if b.exec_timeout is None:
        return False                       # IOS default is 10 minutes
    secs = b.exec_timeout[0] * 60 + b.exec_timeout[1]
    return 0 < secs <= maxmin * 60


def _nd720(m, o):
    mx = int(o["max_idle_minutes"])
    blocks = [b for b in m.line_blocks if b.kind in ("con", "aux", "vty")]
    bad = [f"{b.header} ({'%d %d' % b.exec_timeout if b.exec_timeout else 'default 10 min'})"
           for b in blocks if not _idle_ok(b, mx)]
    return (not bad), ("idle timeout above %d min: %s" % (mx, _join(bad)) if bad
                       else f"all management lines time out within {mx} min")


def _nd720_fix(m, o):
    mx = int(o["max_idle_minutes"])
    out = []
    for b in m.line_blocks:
        if b.kind in ("con", "aux", "vty") and not _idle_ok(b, mx):
            out += _block(b.header, [f"exec-timeout {mx} 0"])
    return out


def _nd980(m, o):
    need = int(o["min_log_buffer"])
    size = m.logging_buffered
    ok = bool(size) and size >= need
    if size is None:
        return False, "no 'logging buffered' line: local audit storage not allocated"
    return ok, (m.logging_buffered_line or "") + ("" if ok else f" (need >= {need} bytes)")


def _nd980_fix(m, o):
    return [f"logging buffered {max(int(o['min_log_buffer']), 65536)} informational"]


def _nd1000(m, o):
    lvl = m.logging_trap
    if not m.logging_on:
        return False, "'no logging on': logging is disabled"
    if lvl is None:
        return False, "no explicit 'logging trap' level: audit failure alerts are not configured"
    ok = lvl >= 2
    return ok, f"logging trap level {lvl}" + ("" if ok else " (critical events are not sent)")


def _nd1000_fix(m, o):
    out = [] if m.logging_on else ["logging on"]
    return out + ["logging trap informational"]


def _nd1030(m, o):
    srv = [s.address for s in m.ntp_servers]
    return len(srv) >= 2, f"NTP servers: {', '.join(srv) or 'none'}" + ("" if len(srv) >= 2 else " (need two)")


def _key_for_new_ntp(m) -> str | None:
    return m.ntp_trusted_keys[0] if m.ntp_trusted_keys and m.ntp_auth_keys else None


def _nd1030_fix(m, o):
    have = {s.address for s in m.ntp_servers}
    key = _key_for_new_ntp(m)
    out = []
    for a in o.get("ntp_servers") or []:
        if len(have) >= 2:
            break
        if a not in have:
            out.append(f"ntp server {a}" + (f" key {key}" if key else ""))
            have.add(a)
    return out


def _nd1130(m, o):
    bad = [f"community {c.name} ({c.access})" for c in m.snmp_communities]
    bad += [f"group {g.name} v3 noauth" for g in m.snmp_groups if g.version == "v3" and g.level == "noauth"]
    bad += [f"group {g.name} {g.version}" for g in m.snmp_groups if g.version in ("v1", "v2c")]
    return (not bad), ("unauthenticated SNMP: " + ", ".join(bad) if bad else "SNMP uses v3 with authentication")


def _snmp_fix(m, priv: bool) -> list[str]:
    out = [f"no snmp-server community {c.name}" for c in m.snmp_communities]
    for g in m.snmp_groups:
        if g.version == "v3" and (g.level == "noauth" or (priv and g.level == "auth")):
            out.append(g.line.replace(f" v3 {g.level}", " v3 priv", 1))
    return out


def _nd1140(m, o):
    bad = [f"community {c.name}" for c in m.snmp_communities]
    bad += [f"group {g.name} {g.version} {g.level or ''}".strip() for g in m.snmp_groups
            if not (g.version == "v3" and g.level == "priv")]
    return (not bad), ("SNMP without privacy: " + ", ".join(bad) if bad else "SNMP v3 priv only")


def _nd1150(m, o):
    bad = []
    if not m.ntp_authenticate:
        bad.append("'ntp authenticate' missing")
    if not m.ntp_trusted_keys:
        bad.append("no 'ntp trusted-key'")
    bad += [f"server {s.address} has no key" for s in m.ntp_servers if not s.key]
    if not m.ntp_servers:
        bad.append("no NTP servers")
    return (not bad), ("; ".join(bad) if bad else "NTP sources authenticated")


def _nd1150_fix(m, o):
    out = []
    if not m.ntp_authenticate:
        out.append("ntp authenticate")
    key = _key_for_new_ntp(m)
    if key:
        out += [f"{s.line} key {key}" for s in m.ntp_servers if not s.key]
    return out


def _nd1200(m, o):
    macs = m.ssh_mac
    if not macs:
        return False, "no 'ip ssh server algorithm mac' line: device default MACs include SHA-1"
    weak = [x for x in macs if x not in SHA2_MACS]
    return (not weak), ("SSH MACs: " + " ".join(macs) + (f" (not approved: {' '.join(weak)})" if weak else ""))


def _nd1200_fix(m, o):
    return ["ip ssh version 2", "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256"]


def _nd1210(m, o):
    bad = []
    if m.ssh_version != 2:
        bad.append("ip ssh version 2 not set")
    if not m.ssh_encryption:
        bad.append("no 'ip ssh server algorithm encryption' line (defaults include CBC/3DES)")
    else:
        weak = [x for x in m.ssh_encryption if x not in APPROVED_CIPHERS]
        if weak:
            bad.append("not approved: " + " ".join(weak))
    return (not bad), ("; ".join(bad) if bad else "SSHv2 with " + " ".join(m.ssh_encryption or []))


def _nd1210_fix(m, o):
    return ["ip ssh version 2", "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"]


def _nd1260(m, o):
    miss = [x for x, ok in (("login on-failure log", m.login_on_failure), ("login on-success log", m.login_on_success))
            if not ok]
    return (not miss), ("missing: " + ", ".join(miss) if miss else "logon success and failure are logged")


def _nd1260_fix(m, o):
    out = []
    if not m.login_on_failure:
        out.append("login on-failure log")
    if not m.login_on_success:
        out.append("login on-success log")
    return out


def _nd1370(m, o):
    srv = [s for s in m.aaa_servers if s.address]
    ok = m.aaa_new_model and len(srv) >= 2
    detail = f"aaa new-model {'on' if m.aaa_new_model else 'off'}; servers: " + \
        (", ".join(f"{s.protocol} {s.name} {s.address}" for s in srv) or "none")
    return ok, detail + ("" if ok else " (need two authentication servers)")


def _nd1370_fix(m, o):
    out = [] if m.aaa_new_model else ["aaa new-model"]
    have = {s.address for s in m.aaa_servers if s.address}
    proto = m.aaa_servers[0].protocol if m.aaa_servers else "tacacs"
    n = len(have)
    for a in o.get("aaa_servers") or []:
        if n >= 2:
            break
        if a not in have:
            n += 1
            out += _block(f"{proto} server AAA-{n}", [f"address ipv4 {a}"])
            have.add(a)
    return out


def _nd1450(m, o):
    hosts = [h.address for h in m.logging_hosts]
    return len(hosts) >= 2, f"syslog hosts: {', '.join(hosts) or 'none'}" + ("" if len(hosts) >= 2 else " (need two)")


def _nd1450_fix(m, o):
    have = {h.address for h in m.logging_hosts}
    known = set(o.get("log_servers") or [])
    count = len(have & known) if known else len(have)
    out = []
    for a in o.get("log_servers") or []:
        if count >= 2:
            break
        if a not in have:
            out.append(f"logging host {a}")
            count += 1
    return out


def _l2_100(m, o):
    glob = bool(m.spanning_tree.get("portfast_bpduguard_default"))
    bad = [i.name for i in _access_ports(m) if not (i.bpduguard or (glob and i.portfast))]
    return (not bad), ("access ports without BPDU guard: " + _join(bad) if bad
                       else "BPDU guard on every active access port")


def _l2_100_fix(m, o):
    glob = bool(m.spanning_tree.get("portfast_bpduguard_default"))
    out = []
    for i in _access_ports(m):
        if not (i.bpduguard or (glob and i.portfast)):
            out += _block(i.header, ["spanning-tree bpduguard enable"])
    return out


def _user_vlans(m, o) -> set[int]:
    skip = {int(o["unused_vlan"])} | {int(v) for v in o.get("non_user_vlans") or []}
    return {i.access_vlan or 1 for i in _access_ports(m)} - skip


def _l2_130(m, o):
    need = _user_vlans(m, o)
    if not need:
        return True, "no user VLANs on access ports"
    miss = need - m.dhcp_snooping_vlans
    ok = m.dhcp_snooping and not miss
    if not m.dhcp_snooping:
        return False, f"'ip dhcp snooping' is off; user VLANs: {format_vlan_list(need)}"
    return ok, ("DHCP snooping on user VLANs " + format_vlan_list(need) if ok
                else f"user VLANs without DHCP snooping: {format_vlan_list(miss)}")


def _l2_130_fix(m, o):
    need = _user_vlans(m, o)
    out = []
    if need - m.dhcp_snooping_vlans:
        out.append("ip dhcp snooping vlan " + format_vlan_list(need | m.dhcp_snooping_vlans))
    if not m.dhcp_snooping:
        out.append("ip dhcp snooping")
    for t in _trunk_ports(m):
        if not t.dhcp_snooping_trust and not t.shutdown:
            out += _block(t.header, ["ip dhcp snooping trust"])
    return out


def _l2_210(m, o):
    uv = int(o["unused_vlan"])
    bad = [f"{i.name} (vlan {i.access_vlan or 1})" for i in _switch_ports(m)
           if i.shutdown and not (i.switchport_mode == "access" and i.access_vlan == uv)]
    return (not bad), (f"disabled ports not in inactive VLAN {uv}: {_join(bad)}" if bad
                       else f"every disabled port is in inactive VLAN {uv}")


def _l2_210_fix(m, o):
    uv = int(o["unused_vlan"])
    out = []
    for i in _switch_ports(m):
        if i.shutdown and not (i.switchport_mode == "access" and i.access_vlan == uv):
            lines = []
            if i.switchport_mode != "access":
                lines.append("switchport mode access")
            lines.append(f"switchport access vlan {uv}")
            out += _block(i.header, lines)
    return out


def _l2_230(m, o):
    bad = [f"{t.name} (allowed {t.trunk_allowed or 'all'})" for t in _trunk_ports(m)
           if 1 in parse_vlan_list(t.trunk_allowed)]
    return (not bad), ("trunks carrying VLAN 1: " + _join(bad) if bad else "VLAN 1 pruned from every trunk")


def _l2_230_fix(m, o):
    out = []
    for t in _trunk_ports(m):
        allowed = parse_vlan_list(t.trunk_allowed)
        if 1 in allowed:
            out += _block(t.header, ["switchport trunk allowed vlan " + format_vlan_list(allowed - {1})])
    return out


def _l2_260(m, o):
    bad = [t.name for t in _trunk_ports(m) if (t.trunk_native_vlan or 1) == 1]
    return (not bad), ("trunks with native VLAN 1: " + _join(bad) if bad else "no trunk uses VLAN 1 as native")


def _l2_260_fix(m, o):
    nv = int(o["native_vlan"])
    out = []
    for t in _trunk_ports(m):
        if (t.trunk_native_vlan or 1) == 1:
            out += _block(t.header, [f"switchport trunk native vlan {nv}"])
    return out


def _has_subifs(m, name: str) -> bool:
    return any(n.startswith(name + ".") for n in m.interfaces)


def _inactive(m) -> list[Interface]:
    return [i for i in m.interfaces.values()
            if i.is_physical and not i.shutdown and not i.ip_address and not i.ip_unnumbered
            and not i.switchport_mode and not _has_subifs(m, i.name)]


def _rt060(m, o):
    bad = [i.name for i in _inactive(m)]
    return (not bad), ("interfaces with no address that are not shut down: " + _join(bad) if bad
                       else "every unused interface is shut down")


def _rt060_fix(m, o):
    out = []
    for i in _inactive(m):
        out += _block(i.header, ["shutdown"])
    return out


def _rt160(m, o):
    bad = [i.name for i in m.interfaces.values() if i.directed_broadcast]
    return (not bad), ("ip directed-broadcast on: " + _join(bad) if bad else "no interface forwards directed broadcasts")


def _rt160_fix(m, o):
    out = []
    for i in m.interfaces.values():
        if i.directed_broadcast:
            out += _block(i.header, ["no ip directed-broadcast"])
    return out


def _rt190(m, o):
    u = _ext_undecided(m, o)
    if u:
        return u
    bad = [i.name for i in external_interfaces(m, o) if i.redirects]
    return (not bad), ("ICMP redirects on external: " + _join(bad) if bad else "no ICMP redirects on external interfaces")


def _rt190_fix(m, o):
    out = []
    for i in external_interfaces(m, o):
        if i.redirects:
            out += _block(i.header, ["no ip redirects"])
    return out


def _ext_acl_name(m, o) -> str | None:
    want = o.get("external_acl")
    if want and want in m.acls:
        return want
    for name, acl in m.acls.items():
        if acl.kind == "extended" and any(h in name.lower() for h in ("external", "internet", "outside", "inbound")):
            return name
    return None


def _rt330(m, o):
    u = _ext_undecided(m, o)
    if u:
        return u
    bad = []
    for i in external_interfaces(m, o):
        if not i.ip_access_group_in:
            bad.append(f"{i.name} (no inbound ACL)")
        elif i.ip_access_group_in not in m.acls:
            bad.append(f"{i.name} (ACL {i.ip_access_group_in} is not defined)")
    return (not bad), ("external interfaces without an inbound filter: " + _join(bad) if bad
                       else "every external interface filters inbound traffic")


def _rt330_fix(m, o):
    name = _ext_acl_name(m, o)
    if not name:
        return []
    out = []
    for i in external_interfaces(m, o):
        if not i.ip_access_group_in or i.ip_access_group_in not in m.acls:
            out += _block(i.header, [f"ip access-group {name} in"])
    return out


def _rt380(m, o):
    u = _ext_undecided(m, o)
    if u:
        return u
    bad = [i.name for i in external_interfaces(m, o) if i.proxy_arp]
    return (not bad), ("proxy ARP on external: " + _join(bad) if bad else "proxy ARP off on external interfaces")


def _rt380_fix(m, o):
    out = []
    for i in external_interfaces(m, o):
        if i.proxy_arp:
            out += _block(i.header, ["no ip proxy-arp"])
    return out


# STIG ID -> (check, fix, disruption, static fix: same lines for every device)
_LOGIC: dict[str, tuple[Callable, Callable, str, bool]] = {
    "CISC-ND-000010": (_nd010, _nd010_fix, "low", False),
    "CISC-ND-000150": (_nd150, _nd150_fix, "low", True),
    "CISC-ND-000160": (_nd160, _nd160_fix, "low", True),
    "CISC-ND-000210": (_nd210, _nd210_fix, "low", True),
    "CISC-ND-000470": (_nd470, _nd470_fix, "low", False),
    "CISC-ND-000490": (_nd490, _nd490_fix, "medium", False),
    "CISC-ND-000550": (_nd550, _nd550_fix, "medium", True),
    "CISC-ND-000620": (_nd620, _nd620_fix, "low", False),
    "CISC-ND-000720": (_nd720, _nd720_fix, "low", False),
    "CISC-ND-000980": (_nd980, _nd980_fix, "low", True),
    "CISC-ND-001000": (_nd1000, _nd1000_fix, "low", False),
    "CISC-ND-001030": (_nd1030, _nd1030_fix, "low", False),
    "CISC-ND-001130": (_nd1130, lambda m, o: _snmp_fix(m, False), "medium", False),
    "CISC-ND-001140": (_nd1140, lambda m, o: _snmp_fix(m, True), "medium", False),
    "CISC-ND-001150": (_nd1150, _nd1150_fix, "low", False),
    "CISC-ND-001200": (_nd1200, _nd1200_fix, "medium", True),
    "CISC-ND-001210": (_nd1210, _nd1210_fix, "medium", True),
    "CISC-ND-001260": (_nd1260, _nd1260_fix, "low", True),
    "CISC-ND-001370": (_nd1370, _nd1370_fix, "medium", False),
    "CISC-ND-001450": (_nd1450, _nd1450_fix, "low", False),
    "CISC-L2-000100": (_l2_100, _l2_100_fix, "low", False),
    "CISC-L2-000130": (_l2_130, _l2_130_fix, "medium", False),
    "CISC-L2-000210": (_l2_210, _l2_210_fix, "low", False),
    "CISC-L2-000230": (_l2_230, _l2_230_fix, "medium", False),
    "CISC-L2-000260": (_l2_260, _l2_260_fix, "medium", False),
    "CISC-RT-000060": (_rt060, _rt060_fix, "medium", False),
    "CISC-RT-000160": (_rt160, _rt160_fix, "low", False),
    "CISC-RT-000190": (_rt190, _rt190_fix, "low", False),
    "CISC-RT-000330": (_rt330, _rt330_fix, "medium", False),
    "CISC-RT-000380": (_rt380, _rt380_fix, "low", False),
}


@dataclass
class Rule:
    stig_id: str
    group_id: str
    rule_id: str                   # SV-...r..._rule
    severity: str
    title: str
    family: str                    # NDM | L2S | RTR
    cci: list[str]
    check_summary: str
    fix_summary: str
    config_evidence: str
    confirmed: bool
    source_url: str
    check_fn: Callable = field(repr=False, default=None)
    fix_fn: Callable = field(repr=False, default=None)
    disruption: str = "low"
    static_fix: bool = False

    @property
    def citations(self) -> list[str]:
        return [self.stig_id, self.group_id, self.rule_id, *self.cci]

    @property
    def benchmark(self) -> tuple[str, str]:
        return FAMILY_BENCHMARK.get(self.family, ("Cisco IOS XE STIG", ""))

    def check(self, model: ConfigModel, opts: dict | None = None) -> tuple[bool | None, str]:
        return self.check_fn(model, resolve_options(opts))

    def fix_lines(self, model: ConfigModel, opts: dict | None = None) -> list[str]:
        return self.fix_fn(model, resolve_options(opts))

    def fix_snippet(self, model: ConfigModel, opts: dict | None = None) -> str:
        return "\n".join(self.fix_lines(model, opts))

    def rollback_snippet(self, model: ConfigModel, opts: dict | None = None) -> str:
        """Inverse of fix_snippet for this config. Live devices prefer 'configure replace' of the archive."""
        snip = self.fix_snippet(model, opts)
        if not snip:
            return ""
        return inverse_snippet(model.text, apply_snippet(model.text, snip))


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    data = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    out = []
    for d in data:
        logic = _LOGIC.get(d["stig_id"])
        if logic is None:
            continue
        check, fix, disruption, static = logic
        out.append(Rule(stig_id=d["stig_id"], group_id=d.get("group_id", ""), rule_id=d.get("rule_id", ""),
                        severity=d.get("severity", "medium"), title=d.get("title", ""),
                        family=d.get("stig_family", ""), cci=list(d.get("cci") or []),
                        check_summary=d.get("check_summary", ""), fix_summary=d.get("fix_summary", ""),
                        config_evidence=d.get("config_evidence", ""), confirmed=bool(d.get("confirmed")),
                        source_url=d.get("source_url", ""), check_fn=check, fix_fn=fix,
                        disruption=disruption, static_fix=static))
    return tuple(out)


def rules_by_id() -> dict[str, Rule]:
    return {r.stig_id: r for r in load_rules()}


def applicable_rules(model: ConfigModel, opts: dict | None = None) -> list[Rule]:
    fams = families_for(model, resolve_options(opts))
    return [r for r in load_rules() if r.family in fams]


def evaluate(model: ConfigModel, opts: dict | None = None,
             rule_filter: list[str] | None = None) -> list[tuple[Rule, bool | None, str]]:
    """Run every applicable rule. Returns (rule, passed, evidence); a rule that raises is reported, not hidden."""
    o = resolve_options(opts)
    out = []
    for r in applicable_rules(model, o):
        if rule_filter and r.stig_id not in rule_filter and r.rule_id not in rule_filter \
                and r.group_id not in rule_filter:
            continue
        try:
            passed, ev = r.check_fn(model, o)
        except Exception as e:  # noqa: BLE001
            passed, ev = None, f"check error: {e}"
        out.append((r, passed, ev))
    return out
