"""Cisco IOS / IOS-XE running-config parser.

Two layers:

* ``tokenize()`` turns config text into a tree of ``Node`` objects by indentation (a banner is kept as a
  single multi-line node). ``render()`` turns the tree back into text. Tokenize + render is a byte-exact
  round trip for normal ``show running-config`` output, which is what lets ``snippet.apply_snippet`` edit
  a config without disturbing lines it does not touch.
* ``parse_config()`` reads the tree into ``ConfigModel``: the facts the STIG rules and the hunt module
  need (lines, interfaces, users, SNMP, NTP, logging, ACLs, EEM, kron, routes ...).

Pure text processing; standard library only.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# -- tree --------------------------------------------------------------------------------------------


@dataclass
class Node:
    text: str                      # stripped line text; a banner holds every line of the banner
    indent: int = 0                # leading spaces as found in the source
    children: list["Node"] = field(default_factory=list)

    def child_texts(self) -> list[str]:
        return [c.text for c in self.children]

    def walk(self):
        for c in self.children:
            yield c
            yield from c.walk()


def banner_delim(rest: str) -> str:
    """Delimiter of a banner: '^C' as printed by show running-config, otherwise the first character."""
    rest = rest.lstrip()
    if rest.startswith("^") and len(rest) >= 2:
        return rest[:2]
    return rest[:1]


def split_lines(text: str) -> list[str]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def tokenize(text: str) -> list[Node]:
    """Config text -> list of top-level nodes. Children nest by indentation."""
    lines = split_lines(text)
    root: list[Node] = []
    stack: list[Node] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        ind = len(raw) - len(raw.lstrip(" "))
        if ind == 0 and stripped.startswith("banner "):
            parts = stripped.split(None, 2)
            if len(parts) == 3:
                delim = banner_delim(parts[2])
                after = parts[2].lstrip()[len(delim):]
                block = [raw]
                if delim and delim not in after:
                    i += 1
                    while i < len(lines):
                        block.append(lines[i])
                        if delim in lines[i]:
                            break
                        i += 1
                node = Node("\n".join(block), 0)
                root.append(node)
                stack = []
                i += 1
                continue
        node = Node(stripped, ind)
        while stack and stack[-1].indent >= ind:
            stack.pop()
        if stack and stripped:
            stack[-1].children.append(node)
        else:
            root.append(node)
            stack = []
        if stripped:
            stack.append(node)
        i += 1
    return root


def render(nodes: list[Node], trailing_newline: bool = True) -> str:
    out: list[str] = []

    def emit(n: Node) -> None:
        if "\n" in n.text:            # banner: lines kept verbatim
            out.append(n.text)
        else:
            out.append(" " * n.indent + n.text)
        for c in n.children:
            emit(c)

    for n in nodes:
        emit(n)
    s = "\n".join(out)
    return s + "\n" if trailing_newline and out else s


# -- model -------------------------------------------------------------------------------------------

LOG_LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4,
              "notifications": 5, "informational": 6, "debugging": 7}

PHYSICAL_RE = re.compile(r"^(GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|"
                         r"HundredGigE|AppGigabitEthernet|Ethernet|TwoGigabitEthernet|FiveGigabitEthernet)\S*$", re.I)


@dataclass
class LineBlock:
    header: str                     # "line vty 0 4"
    kind: str                       # con | aux | vty
    first: int = 0
    last: int = 0
    exec_timeout: tuple[int, int] | None = None     # (minutes, seconds); None = not set (IOS default 10 min)
    transport_input: list[str] | None = None
    transport_output: list[str] | None = None
    access_class_in: str | None = None
    access_class_out: str | None = None
    login: str | None = None        # "login", "login local", "login authentication X"
    password: str | None = None     # raw "password ..." line
    session_limit: int | None = None
    privilege_level: int | None = None
    lines: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.header[len("line "):]

    @property
    def count(self) -> int:
        return self.last - self.first + 1

    @property
    def accepts_input(self) -> bool:
        return self.transport_input is None or "none" not in self.transport_input


@dataclass
class Interface:
    name: str
    shutdown: bool = False
    description: str | None = None
    no_switchport: bool = False
    switchport_mode: str | None = None
    access_vlan: int | None = None
    trunk_native_vlan: int | None = None
    trunk_allowed: str | None = None
    port_security: bool = False
    ip_address: str | None = None
    ip_mask: str | None = None
    ip_unnumbered: bool = False
    ip_access_group_in: str | None = None
    ip_access_group_out: str | None = None
    cdp_enabled: bool = True
    proxy_arp: bool = True
    redirects: bool = True
    directed_broadcast: bool = False
    bpduguard: bool = False
    portfast: bool = False
    dhcp_snooping_trust: bool = False
    tunnel_source: str | None = None
    tunnel_destination: str | None = None
    lines: list[str] = field(default_factory=list)

    @property
    def header(self) -> str:
        return f"interface {self.name}"

    @property
    def is_physical(self) -> bool:
        return bool(PHYSICAL_RE.match(self.name)) and "." not in self.name

    @property
    def is_tunnel(self) -> bool:
        return self.name.lower().startswith("tunnel")

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        if not (self.ip_address and self.ip_mask):
            return None
        try:
            return ipaddress.IPv4Interface(f"{self.ip_address}/{self.ip_mask}").network
        except ValueError:
            return None


@dataclass
class AccessList:
    name: str
    kind: str                      # standard | extended
    numbered: bool = False
    entries: list[str] = field(default_factory=list)


@dataclass
class User:
    name: str
    privilege: int = 1
    kind: str = "secret"           # secret | password | nopassword
    secret_type: str | None = None
    line: str = ""


@dataclass
class SnmpCommunity:
    name: str
    access: str = "RO"
    acl: str | None = None
    line: str = ""


@dataclass
class SnmpGroup:
    name: str
    version: str
    level: str | None              # noauth | auth | priv (v3 only)
    line: str = ""


@dataclass
class NtpServer:
    address: str
    key: str | None = None
    line: str = ""


@dataclass
class LoggingHost:
    address: str
    line: str = ""


@dataclass
class Applet:
    name: str
    event: str = ""
    actions: list[str] = field(default_factory=list)


@dataclass
class KronPolicy:
    name: str
    cli: list[str] = field(default_factory=list)


@dataclass
class KronOccurrence:
    name: str
    schedule: str = ""
    policies: list[str] = field(default_factory=list)


@dataclass
class Route:
    dest: str
    mask: str
    next_hop: str | None
    interface: str | None
    line: str
    vrf: str | None = None

    @property
    def prefix(self) -> str:
        try:
            return str(ipaddress.IPv4Network(f"{self.dest}/{self.mask}", strict=False))
        except ValueError:
            return f"{self.dest}/{self.mask}"


@dataclass
class AaaServer:
    name: str
    protocol: str                   # tacacs | radius
    address: str | None = None
    has_key: bool = False


@dataclass
class ConfigModel:
    text: str
    nodes: list[Node]
    hostname: str | None = None
    version: str | None = None
    global_lines: list[str] = field(default_factory=list)
    services: dict[str, bool] = field(default_factory=dict)      # "password-encryption": True, "pad": False
    enable_secret: str | None = None
    enable_password: str | None = None
    users: list[User] = field(default_factory=list)
    aaa_new_model: bool = False
    aaa_lines: list[str] = field(default_factory=list)
    aaa_servers: list[AaaServer] = field(default_factory=list)
    common_criteria_min_length: int | None = None
    security_min_length: int | None = None
    line_blocks: list[LineBlock] = field(default_factory=list)
    interfaces: dict[str, Interface] = field(default_factory=dict)
    acls: dict[str, AccessList] = field(default_factory=dict)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    snmp_groups: list[SnmpGroup] = field(default_factory=list)
    snmp_users: list[str] = field(default_factory=list)
    snmp_hosts: list[str] = field(default_factory=list)
    ntp_servers: list[NtpServer] = field(default_factory=list)
    ntp_authenticate: bool = False
    ntp_trusted_keys: list[str] = field(default_factory=list)
    ntp_auth_keys: dict[str, str] = field(default_factory=dict)   # key id -> algorithm
    logging_on: bool = True
    logging_hosts: list[LoggingHost] = field(default_factory=list)
    logging_buffered: int | None = None          # size; 0 = disabled; None = not configured
    logging_buffered_line: str | None = None
    logging_trap: int | None = None              # level number; -1 = "no logging trap"
    logging_userinfo: bool = False
    banners: dict[str, str] = field(default_factory=dict)          # login|motd|exec -> body text
    http_server: bool = False
    http_secure_server: bool = False
    http_auth: str | None = None
    ssh_version: int | None = None
    ssh_mac: list[str] | None = None
    ssh_encryption: list[str] | None = None
    login_block_for: dict | None = None
    login_on_failure: bool = False
    login_on_success: bool = False
    archive_present: bool = False
    archive_log_enabled: bool = False
    archive_path: str | None = None
    applets: list[Applet] = field(default_factory=list)
    kron_policies: list[KronPolicy] = field(default_factory=list)
    kron_occurrences: list[KronOccurrence] = field(default_factory=list)
    domain_name: str | None = None
    crypto_key_present: bool = False
    vtp: dict[str, str] = field(default_factory=dict)
    spanning_tree: dict[str, str | bool] = field(default_factory=dict)
    dhcp_snooping: bool = False
    dhcp_snooping_vlans: set[int] = field(default_factory=set)
    routes: list[Route] = field(default_factory=list)
    ip_routing: bool = False

    # -- convenience ----------------------------------------------------------------------------
    def line(self, kind: str) -> list[LineBlock]:
        return [b for b in self.line_blocks if b.kind == kind]

    @property
    def vty_lines(self) -> list[LineBlock]:
        return self.line("vty")

    @property
    def tunnels(self) -> list[Interface]:
        return [i for i in self.interfaces.values() if i.is_tunnel]

    def has_line(self, text: str) -> bool:
        return text in self.global_lines

    def connected_networks(self) -> list[ipaddress.IPv4Network]:
        return [n for n in (i.network for i in self.interfaces.values()) if n is not None]


# -- helpers -----------------------------------------------------------------------------------------

def parse_vlan_list(spec: str | None) -> set[int]:
    """'1-5,10,20-22' -> {1..5, 10, 20, 21, 22}. 'all' or None -> 1-4094. 'except 1' -> 2-4094."""
    if spec is None or spec.strip().lower() in ("all", ""):
        return set(range(1, 4095))
    s = spec.strip().lower()
    if s == "none":
        return set()
    if s.startswith("except "):
        return set(range(1, 4095)) - parse_vlan_list(s[len("except "):])
    out: set[int] = set()
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def format_vlan_list(vlans) -> str:
    vs = sorted(set(vlans))
    if not vs:
        return "none"
    parts: list[str] = []
    start = prev = vs[0]
    for v in vs[1:]:
        if v == prev + 1:
            prev = v
            continue
        parts.append(f"{start}-{prev}" if prev > start else str(start))
        start = prev = v
    parts.append(f"{start}-{prev}" if prev > start else str(start))
    return ",".join(parts)


def _int(s: str | None, default: int | None = None) -> int | None:
    try:
        return int(s) if s is not None else default
    except ValueError:
        return default


def banner_body(text: str) -> tuple[str, str]:
    """Banner node text -> (kind, body without delimiters)."""
    parts = text.split(None, 2)
    kind = parts[1] if len(parts) > 1 else ""
    rest = parts[2] if len(parts) > 2 else ""
    delim = banner_delim(rest)
    body = rest.lstrip()[len(delim):]
    if delim and delim in body:
        body = body[: body.rfind(delim)]
    return kind, body.strip("\n")


def is_ipv4(s: str | None) -> bool:
    if not s:
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


# -- parse -------------------------------------------------------------------------------------------

def _parse_line_block(node: Node) -> LineBlock:
    w = node.text.split()
    kind = w[1] if len(w) > 1 else ""
    nums = [int(x) for x in w[2:] if x.isdigit()]
    first = nums[0] if nums else 0
    last = nums[1] if len(nums) > 1 else first
    b = LineBlock(header=node.text, kind=kind, first=first, last=last, lines=node.child_texts())
    for t in b.lines:
        cw = t.split()
        if not cw:
            continue
        if cw[0] == "exec-timeout" and len(cw) >= 2:
            b.exec_timeout = (_int(cw[1], 0) or 0, (_int(cw[2], 0) or 0) if len(cw) > 2 else 0)
        elif cw[:2] == ["transport", "input"]:
            b.transport_input = cw[2:]
        elif cw[:2] == ["transport", "output"]:
            b.transport_output = cw[2:]
        elif cw[0] == "access-class" and len(cw) >= 3:
            if cw[-1] == "in":
                b.access_class_in = cw[1]
            elif cw[-1] == "out":
                b.access_class_out = cw[1]
        elif cw[0] == "login":
            b.login = t
        elif cw[0] == "password":
            b.password = t
        elif cw[0] == "session-limit" and len(cw) > 1:
            b.session_limit = _int(cw[1])
        elif cw[:2] == ["privilege", "level"] and len(cw) > 2:
            b.privilege_level = _int(cw[2])
    return b


def _parse_interface(node: Node) -> Interface:
    name = node.text.split(None, 1)[1] if " " in node.text else ""
    i = Interface(name=name, lines=node.child_texts())
    for t in i.lines:
        w = t.split()
        if not w:
            continue
        if t == "shutdown":
            i.shutdown = True
        elif t == "no shutdown":
            i.shutdown = False
        elif w[0] == "description":
            i.description = t[len("description "):]
        elif t == "no switchport":
            i.no_switchport = True
        elif w[:2] == ["switchport", "mode"] and len(w) > 2:
            i.switchport_mode = w[2]
        elif w[:3] == ["switchport", "access", "vlan"] and len(w) > 3:
            i.access_vlan = _int(w[3])
        elif w[:4] == ["switchport", "trunk", "native", "vlan"] and len(w) > 4:
            i.trunk_native_vlan = _int(w[4])
        elif w[:4] == ["switchport", "trunk", "allowed", "vlan"] and len(w) > 4:
            i.trunk_allowed = " ".join(w[4:])
        elif w[:2] == ["switchport", "port-security"]:
            i.port_security = True
        elif w[:2] == ["ip", "address"] and len(w) >= 4 and w[-1] != "secondary":
            i.ip_address, i.ip_mask = w[2], w[3]
        elif w[:2] == ["ip", "unnumbered"]:
            i.ip_unnumbered = True
        elif w[:2] == ["ip", "access-group"] and len(w) >= 4:
            if w[3] == "in":
                i.ip_access_group_in = w[2]
            elif w[3] == "out":
                i.ip_access_group_out = w[2]
        elif t == "no cdp enable":
            i.cdp_enabled = False
        elif t == "no ip proxy-arp":
            i.proxy_arp = False
        elif t == "no ip redirects":
            i.redirects = False
        elif t == "ip directed-broadcast":
            i.directed_broadcast = True
        elif t == "spanning-tree bpduguard enable":
            i.bpduguard = True
        elif w[:2] == ["spanning-tree", "portfast"] and "disable" not in w:
            i.portfast = True
        elif t == "ip dhcp snooping trust":
            i.dhcp_snooping_trust = True
        elif w[:2] == ["tunnel", "source"] and len(w) > 2:
            i.tunnel_source = w[2]
        elif w[:2] == ["tunnel", "destination"] and len(w) > 2:
            i.tunnel_destination = w[2]
    return i


def _strip_seq(entry: str) -> str:
    w = entry.split(None, 1)
    return w[1] if len(w) == 2 and w[0].isdigit() else entry


def _parse_user(t: str) -> User:
    w = t.split()
    u = User(name=w[1] if len(w) > 1 else "", line=t)
    if "privilege" in w and w.index("privilege") + 1 < len(w):
        u.privilege = _int(w[w.index("privilege") + 1], 1) or 1
    for kw in ("secret", "password"):
        if kw in w:
            u.kind = kw
            idx = w.index(kw)
            nxt = w[idx + 1] if idx + 1 < len(w) else None
            u.secret_type = nxt if nxt and nxt.isdigit() and idx + 2 < len(w) else "0"
            break
    else:
        if "nopassword" in w:
            u.kind = "nopassword"
    return u


def _parse_route(t: str) -> Route | None:
    w = t.split()
    i = 2
    vrf = None
    if len(w) > 3 and w[2] == "vrf":
        vrf = w[3]
        i = 4
    if len(w) < i + 3:
        return None
    dest, mask = w[i], w[i + 1]
    nh = intf = None
    rest = w[i + 2:]
    if rest and is_ipv4(rest[0]):
        nh = rest[0]
    elif rest:
        intf = rest[0]
        if len(rest) > 1 and is_ipv4(rest[1]):
            nh = rest[1]
    return Route(dest, mask, nh, intf, t, vrf)


def _numbered_kind(num: str) -> str:
    n = _int(num, 0) or 0
    return "extended" if 100 <= n <= 199 or 2000 <= n <= 2699 else "standard"


def parse_config(text: str) -> ConfigModel:
    nodes = tokenize(text)
    m = ConfigModel(text=text, nodes=nodes)
    for n in nodes:
        t = n.text
        if not t or t == "!" or t == "end":
            continue
        m.global_lines.append(t)
        w = t.split()
        if t.startswith("banner "):
            kind, body = banner_body(t)
            m.banners[kind] = body
        elif w[0] == "hostname" and len(w) > 1:
            m.hostname = w[1]
        elif w[0] == "version" and len(w) > 1:
            m.version = w[1]
        elif w[0] == "service" and len(w) > 1:
            m.services[" ".join(w[1:])] = True
        elif w[:2] == ["no", "service"] and len(w) > 2:
            m.services[" ".join(w[2:])] = False
        elif w[:2] == ["enable", "secret"]:
            m.enable_secret = t
        elif w[:2] == ["enable", "password"]:
            m.enable_password = t
        elif w[0] == "username" and len(w) > 1:
            m.users.append(_parse_user(t))
        elif t == "aaa new-model":
            m.aaa_new_model = True
        elif w[:3] == ["aaa", "common-criteria", "policy"]:
            for c in n.child_texts():
                cw = c.split()
                if cw[:1] == ["min-length"] and len(cw) > 1:
                    v = _int(cw[1])
                    if v is not None:
                        m.common_criteria_min_length = max(v, m.common_criteria_min_length or 0)
            m.aaa_lines.append(t)
        elif w[0] == "aaa":
            m.aaa_lines.append(t)
        elif w[:2] in (["tacacs", "server"], ["radius", "server"]) and len(w) > 2:
            srv = AaaServer(name=w[2], protocol=w[0])
            for c in n.child_texts():
                cw = c.split()
                if cw[:1] == ["address"] and len(cw) > 2:
                    srv.address = cw[2]
                elif cw[:1] == ["key"]:
                    srv.has_key = True
            m.aaa_servers.append(srv)
        elif w[0] in ("tacacs-server", "radius-server") and len(w) > 2 and w[1] == "host":
            m.aaa_servers.append(AaaServer(name=w[2], protocol=w[0].split("-")[0], address=w[2],
                                           has_key="key" in w))
        elif w[:3] == ["security", "passwords", "min-length"] and len(w) > 3:
            m.security_min_length = _int(w[3])
        elif w[0] == "line" and len(w) > 1:
            m.line_blocks.append(_parse_line_block(n))
        elif w[0] == "interface" and len(w) > 1:
            itf = _parse_interface(n)
            m.interfaces[itf.name] = itf
        elif w[:2] == ["ip", "access-list"] and len(w) > 3 and w[2] in ("standard", "extended"):
            m.acls[w[3]] = AccessList(w[3], w[2], False, [_strip_seq(c) for c in n.child_texts()
                                                          if not c.startswith("remark")])
        elif w[0] == "access-list" and len(w) > 2:
            acl = m.acls.setdefault(w[1], AccessList(w[1], _numbered_kind(w[1]), True))
            if w[2] != "remark":
                acl.entries.append(" ".join(w[2:]))
        elif w[:2] == ["snmp-server", "community"] and len(w) > 2:
            c = SnmpCommunity(name=w[2], line=t)
            rest = w[3:]
            if rest and rest[0] == "view":
                rest = rest[2:]
            if rest and rest[0].upper() in ("RO", "RW"):
                c.access = rest[0].upper()
                rest = rest[1:]
            if rest and rest[0] == "ipv6":
                rest = rest[2:]
            if rest:
                c.acl = rest[0]
            m.snmp_communities.append(c)
        elif w[:2] == ["snmp-server", "group"] and len(w) > 3:
            level = w[4] if w[3] == "v3" and len(w) > 4 else None
            m.snmp_groups.append(SnmpGroup(w[2], w[3], level, t))
        elif w[:2] == ["snmp-server", "user"]:
            m.snmp_users.append(t)
        elif w[:2] == ["snmp-server", "host"]:
            m.snmp_hosts.append(t)
        elif w[:2] == ["ntp", "server"] and len(w) > 2:
            addr = w[3] if w[2] == "vrf" and len(w) > 4 else w[2]
            if w[2] == "vrf" and len(w) > 4:
                addr = w[4]
            key = w[w.index("key") + 1] if "key" in w and w.index("key") + 1 < len(w) else None
            m.ntp_servers.append(NtpServer(addr, key, t))
        elif t == "ntp authenticate":
            m.ntp_authenticate = True
        elif w[:2] == ["ntp", "trusted-key"] and len(w) > 2:
            m.ntp_trusted_keys.append(w[2])
        elif w[:2] == ["ntp", "authentication-key"] and len(w) > 3:
            m.ntp_auth_keys[w[2]] = w[3]
        elif t == "no logging on":
            m.logging_on = False
        elif w[:2] == ["logging", "host"] and len(w) > 2:
            addr = w[3] if w[2] in ("ipv4", "ipv6") and len(w) > 3 else w[2]
            m.logging_hosts.append(LoggingHost(addr, t))
        elif w[0] == "logging" and len(w) > 1 and is_ipv4(w[1]):
            m.logging_hosts.append(LoggingHost(w[1], t))
        elif w[:2] == ["logging", "buffered"]:
            m.logging_buffered_line = t
            m.logging_buffered = next((int(x) for x in w[2:] if x.isdigit()), 4096)
        elif t == "no logging buffered":
            m.logging_buffered = 0
            m.logging_buffered_line = t
        elif w[:2] == ["logging", "trap"]:
            lvl = w[2] if len(w) > 2 else "informational"
            m.logging_trap = int(lvl) if lvl.isdigit() else LOG_LEVELS.get(lvl, 6)
        elif t == "no logging trap":
            m.logging_trap = -1
        elif t == "logging userinfo":
            m.logging_userinfo = True
        elif t == "ip http server":
            m.http_server = True
        elif t == "ip http secure-server":
            m.http_secure_server = True
        elif w[:3] == ["ip", "http", "authentication"] and len(w) > 3:
            m.http_auth = w[3]
        elif w[:3] == ["ip", "ssh", "version"] and len(w) > 3:
            m.ssh_version = _int(w[3])
        elif w[:5] == ["ip", "ssh", "server", "algorithm", "mac"]:
            m.ssh_mac = w[5:]
        elif w[:5] == ["ip", "ssh", "server", "algorithm", "encryption"]:
            m.ssh_encryption = w[5:]
        elif w[:2] == ["login", "block-for"] and len(w) >= 7:
            m.login_block_for = {"block_for": _int(w[2], 0), "attempts": _int(w[4], 0), "within": _int(w[6], 0)}
        elif w[:2] == ["login", "on-failure"]:
            m.login_on_failure = True
        elif w[:2] == ["login", "on-success"]:
            m.login_on_success = True
        elif t == "archive":
            m.archive_present = True
            for c in n.children:
                if c.text.startswith("path "):
                    m.archive_path = c.text.split(None, 1)[1]
                if c.text == "log config" and "logging enable" in c.child_texts():
                    m.archive_log_enabled = True
        elif w[:3] == ["event", "manager", "applet"] and len(w) > 3:
            ap = Applet(name=w[3])
            for c in n.child_texts():
                if c.startswith("event "):
                    ap.event = c
                elif c.startswith("action "):
                    ap.actions.append(c)
            m.applets.append(ap)
        elif w[:2] == ["kron", "policy-list"] and len(w) > 2:
            m.kron_policies.append(KronPolicy(w[2], [c[4:] if c.startswith("cli ") else c
                                                     for c in n.child_texts()]))
        elif w[:2] == ["kron", "occurrence"] and len(w) > 2:
            m.kron_occurrences.append(KronOccurrence(w[2], " ".join(w[3:]),
                                                     [c.split()[1] for c in n.child_texts()
                                                      if c.startswith("policy-list ") and len(c.split()) > 1]))
        elif w[:2] == ["ip", "domain-name"] and len(w) > 2:
            m.domain_name = w[2]
        elif w[:3] == ["ip", "domain", "name"] and len(w) > 3:
            m.domain_name = w[3]
        elif w[0] == "crypto" and len(w) > 1 and w[1] in ("key", "pki"):
            m.crypto_key_present = True
        elif w[0] == "vtp" and len(w) > 2:
            m.vtp[w[1]] = " ".join(w[2:])
        elif w[0] == "spanning-tree" and len(w) > 1:
            if w[1] == "mode" and len(w) > 2:
                m.spanning_tree["mode"] = w[2]
            elif t == "spanning-tree portfast bpduguard default":
                m.spanning_tree["portfast_bpduguard_default"] = True
            elif t in ("spanning-tree portfast default", "spanning-tree portfast edge default"):
                m.spanning_tree["portfast_default"] = True
        elif t == "ip dhcp snooping":
            m.dhcp_snooping = True
        elif w[:4] == ["ip", "dhcp", "snooping", "vlan"] and len(w) > 4:
            m.dhcp_snooping_vlans |= parse_vlan_list(" ".join(w[4:]))
        elif w[:2] == ["ip", "route"]:
            r = _parse_route(t)
            if r:
                m.routes.append(r)
        elif t == "ip routing":
            m.ip_routing = True
    return m
