"""Data shapes for discovery. Plain dataclasses with to_dict/from_dict so they persist as JSON under
<state_dir>/discovery/ and travel over the API unchanged."""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from cyberthunder.findings.schema import utcnow

ASSET_TYPE_GUESSES = ("linux", "windows", "cisco_ios", "kubernetes", "containers", "unknown")
ASSET_STATUSES = ("new", "known", "ignored", "missing")
RUN_MODES = ("quick", "full", "simulated", "passive")
RUN_STATUSES = ("running", "finished", "partial", "failed", "stopped")


def _known(cls, d: dict) -> dict:
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in d.items() if k in names}


def normalize_mac(mac: str | None) -> str | None:
    """Accepts aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF and Cisco aabb.ccdd.eeff; returns aa:bb:cc:dd:ee:ff."""
    if not mac:
        return None
    hexdigits = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(hexdigits) != 12 or hexdigits in ("000000000000", "ffffffffffff"):
        return None
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def asset_id_for(mac: str | None, address: str | None) -> str:
    key = (normalize_mac(mac) or (address or "")).lower()
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


@dataclass
class OpenPort:
    port: int
    proto: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""

    @property
    def key(self) -> str:
        return f"{self.port}/{self.proto}"

    def label(self) -> str:
        detail = " ".join(x for x in (self.product, self.version) if x)
        return f"{self.key} {self.service}{(' ' + detail) if detail else ''}".strip()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "OpenPort":
        d = _known(cls, dict(d))
        d["port"] = int(d.get("port", 0))
        return cls(**d)


@dataclass
class DiscoveredAsset:
    address: str | None = None
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    open_ports: list[OpenPort] = field(default_factory=list)
    os_guess: str | None = None
    os_accuracy: int | None = None
    asset_type_guess: str = "unknown"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)
    status: str = "new"
    inventory_target_id: str | None = None
    notes: str = ""
    # source-specific facts: osclass, CDP/LLDP platform, kubelet version, snmp sysDescr, switch port ...
    facts: dict = field(default_factory=dict)
    # what differs from the inventory or the previous sweep: [{kind, detail, ...}]
    changes: list[dict] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        self.mac = normalize_mac(self.mac)
        self.open_ports = [p if isinstance(p, OpenPort) else OpenPort.from_dict(p) for p in self.open_ports]
        if not self.id:
            self.id = asset_id_for(self.mac, self.address)

    @property
    def port_keys(self) -> set[str]:
        return {p.key for p in self.open_ports}

    def has_port(self, port: int, proto: str = "tcp") -> bool:
        return any(p.port == port and p.proto == proto for p in self.open_ports)

    def add_source(self, source: str) -> None:
        if source and source not in self.sources:
            self.sources.append(source)

    def merge(self, other: "DiscoveredAsset") -> "DiscoveredAsset":
        """Fold another observation of the same device into this one (fill gaps, union ports/evidence)."""
        for attr in ("address", "hostname", "mac", "vendor", "os_guess", "os_accuracy"):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
        have = {p.key: p for p in self.open_ports}
        for p in other.open_ports:
            cur = have.get(p.key)
            if cur is None:
                self.open_ports.append(p)
                have[p.key] = p
                continue
            for a in ("service", "product", "version", "banner"):
                if not getattr(cur, a) and getattr(p, a):
                    setattr(cur, a, getattr(p, a))
        self.open_ports.sort(key=lambda p: (p.proto, p.port))
        for e in other.evidence:
            if e not in self.evidence:
                self.evidence.append(e)
        for s in other.sources:
            self.add_source(s)
        for k, v in other.facts.items():
            self.facts.setdefault(k, v)
        return self

    def summary(self) -> str:
        ports = ", ".join(p.label() for p in self.open_ports) or "none"
        return (f"address={self.address or '-'} mac={self.mac or '-'} vendor={self.vendor or '-'} "
                f"hostname={self.hostname or '-'} ports=[{ports}]")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["open_ports"] = [p.to_dict() for p in self.open_ports]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DiscoveredAsset":
        d = _known(cls, dict(d))
        d["open_ports"] = [OpenPort.from_dict(p) for p in d.get("open_ports", [])]
        return cls(**d)


# Address space a sweep may touch without an explicit, audited allow_public decision.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # RFC 1918
    "169.254.0.0/16", "127.0.0.0/8",                      # link-local, loopback
    "fc00::/7", "fe80::/10", "::1/128",                   # IPv6 unique-local, link-local, loopback
))
# Largest sweep accepted in one scope: a /16 (65,536 addresses) for IPv4, a /112 for IPv6.
MAX_PREFIX = {4: 16, 6: 112}


def is_private_network(net) -> bool:
    return any(net.version == p.version and net.subnet_of(p) for p in PRIVATE_NETWORKS)


def parse_network(cidr: str):
    try:
        return ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"invalid CIDR {cidr!r}: {e}") from None


def network_normalization(value: str):
    """Expose a host-bit CIDR's wider network before it becomes a saved authorization."""
    text = str(value).strip()
    net = parse_network(text)
    if "/" in text and ipaddress.ip_interface(text).ip != net.network_address:
        return {"input": text, "normalized": str(net)}
    return None


@dataclass
class DiscoveryScope:
    cidr: str
    allow_public: bool = False
    added_by: str = ""
    added_at: str = field(default_factory=utcnow)
    reason: str = ""
    scanner_target: str | None = None   # inventory target (ssh) that runs nmap from inside the enclave

    def __post_init__(self) -> None:
        self._normalization = network_normalization(self.cidr)
        self.cidr = str(parse_network(self.cidr))

    @property
    def network(self):
        return parse_network(self.cidr)

    def validate(self) -> None:
        """Raise ValueError unless this scope is safe to sweep."""
        net = self.network
        if net.prefixlen < MAX_PREFIX[net.version]:
            raise ValueError(f"scope {net} is too large; split it into /{MAX_PREFIX[net.version]} or smaller")
        if not is_private_network(net):
            if not self.allow_public:
                raise ValueError(f"scope {net} is not private, link-local or loopback address space; "
                                 "save it with allow_public and a reason if this is intended")
            if not (self.reason or "").strip():
                raise ValueError(f"scope {net} is public address space; a reason is required")

    def contains(self, address: str | None) -> bool:
        if not address:
            return False
        try:
            return ipaddress.ip_address(address) in self.network
        except ValueError:
            return False

    def covers(self, other: "DiscoveryScope") -> bool:
        a, b = self.network, other.network
        return a.version == b.version and b.subnet_of(a)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Any) -> "DiscoveryScope":
        if isinstance(d, str):
            return cls(cidr=d)
        return cls(**_known(cls, dict(d)))


@dataclass
class DiscoveryRun:
    id: str
    mode: str = "quick"
    status: str = "running"
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    scopes: list[str] = field(default_factory=list)
    hosts_seen: int = 0
    new: int = 0
    known: int = 0
    changed: int = 0
    missing: int = 0
    errors: list[str] = field(default_factory=list)
    requested_by: str = ""
    asset_ids: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {"hosts_seen": self.hosts_seen, "new": self.new, "known": self.known,
                "changed": self.changed, "missing": self.missing}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DiscoveryRun":
        return cls(**_known(cls, dict(d)))
