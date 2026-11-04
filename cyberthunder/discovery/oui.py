"""A small built-in OUI table for the vendors that matter on a shipboard enclave. Offline on purpose: the
full IEEE registry is several megabytes and the classifier only needs to tell a Cisco switch from a
hypervisor NIC from a Raspberry Pi. nmap's own vendor string wins when nmap supplies one."""
from __future__ import annotations

from .models import normalize_mac

OUI_VENDORS: dict[str, str] = {
    # Cisco
    "00:00:0c": "Cisco Systems", "00:1a:a1": "Cisco Systems", "00:1b:54": "Cisco Systems",
    "00:26:0b": "Cisco Systems", "58:97:bd": "Cisco Systems", "70:10:5c": "Cisco Systems",
    "f8:72:ea": "Cisco Systems", "00:1e:13": "Cisco Systems", "2c:31:24": "Cisco Systems",
    # VMware
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware", "00:1c:14": "VMware",
    # Dell
    "00:14:22": "Dell", "f8:bc:12": "Dell", "18:66:da": "Dell", "b0:83:fe": "Dell",
    # HP / HPE
    "3c:d9:2b": "Hewlett Packard", "00:1b:78": "Hewlett Packard", "9c:8e:99": "Hewlett Packard",
    "94:57:a5": "Hewlett Packard",
    # Intel
    "00:1b:21": "Intel Corporate", "3c:fd:fe": "Intel Corporate", "a0:36:9f": "Intel Corporate",
    "8c:8d:28": "Intel Corporate",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi Trading", "e4:5f:01": "Raspberry Pi Trading",
    "d8:3a:dd": "Raspberry Pi Trading", "28:cd:c1": "Raspberry Pi Trading",
    # Microsoft / Hyper-V virtual NICs
    "00:15:5d": "Microsoft (Hyper-V)", "00:03:ff": "Microsoft",
    # QEMU / KVM and VirtualBox virtual NICs
    "52:54:00": "QEMU/KVM virtual NIC", "08:00:27": "Oracle VirtualBox virtual NIC",
    "0a:00:27": "Oracle VirtualBox virtual NIC",
}

CISCO_HINTS = ("cisco",)
RPI_HINTS = ("raspberry",)
PRINTER_HINTS = ("hewlett packard", "brother", "lexmark", "xerox", "canon", "kyocera", "ricoh")


def vendor_for(mac: str | None) -> str | None:
    m = normalize_mac(mac)
    if not m:
        return None
    return OUI_VENDORS.get(m[:8])


def is_locally_administered(mac: str | None) -> bool:
    """Randomized / locally assigned MACs carry no vendor; worth noting on a managed enclave."""
    m = normalize_mac(mac)
    return bool(m) and bool(int(m[:2], 16) & 0x02)


def vendor_matches(vendor: str | None, hints: tuple[str, ...]) -> bool:
    v = (vendor or "").lower()
    return any(h in v for h in hints)


# Virtual NIC prefixes and the hypervisor platform they imply. A VM is still a real asset to inventory,
# but knowing it is virtual tells the operator where its console and snapshots live.
VIRTUAL_PLATFORMS: dict[str, str] = {
    "00:50:56": "vmware", "00:0c:29": "vmware", "00:05:69": "vmware", "00:1c:14": "vmware",
    "00:15:5d": "hyperv",
    "52:54:00": "kvm",
    "08:00:27": "virtualbox", "0a:00:27": "virtualbox",
}


def virtual_platform(mac: str | None) -> str | None:
    m = normalize_mac(mac)
    return VIRTUAL_PLATFORMS.get(m[:8]) if m else None


def tag_virtual(asset, platform: str | None = None) -> str | None:
    """Record virtual:<platform> in the asset's evidence, notes and facts. Idempotent. Returns the platform."""
    platform = platform or virtual_platform(getattr(asset, "mac", None))
    if not platform:
        return None
    tag = f"virtual:{platform}"
    asset.facts["virtual_platform"] = platform
    if not any(e.startswith(tag) for e in asset.evidence):
        if asset.mac and virtual_platform(asset.mac) == platform:
            asset.evidence.append(f"{tag}: MAC prefix {asset.mac[:8]} is a {platform} virtual NIC")
        else:
            asset.evidence.append(f"{tag}: listed by the {platform} hypervisor")
    if tag not in (asset.notes or ""):
        asset.notes = (asset.notes + "; " if asset.notes else "") + tag
    return platform
