"""Deterministic asset typing from evidence.

Every rule that fires adds a weight to one type and a reason to the asset's evidence, so an operator can
see exactly why a host was called a Cisco switch. No model is involved.

Decision, in order:
  1. Specific types (cisco_ios, kubernetes, containers, consumer/IoT) win when their score reaches
     DECISIVE (0.5). Several over the line: highest score; a tie goes to PRECEDENCE order.
  2. Otherwise the generic OS types (windows, linux) win when their score reaches MIN_TYPED (0.5).
  3. Otherwise the asset is "unknown" with its best score as confidence and "insufficient evidence".
Confidence is the winning score capped at 0.99. Consumer/IoT devices (printers, single-board computers)
are typed "unknown" with the note "consumer/iot device" because no adapter manages them; that note is
what raises the consumer/IoT finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import DiscoveredAsset
from .oui import CISCO_HINTS, RPI_HINTS, vendor_matches

DECISIVE = 0.5
MIN_TYPED = 0.5
MAX_CONFIDENCE = 0.99
PRECEDENCE = ("cisco_ios", "kubernetes", "containers", "iot", "windows", "linux")
SPECIFIC = ("cisco_ios", "kubernetes", "containers", "iot")
GENERIC = ("windows", "linux")
IOT_NOTE = "consumer/iot device"

_LINUX_DISTRO = re.compile(r"ubuntu|debian|\bel\d|red ?hat|rhel|rocky|alma|centos|fedora|suse|raspbian", re.I)
_PRINTER = re.compile(r"jetdirect|printer|laserjet|officejet|hp-chaisoe|ipp|cups|brother|lexmark|xerox", re.I)


@dataclass
class Classification:
    asset_type: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    iot: bool = False


def _score(asset: DiscoveredAsset) -> tuple[dict[str, float], list[str]]:
    scores = {t: 0.0 for t in PRECEDENCE}
    reasons: list[str] = []

    def add(t: str, w: float, why: str) -> None:
        scores[t] += w
        reasons.append(f"{t} +{w:.2f}: {why}")

    tcp = {p.port for p in asset.open_ports if p.proto == "tcp"}
    by_port = {p.port: p for p in asset.open_ports}
    products = " ".join(f"{p.product} {p.version} {p.banner}" for p in asset.open_ports).lower()
    facts = asset.facts
    ostypes = " ".join(facts.get("service_ostypes", [])).lower()
    cpes = " ".join(facts.get("cpes", [])).lower()
    osclass = facts.get("osclass", [])
    acc = (asset.os_accuracy or 100) / 100.0
    os_text = (asset.os_guess or "").lower() + " " + " ".join(
        f"{c.get('vendor', '')} {c.get('family', '')}" for c in osclass).lower()
    platform_type = facts.get("platform_type")

    # -- Cisco IOS / IOS-XE ----------------------------------------------------------------------
    cisco_vendor = vendor_matches(asset.vendor, CISCO_HINTS)
    if cisco_vendor:
        add("cisco_ios", 0.35, f"MAC vendor {asset.vendor}")
    if platform_type == "cisco_ios":
        add("cisco_ios", 0.6, f"CDP/LLDP platform '{facts.get('platform') or facts.get('system_description', '')[:60]}'")
    ssh = by_port.get(22)
    if ssh and "cisco" in f"{ssh.product} {ssh.banner}".lower():
        add("cisco_ios", 0.4, f"SSH banner '{ssh.product} {ssh.version}'".strip())
    if "cisco" in (facts.get("snmp_sysdescr") or "").lower():
        add("cisco_ios", 0.5, "SNMP sysDescr names Cisco IOS")
    if {22, 23} <= tcp and cisco_vendor:
        add("cisco_ios", 0.2, "SSH and telnet both open on Cisco hardware")
    if "ios" in ostypes.split() or "cpe:/o:cisco:ios" in cpes or "cisco" in os_text:
        add("cisco_ios", 0.5, "nmap reports Cisco IOS")

    # -- Kubernetes ------------------------------------------------------------------------------
    for port, w, what in ((6443, 0.5, "Kubernetes API server"), (10250, 0.4, "kubelet API"), (2379, 0.3, "etcd client")):
        if port in tcp:
            add("kubernetes", w, f"tcp/{port} open ({what})")
    if re.search(r"\bk3s\b|kubernetes|kubelet", products):
        add("kubernetes", 0.3, "service product names Kubernetes")
    if "kubernetes" in asset.sources:
        add("kubernetes", 0.8, "listed as a node by a cluster in the inventory")

    # -- Container hosts -------------------------------------------------------------------------
    for port, what in ((2375, "Docker/Podman API, plain text"), (2376, "Docker/Podman API, TLS")):
        if port in tcp:
            add("containers", 0.6, f"tcp/{port} open ({what})")
    if re.search(r"docker|podman", products):
        add("containers", 0.4, "service product names Docker/Podman")

    # -- Consumer / IoT --------------------------------------------------------------------------
    rpi = vendor_matches(asset.vendor, RPI_HINTS)
    if 9100 in tcp:
        add("iot", 0.5, "tcp/9100 open (raw printing)")
    if 631 in tcp:
        add("iot", 0.3, "tcp/631 open (IPP printing)")
    if _PRINTER.search(products) or any(c.get("type") == "printer" for c in osclass):
        add("iot", 0.4, "printer service or device class")
    if rpi:
        add("iot", 0.4, f"MAC vendor {asset.vendor}")
    if rpi and 23 in tcp:
        add("iot", 0.3, "telnet open on a single-board computer")

    # -- Windows ---------------------------------------------------------------------------------
    for port, w, what in ((3389, 0.3, "RDP"), (445, 0.25, "SMB"), (135, 0.2, "MS RPC"), (139, 0.1, "NetBIOS"),
                          (5985, 0.25, "WinRM HTTP"), (5986, 0.25, "WinRM HTTPS")):
        if port in tcp:
            add("windows", w, f"tcp/{port} open ({what})")
    if "windows" in os_text:
        add("windows", round(0.5 * acc, 2), f"OS match '{asset.os_guess}' ({asset.os_accuracy or '?'}%)")
    if "windows" in ostypes or "cpe:/o:microsoft:windows" in cpes:
        add("windows", 0.3, "service OS type Windows")
    if "microsoft" in products:
        add("windows", 0.2, "Microsoft service products")
    if facts.get("netbios_name"):
        add("windows", 0.2, f"NetBIOS name {facts['netbios_name']}")
    if platform_type == "windows":
        add("windows", 0.4, "LLDP system description names Windows")
    if ssh and "for_windows" in f"{ssh.version} {ssh.banner}".lower():
        add("windows", 0.3, "OpenSSH for Windows")

    # -- Linux -----------------------------------------------------------------------------------
    if "linux" in os_text and "cisco" not in os_text:
        add("linux", round(0.5 * acc, 2), f"OS match '{asset.os_guess}' ({asset.os_accuracy or '?'}%)")
    if "linux" in ostypes or "cpe:/o:linux:linux_kernel" in cpes:
        add("linux", 0.3, "service OS type Linux")
    if ssh and "openssh" in ssh.product.lower() and "for_windows" not in f"{ssh.version} {ssh.banner}".lower():
        if _LINUX_DISTRO.search(f"{ssh.version} {ssh.banner}"):
            add("linux", 0.4, f"SSH banner '{ssh.product} {ssh.version}' names a Linux distribution")
        else:
            add("linux", 0.3, f"SSH banner '{ssh.product} {ssh.version}'".strip())
    if platform_type == "linux":
        add("linux", 0.4, "LLDP system description names Linux")
    if _LINUX_DISTRO.search(facts.get("os_image", "") or "") or "linux" == (facts.get("operating_system") or ""):
        add("linux", 0.3, f"node OS image '{facts.get('os_image')}'")

    return {k: round(v, 2) for k, v in scores.items()}, reasons


def _pick(scores: dict[str, float], candidates: tuple[str, ...], threshold: float) -> str | None:
    over = [t for t in candidates if scores[t] >= threshold]
    if not over:
        return None
    best = max(scores[t] for t in over)
    return next(t for t in PRECEDENCE if t in over and scores[t] == best)


def classify(asset: DiscoveredAsset) -> Classification:
    scores, reasons = _score(asset)
    winner = _pick(scores, SPECIFIC, DECISIVE) or _pick(scores, GENERIC, MIN_TYPED)
    if winner is None:
        best = max(scores.values()) if scores else 0.0
        return Classification("unknown", round(min(best, MAX_CONFIDENCE), 2),
                              reasons + ["unknown: insufficient evidence to type this asset"], scores)
    conf = round(min(scores[winner], MAX_CONFIDENCE), 2)
    if winner == "iot":
        return Classification("unknown", conf, reasons + [f"unknown: {IOT_NOTE}"], scores, iot=True)
    return Classification(winner, conf, reasons, scores)


def apply_classification(asset: DiscoveredAsset) -> DiscoveredAsset:
    """Classify and record the result and every reason on the asset."""
    c = classify(asset)
    asset.asset_type_guess, asset.confidence = c.asset_type, c.confidence
    asset.evidence = [e for e in asset.evidence if not e.startswith("classify: ")]
    asset.evidence.extend(f"classify: {r}" for r in c.reasons)
    asset.facts["type_scores"] = c.scores
    if c.iot:
        asset.facts["iot"] = True
        if IOT_NOTE not in asset.notes:
            asset.notes = (asset.notes + "; " if asset.notes else "") + IOT_NOTE
    else:
        asset.facts.pop("iot", None)
    return asset
