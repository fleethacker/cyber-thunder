"""Classifier expectations: every host type in the nmap fixture, the simulated enclave and the thresholds."""
from __future__ import annotations

from cyberthunder.discovery.classify import DECISIVE, IOT_NOTE, apply_classification, classify
from cyberthunder.discovery.models import DiscoveredAsset, OpenPort
from cyberthunder.discovery.simulated import SimulatedSweep
from cyberthunder.discovery.sources import nmap

EXPECTED = {
    "192.168.56.2": "cisco_ios",
    "192.168.56.10": "linux",
    "192.168.56.11": "windows",
    "192.168.56.20": "kubernetes",
    "192.168.56.30": "containers",
    "192.168.56.40": "windows",
    "192.168.56.50": "unknown",      # printer
    "192.168.56.66": "unknown",      # Raspberry Pi
}


def test_nmap_fixture_types(fix):
    assets = {a.address: apply_classification(a) for a in nmap.parse_xml((fix / "nmap_full.xml").read_text(encoding="utf-8"))}
    assert {k: a.asset_type_guess for k, a in assets.items()} == EXPECTED
    for addr in ("192.168.56.50", "192.168.56.66"):
        assert IOT_NOTE in assets[addr].notes and assets[addr].facts["iot"] is True
    for a in assets.values():
        assert any(e.startswith("classify: ") for e in a.evidence)
        assert 0 < a.confidence <= 0.99


def test_simulated_enclave_types_match_inventory_types():
    sim = SimulatedSweep()
    got = {a.hostname or a.address: apply_classification(a).asset_type_guess for a in sim.assets()}
    assert got["sim-linux-01"] == "linux" and got["sim-win-01"] == "windows"
    assert got["sim-switch-01"] == "cisco_ios" and got["sim-k8s-01"] == "kubernetes"
    assert got["sim-docker-01"] == "containers" and got["SW-SPARE-03"] == "cisco_ios"
    pi = next(a for a in sim.assets() if a.address == "192.168.56.66")
    assert classify(pi).iot


def test_insufficient_evidence_is_unknown():
    a = DiscoveredAsset(address="192.168.56.90", open_ports=[OpenPort(80, "tcp", "http", "nginx")])
    c = classify(a)
    assert c.asset_type == "unknown" and c.confidence < DECISIVE
    assert any("insufficient evidence" in r for r in c.reasons)


def test_reclassify_replaces_reasons():
    a = DiscoveredAsset(address="192.168.56.91", open_ports=[OpenPort(3389, "tcp"), OpenPort(445, "tcp")])
    apply_classification(a)
    n = len(a.evidence)
    apply_classification(a)
    assert len(a.evidence) == n and a.asset_type_guess == "windows"
