"""Parsers and command builders, from recorded fixtures only."""
from __future__ import annotations

import pytest

from cyberthunder.discovery.classify import apply_classification
from cyberthunder.discovery.models import DiscoveryScope
from cyberthunder.discovery.oui import tag_virtual, virtual_platform
from cyberthunder.discovery.sources import active_directory as ad
from cyberthunder.discovery.sources import hypervisor as hv
from cyberthunder.discovery.sources import kube, neighbors, network_gear, nmap
from cyberthunder.transport.fixture import FixtureTransport


def _by_addr(assets):
    return {a.address: a for a in assets}


# -- nmap ---------------------------------------------------------------------------------------

def test_nmap_xml_hosts(fix):
    assets = _by_addr(nmap.parse_xml((fix / "nmap_full.xml").read_text(encoding="utf-8")))
    assert "192.168.56.77" not in assets                    # down host skipped
    assert len(assets) == 8
    sw = assets["192.168.56.2"]
    assert sw.mac == "70:10:5c:aa:bb:01" and sw.vendor == "Cisco Systems" and sw.hostname == "sw-core-01"
    assert sw.port_keys == {"22/tcp", "23/tcp"} and "cpe:/o:cisco:ios" in sw.facts["cpes"]
    linux = assets["192.168.56.10"]
    assert linux.os_guess == "Linux 5.0 - 5.14" and linux.os_accuracy == 95
    assert linux.port_keys == {"22/tcp"}                     # closed 9090 ignored
    assert linux.facts["uptime_s"] == 86400
    win = assets["192.168.56.11"]
    assert win.facts["netbios_name"] == "WIN11-WS01" and win.hostname == "WIN11-WS01"
    k8s = assets["192.168.56.20"]
    assert any(p.service == "ssl/http" and p.port == 6443 for p in k8s.open_ports)


def test_nmap_smb_os_discovery(fix):
    dc = _by_addr(nmap.parse_xml((fix / "nmap_full.xml").read_text(encoding="utf-8")))["192.168.56.40"]
    assert dc.os_guess == "Windows Server 2019 Standard 17763"
    assert dc.facts["nmap_os_match"] == "Microsoft Windows Server 2016 - 2019"
    assert dc.hostname == "DC01.fleet.lab"
    assert dc.facts["netbios_name"] == "DC01" and dc.facts["domain"] == "fleet.lab"
    assert any(e.startswith("smb-os-discovery: OS Windows Server 2019") and "domain fleet.lab" in e for e in dc.evidence)


def test_nmap_virtual_platform_tags(fix):
    assets = _by_addr(nmap.parse_xml((fix / "nmap_full.xml").read_text(encoding="utf-8")))
    expect = {"192.168.56.10": "kvm", "192.168.56.11": "hyperv", "192.168.56.20": "vmware",
              "192.168.56.30": "virtualbox", "192.168.56.40": "hyperv"}
    for addr, plat in expect.items():
        a = assets[addr]
        assert a.facts["virtual_platform"] == plat
        assert f"virtual:{plat}" in a.notes
        assert any(e.startswith(f"virtual:{plat}") for e in a.evidence)
    assert "virtual_platform" not in assets["192.168.56.2"].facts
    assert virtual_platform("00-50-56-01-02-03") == "vmware"
    tag_virtual(assets["192.168.56.10"])                     # idempotent
    assert assets["192.168.56.10"].notes.count("virtual:kvm") == 1


def test_nmap_rejects_entities():
    with pytest.raises(ValueError):
        nmap.parse_xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')
    with pytest.raises(ValueError):
        nmap.parse_xml("<notnmap/>")


def test_live_hosts(fix):
    hosts = nmap.live_hosts((fix / "nmap_ping.xml").read_text(encoding="utf-8"))
    assert len(hosts) == 8 and hosts[0] == "192.168.56.2"


# -- command table ------------------------------------------------------------------------------

def test_command_table_quick_full_privileged():
    scope = DiscoveryScope(cidr="192.168.56.0/24")
    assert nmap.build_ping_command([scope]) == ["nmap", "-sn", "-T3", "--max-rate", "50", "-n", "-oX", "-",
                                                "192.168.56.0/24"]
    quick = nmap.build_command([scope], "quick", privileged=True, hosts=["192.168.56.10"])
    assert quick == ["nmap", "-sV", "--top-ports", "25", "-T3", "--max-rate", "50", "-n", "-oX", "-", "192.168.56.10"]
    full = nmap.build_command([scope], "full", privileged=False)
    assert "--script" in full and full[full.index("--script") + 1] == "smb-os-discovery"
    assert "-O" not in full
    assert "-O" in nmap.build_command([scope], "full", privileged=True)
    scripts = [full[i + 1] for i, x in enumerate(full) if x == "--script"]
    assert scripts == ["smb-os-discovery"]                   # the only NSE script anywhere
    assert "--script" not in quick
    assert nmap.render(full) == " ".join(full)


def test_command_table_refusals():
    with pytest.raises(ValueError, match="not private"):
        nmap.build_ping_command(["8.8.8.0/24"])
    ok = DiscoveryScope(cidr="8.8.8.0/24", allow_public=True, reason="range ISP block, authorized")
    assert nmap.build_ping_command([ok])[-1] == "8.8.8.0/24"
    with pytest.raises(ValueError, match="reason"):
        DiscoveryScope(cidr="8.8.8.0/24", allow_public=True).validate()
    with pytest.raises(ValueError, match="too large"):
        nmap.build_ping_command(["10.0.0.0/8"])
    with pytest.raises(ValueError, match="outside"):
        nmap.build_command(["192.168.56.0/24"], hosts=["192.168.57.1"])
    with pytest.raises(ValueError, match="not an IP"):
        nmap.build_command(["192.168.56.0/24"], hosts=["192.168.56.1;id"])
    with pytest.raises(ValueError, match="unknown nmap mode"):
        nmap.build_command(["192.168.56.0/24"], mode="aggressive")
    with pytest.raises(ValueError, match="unsafe"):
        nmap.render(["nmap", "-sn", "$(reboot)"])


# -- passive sources ----------------------------------------------------------------------------

def test_neighbor_formats(fix):
    ip_neigh = _by_addr(neighbors.parse_neighbors((fix / "ip_neigh.txt").read_text()))
    assert "192.168.56.88" not in ip_neigh and "192.168.56.255" not in ip_neigh
    assert ip_neigh["192.168.56.66"].vendor.startswith("Raspberry Pi")
    arp_l = _by_addr(neighbors.parse_neighbors((fix / "arp_linux.txt").read_text()))
    assert arp_l["192.168.56.10"].hostname == "rocky9-app01" and set(arp_l) == {"192.168.56.2", "192.168.56.10"}
    arp_w = _by_addr(neighbors.parse_neighbors((fix / "arp_windows.txt").read_text()))
    assert set(arp_w) == {"192.168.56.2", "192.168.56.10"}
    assert arp_w["192.168.56.2"].facts["interface"] == "192.168.56.5"
    ps = _by_addr(neighbors.parse_neighbors((fix / "netneighbor.json").read_text()))
    assert set(ps) == {"192.168.56.2", "192.168.56.10"}


def test_hosts_and_known_hosts(fix):
    hosts = _by_addr(neighbors.parse_hosts_file((fix / "scanner" / "files" / "etc" / "hosts").read_text()))
    assert hosts["192.168.56.10"].hostname == "rocky9-app01" and hosts["192.168.56.10"].facts["aliases"] == ["rocky9"]
    kh = neighbors.parse_known_hosts((fix / "known_hosts").read_text())
    assert [(a.address, a.hostname) for a in kh] == [("192.168.56.10", "rocky9-app01"), ("192.168.56.30", None)]
    assert kh[1].facts["ssh_port"] == 2222
    assert all("AAAA" not in str(a.to_dict()) for a in kh)    # key material never kept


# -- switch tables ------------------------------------------------------------------------------

def test_cdp_lldp_arp_mac(fix):
    g = fix / "gear"
    cdp = network_gear.parse_cdp_detail((g / "cdp.txt").read_text())
    assert [a.hostname for a in cdp] == ["SW-SPARE-03", "SEP001122334455"]
    assert cdp[0].facts["platform_type"] == "cisco_ios" and cdp[0].facts["remote_port"] == "GigabitEthernet0/1"
    lldp = network_gear.parse_lldp_detail((g / "lldp.txt").read_text())
    assert [(a.address, a.facts.get("platform_type")) for a in lldp] == [("192.168.56.10", "linux"),
                                                                         ("192.168.56.11", "windows")]
    assert lldp[0].mac == "52:54:00:12:34:10"
    arp = network_gear.parse_show_ip_arp((g / "arp.txt").read_text())
    assert arp[0]["own"] is True and len(arp) == 5
    mac = network_gear.parse_mac_table((g / "mac.txt").read_text())
    assert {r["port"] for r in mac} == {"Gi1/0/10", "Gi1/0/17", "Gi1/0/18"}
    merged = _by_addr(network_gear.assets_from_gear({k: (g / f"{k}.txt").read_text() for k in ("cdp", "lldp", "arp", "mac")},
                                                    seen_by="sw-core-01"))
    assert "192.168.56.2" not in merged                       # the switch's own SVI
    assert merged["192.168.56.66"].facts["switch_port"] == "Gi1/0/17"
    assert merged["192.168.56.10"].facts["seen_by"] == "sw-core-01"
    assert set(merged["192.168.56.10"].sources) == {"lldp", "switch_arp"}


def test_kube_nodes(fix):
    nodes = kube.parse_nodes((fix / "kube_nodes.json").read_text())
    assert [n.address for n in nodes] == ["192.168.56.20", "192.168.56.21"]
    cp = nodes[0]
    assert cp.facts["roles"] == ["control-plane", "master"] and cp.facts["kubelet_version"] == "v1.29.4+k3s1"
    assert nodes[1].facts["ready"] is False and nodes[1].os_guess.startswith("Rocky Linux 8.9")
    assert apply_classification(cp).asset_type_guess == "kubernetes"


# -- directory and hypervisors ------------------------------------------------------------------

def test_active_directory(fix):
    comps = ad.parse_ad_computers((fix / "ad_computers.json").read_text(encoding="utf-8"))
    assert len(comps) == 6
    enabled = [c for c in comps if c.facts["ad_enabled"]]
    assert sorted(c.facts["windows_role"] for c in enabled) == ["server", "server", "workstation", "workstation",
                                                                "workstation"]
    disabled = [c for c in comps if not c.facts["ad_enabled"]]
    assert len(disabled) == 1 and "disabled computer account" in disabled[0].notes
    assert disabled[0].address is None and disabled[0].id
    dc = next(c for c in comps if c.facts["ad_name"] == "DC01")
    assert dc.address == "192.168.56.40" and dc.notes == "server"
    assert any("Windows Server 2019 Standard" in e and "(server)" in e for e in dc.evidence)
    assert dc.facts["last_logon"].startswith("2026-11-")
    assert all(apply_classification(c).asset_type_guess == "windows" for c in comps)
    single = ad.parse_ad_computers('{"Name": "X1", "IPv4Address": "10.1.1.1", "OperatingSystem": "Windows 11 Pro", "Enabled": true}')
    assert len(single) == 1 and single[0].facts["windows_role"] == "workstation"


def test_hyperv(fix):
    vms = {v.hostname: v for v in hv.parse_hyperv_vms((fix / "hyperv_vms.json").read_text(), host="hv01")}
    assert set(vms) == {"rocky9-app01", "WIN11-WS02", "old-build-box", "lab-template"}
    assert vms["rocky9-app01"].address == "192.168.56.21" and vms["WIN11-WS02"].address == "192.168.56.12"
    off = vms["old-build-box"]
    assert off.address is None and not off.open_ports and off.facts["power_state"] == "Off"
    assert any(e.startswith("status offline") for e in off.evidence)
    assert all("virtual:hyperv" in v.notes for v in vms.values())
    assert vms["lab-template"].mac is None and vms["lab-template"].id != off.id


def test_vmware(fix):
    t = FixtureTransport(fix / "vmware")
    paths = hv.parse_vmrun_list(t.run(hv.VMRUN_LIST).stdout)
    assert len(paths) == 3
    assets, errors = hv.assets_from_vmware(t.run(hv.VMRUN_LIST).stdout, t.read_file, host="ws-host")
    by = {a.hostname: a for a in assets}
    assert by["rocky9-lab"].mac == "00:0c:29:9a:01:10" and by["rocky9-lab"].os_guess == "Red Hat Enterprise Linux 9"
    assert by["win11-lab"].mac == "00:50:56:3f:00:11" and by["win11-lab"].os_guess == "Windows 11"
    assert all("virtual:vmware" in a.notes for a in assets)
    assert len(errors) == 1 and "gone.vmx" in errors[0]
    assert apply_classification(by["rocky9-lab"]).asset_type_guess == "linux"
