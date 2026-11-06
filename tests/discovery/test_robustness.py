"""Discovery under bad conditions: failed or partial nmap runs, odd tool output, re-keyed assets, interrupted
runs, stale accepts and an empty inventory."""
from __future__ import annotations

import argparse
import json
import time

import pytest

from cyberthunder.discovery.models import DiscoveredAsset, DiscoveryRun, DiscoveryScope, OpenPort, asset_id_for
from cyberthunder.discovery.service import DiscoveryService, _RunLock
from cyberthunder.discovery.sources import active_directory, hypervisor, nmap
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.fixture import FixtureTransport

from .conftest import add_targets

SCOPE = "10.1.1.0/24"
PING_UP = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
           '<address addr="10.1.1.5" addrtype="ipv4"/></host></nmaprun>')
PING_NONE = '<?xml version="1.0"?><nmaprun></nmaprun>'


def _scanner(tmp_path, entries) -> FixtureTransport:
    root = tmp_path / "scan"
    root.mkdir(exist_ok=True)
    (root / "commands.json").write_text(json.dumps(entries), encoding="utf-8")
    return FixtureTransport(root)


def _svc(ctx, tmp_path, entries) -> DiscoveryService:
    add_targets(ctx, Target(id="lx", name="lx", asset_type="linux", address="10.1.1.5"))
    svc = DiscoveryService(ctx)
    svc.set_scopes([SCOPE], "it1.jones", "enclave B")
    svc.local_transport_factory = lambda: _scanner(tmp_path, entries)
    return svc


def test_port_scan_timeout_keeps_ping_hosts_and_marks_run_partial(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [{"regex": " -sn ", "stdout": PING_UP},
                               {"regex": "-sV", "stdout": "", "stderr": "timed out", "exit": 124}])
    run = svc.sweep(mode="quick", actor="it1.jones", background=False)
    assert run.status == "partial"
    assert run.missing == 0 and run.known == 1 and run.hosts_seen == 1
    assert any("timed out" in e for e in run.errors)
    assert not [f for f in svc.findings(run.id) if f.rule_id == "discovery:missing_asset"]
    assert ctx.audit.verify().ok


def test_ping_failure_never_reports_the_scope_missing(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [{"regex": "nmap", "stdout": "", "stderr": "timed out", "exit": 124}])
    run = svc.sweep(mode="quick", actor="it1.jones", background=False)
    assert run.status == "partial" and run.missing == 0
    assert any(SCOPE in e and "failed" in e for e in run.errors)
    assert svc.counts()["missing"] == 0


def test_empty_ping_sweep_still_reports_missing(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [{"regex": " -sn ", "stdout": PING_NONE}])
    run = svc.sweep(mode="quick", actor="it1.jones", background=False)
    assert run.status == "finished" and run.missing == 1


BAD_XML = ('<?xml version="1.0"?><nmaprun>'
           '<host><status state="up"/><address addr="10.1.1.5" addrtype="ipv4"/>'
           '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>'
           '<uptime seconds="12x"/></host>'
           '<host><status state="up"/><address addr="10.1.1.6" addrtype="ipv4"/>'
           '<ports><port protocol="tcp" portid="x22"><state state="open"/></port></ports></host>'
           '<host><status state="up"/><address addr="10.1.1.7" addrtype="ipv4"/>'
           '<os><osmatch name="Linux 5.X" accuracy="9a"/></os></host>'
           '</nmaprun>')


def test_bad_numeric_attribute_costs_one_host_at_most():
    errors: list[str] = []
    by = {a.address: a for a in nmap.parse_xml(BAD_XML, errors)}
    assert set(by) == {"10.1.1.5", "10.1.1.7"}
    assert "uptime_s" not in by["10.1.1.5"].facts and by["10.1.1.5"].open_ports[0].port == 22
    assert by["10.1.1.7"].os_accuracy == 0
    assert len(errors) == 1 and "10.1.1.6" in errors[0]


def test_skipped_host_is_kept_from_the_ping_sweep(ctx, tmp_path):
    ping = PING_UP.replace("</nmaprun>", '<host><status state="up"/>'
                                         '<address addr="10.1.1.6" addrtype="ipv4"/></host></nmaprun>')
    svc = _svc(ctx, tmp_path, [{"regex": " -sn ", "stdout": ping}, {"regex": "-sV", "stdout": BAD_XML}])
    run = svc.sweep(mode="quick", actor="it1.jones", background=False)
    addrs = {a.address for a in svc.run_assets(run.id)}
    assert {"10.1.1.5", "10.1.1.6", "10.1.1.7"} <= addrs
    assert run.status == "partial" and run.missing == 0


def _finish(svc, ctx, observed):
    run = DiscoveryRun(id=ctx.store.new_id("disc-"), mode="quick", scopes=[SCOPE])
    svc._finish(run, [DiscoveryScope(cidr=SCOPE)], observed, None, "it1.jones")
    return run


def _records(svc, address):
    return sorted((a.id, a.status) for a in svc.list_assets() if a.address == address)


def test_one_record_per_target_across_mac_and_address_ids(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [])
    mac = "52:54:00:aa:bb:05"
    seen_mac = DiscoveredAsset(address="10.1.1.5", mac=mac, open_ports=[OpenPort(22, "tcp", "ssh")],
                               sources=["nmap"])
    _finish(svc, ctx, [seen_mac])
    assert _records(svc, "10.1.1.5") == [(asset_id_for(mac, "10.1.1.5"), "known")]
    _finish(svc, ctx, [])                                                         # host goes quiet
    assert _records(svc, "10.1.1.5") == [(asset_id_for(mac, "10.1.1.5"), "missing")]
    assert svc.counts()["missing"] == 1 and svc.counts()["known"] == 0
    _finish(svc, ctx, [DiscoveredAsset(address="10.1.1.5", sources=["nmap"])])   # back, seen without a MAC
    assert [s for _, s in _records(svc, "10.1.1.5")] == ["known"]


def test_missing_address_record_is_replaced_when_the_host_returns_with_a_mac(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [])
    _finish(svc, ctx, [])
    assert _records(svc, "10.1.1.5") == [(asset_id_for(None, "10.1.1.5"), "missing")]
    _finish(svc, ctx, [DiscoveredAsset(address="10.1.1.5", mac="52:54:00:aa:bb:05", sources=["nmap"])])
    assert _records(svc, "10.1.1.5") == [(asset_id_for("52:54:00:aa:bb:05", None), "known")]
    assert svc.counts() == {"new": 0, "known": 1, "ignored": 0, "missing": 0}


def test_unknown_host_seen_later_with_its_mac_is_one_record(ctx, tmp_path):
    svc = _svc(ctx, tmp_path, [])
    _finish(svc, ctx, [DiscoveredAsset(address="10.1.1.9", sources=["nmap"])])
    _finish(svc, ctx, [DiscoveredAsset(address="10.1.1.9", mac="52:54:00:aa:bb:09", sources=["nmap"])])
    assert [s for _, s in _records(svc, "10.1.1.9")] == ["new"]


def test_run_left_running_by_a_dead_process_is_closed_as_interrupted(ctx):
    svc = DiscoveryService(ctx)
    svc._save_run(DiscoveryRun(id="disc-orphan", mode="full", scopes=[SCOPE]))
    live = DiscoveryRun(id="disc-live", mode="full", scopes=[SCOPE])
    lock = _RunLock(svc._run_file(live.id).with_suffix(".lock"))
    assert lock.acquire()
    try:
        svc._save_run(live)
        DiscoveryService(ctx)
        orphan = svc.get_run("disc-orphan")
        assert orphan.status == "failed" and any("interrupted" in e for e in orphan.errors)
        assert svc.get_run("disc-live").status == "running"                     # its owner still holds the lock
    finally:
        lock.release()
    fin = [r for r in ctx.audit.records() if r["action"] == "discovery.finish"]
    assert [r["details"]["run"] for r in fin] == ["disc-orphan"]
    assert ctx.audit.verify().ok


def test_cli_sweep_without_wait_runs_to_completion(ctx, state_dir, monkeypatch, capsys):
    from cyberthunder.discovery.cli import register_cli

    def slow_collect(self, run, scopes, actor, *, vsphere_access=None):
        time.sleep(0.3)
        return [], None, {}
    monkeypatch.setattr(DiscoveryService, "_collect", slow_collect)
    monkeypatch.setattr(DiscoveryService, "join", lambda self, run_id, timeout=None: self.get_run(run_id))
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", default=str(state_dir))
    p.add_argument("--actor", default="it1.jones")
    register_cli(p.add_subparsers(dest="cmd"))
    a = p.parse_args(["discover", "sweep", "--mode", "simulated"])
    assert a.fn(a) == 0
    assert "finished" in capsys.readouterr().out
    assert DiscoveryService(ctx).runs()[0].status == "finished"


def test_accept_refuses_a_host_the_inventory_already_holds(ctx):
    svc = DiscoveryService(ctx)
    svc.sweep(mode="simulated", actor="it1.jones", background=False)
    pi = next(a for a in svc.list_assets("new") if a.address == "192.168.56.66")
    add_targets(ctx, Target(id="pi", name="pi", asset_type="linux", transport="simulated",
                            address="192.168.56.66", simulated=True))
    with pytest.raises(ValueError, match="already in the inventory as pi"):
        svc.accept(pi.id, "it1.jones", asset_type="linux", in_scope=True, reason="ok")
    assert [t.id for t in ctx.inventory.all() if t.address == "192.168.56.66"] == ["pi"]
    after = svc.get_asset(pi.id)
    assert after.status == "known" and after.inventory_target_id == "pi"


def test_simulated_sweep_on_an_empty_inventory_finds_every_answer_key_item(ctx, fix):
    key = json.loads((fix.parent.parent.parent / "range" / "answer_key" / "discovery.json").read_text(encoding="utf-8"))
    svc = DiscoveryService(ctx)
    run = svc.sweep(mode="simulated", actor="it1.jones", background=False)
    fs = svc.findings(run.id)
    for item in key["items"]:
        assert any(f.rule_id == item["check_id"] for f in fs), item["id"]
    assert any("4444" in f.title for f in fs if f.rule_id == "discovery:new_listener")


def test_ad_minimum_date_does_not_drop_the_directory():
    rows = [{"Name": "NEVER01", "IPv4Address": "10.1.1.20", "OperatingSystem": "Windows 11 Enterprise",
             "LastLogonDate": "/Date(-62135596800000)/", "Enabled": True},
            {"Name": "WS02", "IPv4Address": "10.1.1.21", "OperatingSystem": "Windows 11 Enterprise",
             "LastLogonDate": "/Date(1730721600000)/", "Enabled": True}]
    by = {a.address: a for a in active_directory.parse_ad_computers(json.dumps(rows))}
    assert set(by) == {"10.1.1.20", "10.1.1.21"}
    assert "last_logon" not in by["10.1.1.20"].facts
    assert by["10.1.1.21"].facts["last_logon"] == "2024-11-04T12:00:00Z"


def test_vmx_server_guest_ids_are_servers():
    assert hypervisor.guest_os_name("windows9srv-64") == "Windows Server 2016"
    assert hypervisor.guest_os_name("windows8srv-64") == "Windows Server 2012"
    assert hypervisor.guest_os_name("windows9-64") == "Windows 10"
