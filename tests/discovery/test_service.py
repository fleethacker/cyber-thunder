"""DiscoveryService against a temp inventory: sweeps, reconcile, accept/ignore, findings, kill switch."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.discovery.models import DiscoveredAsset, DiscoveryScope, OpenPort
from cyberthunder.discovery.service import DiscoveryService
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.fixture import FixtureTransport

from .conftest import add_targets


def _inventory(ctx):
    add_targets(ctx,
                Target(id="rocky9-app01", name="rocky9-app01", asset_type="linux", address="192.168.56.10"),
                Target(id="win11-ws01", name="win11-ws01", asset_type="windows", transport="winrm",
                       address="192.168.56.11"),
                Target(id="retired-01", name="retired-01", asset_type="linux", options={"address": "192.168.56.99"}),
                Target(id="far-away", name="far-away", asset_type="linux", address="10.50.0.9"))


def _actions(ctx):
    return [r["action"] for r in ctx.audit.records()]


def _sim(ctx) -> tuple[DiscoveryService, object]:
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    return svc, svc.sweep(mode="simulated", actor="it1.jones", background=False)


def test_simulated_sweep_counts_and_persistence(ctx):
    svc, run = _sim(ctx)
    assert run.status == "finished"
    assert run.counts() == {"hosts_seen": 4, "new": 2, "known": 2, "changed": 1, "missing": 1}
    assert run.scopes == ["192.168.56.0/24"]
    d = ctx.store.root / "discovery"
    assert (d / "assets.json").exists() and (d / "runs" / f"{run.id}.json").exists()
    saved = json.loads((d / "runs" / f"{run.id}.json").read_text(encoding="utf-8"))
    assert saved["status"] == "finished" and len(saved["assets"]) == 5
    assert svc.get_run(run.id).counts() == run.counts() and svc.runs()[0].id == run.id
    by = {a.address: a for a in svc.list_assets()}
    assert by["192.168.56.66"].status == "new" and by["192.168.56.3"].status == "new"
    assert by["192.168.56.10"].status == "known" and by["192.168.56.10"].inventory_target_id == "rocky9-app01"
    assert [c["kind"] for c in by["192.168.56.10"].changes] == ["new_listener"]
    assert by["192.168.56.99"].status == "missing" and by["192.168.56.99"].inventory_target_id == "retired-01"
    assert "10.50.0.9" not in by                                   # outside the swept scope: not "missing"
    assert [a.address for a in svc.list_assets("new")] == ["192.168.56.3", "192.168.56.66"]
    acts = _actions(ctx)
    assert "discovery.start" in acts and acts[-1] == "discovery.finish"
    finish = list(ctx.audit.records())[-1]["details"]
    assert finish["new"] == 2 and finish["missing"] == 1
    assert len(ctx.inventory.all()) == 4                           # nothing added without accept
    assert ctx.audit.verify().ok


def test_background_sweep_and_join(ctx):
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    run = svc.sweep(mode="simulated", actor="it1.jones")
    done = svc.join(run.id, timeout=30)
    assert done.status == "finished" and done.new == 2
    assert ctx.audit.verify().ok


def test_accept_creates_audited_target(ctx):
    svc, _ = _sim(ctx)
    sw = next(a for a in svc.list_assets("new") if a.address == "192.168.56.3")
    t = svc.accept(sw.id, "it1.jones", name="SW-SPARE-03", in_scope=True, reason="spare switch, now managed")
    # the switch exists only in the emulator, so it becomes a simulated target, never a live ssh one
    assert t.asset_type == "cisco_ios" and t.transport == "simulated" and t.simulated and t.port is None
    assert t.tags == ["discovered"] and t.in_scope and t.address == "192.168.56.3"
    assert ctx.inventory.get(t.id) is t
    assert any(x.id == t.id for x in type(ctx.inventory).load(ctx.store.targets).all())   # saved to disk
    recs = list(ctx.audit.records())
    add = next(r for r in recs if r["action"] == "inventory.add")
    assert add["details"]["source"] == "discovery" and add["details"]["in_scope"] is True
    assert add["details"]["reason"] == "spare switch, now managed"
    scope = next(r for r in recs if r["action"] == "scope.change")
    assert scope["details"] == {"target": t.id, "before": None, "after": True, "reason": "spare switch, now managed"}
    after = svc.get_asset(sw.id)
    assert after.status == "known" and after.inventory_target_id == t.id
    with pytest.raises(ValueError, match="already"):
        svc.accept(sw.id, "it1.jones", in_scope=True, reason="again")
    assert ctx.audit.verify().ok


def test_accept_out_of_scope_and_refusals(ctx):
    svc, _ = _sim(ctx)
    pi = next(a for a in svc.list_assets("new") if a.address == "192.168.56.66")
    with pytest.raises(PermissionError):
        svc.accept(pi.id, "agent", asset_type="linux", in_scope=True, reason="x")
    with pytest.raises(PermissionError):
        svc.accept(pi.id, "llm", asset_type="linux", in_scope=True, reason="x")
    with pytest.raises(ValueError, match="reason"):
        svc.accept(pi.id, "it1.jones", asset_type="linux", in_scope=True, reason="  ")
    with pytest.raises(ValueError, match="asset type"):
        svc.accept(pi.id, "it1.jones", in_scope=False, reason="unknown type")       # guess is unknown
    with pytest.raises(KeyError):
        svc.accept("nope", "it1.jones", asset_type="linux", in_scope=False, reason="x")
    before = len(ctx.inventory.all())
    t = svc.accept(pi.id, "it1.jones", asset_type="linux", in_scope=False, reason="lab pi, track only")
    assert not t.in_scope and len(ctx.inventory.all()) == before + 1
    assert "scope.change" not in _actions(ctx)
    assert ctx.audit.verify().ok


def test_accept_from_simulated_sweep_never_goes_live(ctx):
    svc, _ = _sim(ctx)
    sw = next(a for a in svc.list_assets("new") if a.address == "192.168.56.3")
    for kind in ("ssh", "winrm", "fixture"):
        with pytest.raises(ValueError, match="simulated"):
            svc.accept(sw.id, "it1.jones", transport=kind, in_scope=True, reason="probe")
    t = svc.accept(sw.id, "it1.jones", transport="simulated", username="admin", credential_ref="SW_PW",
                   in_scope=True, reason="probe")
    assert t.transport == "simulated" and t.simulated and t.username is None and t.credential_ref is None
    assert ctx.audit.verify().ok


def test_accept_credential_ref_is_a_name_not_a_path_or_process_variable(ctx, monkeypatch):
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    real = DiscoveredAsset(address="192.168.56.40", sources=["nmap"], open_ports=[OpenPort(22, "tcp", "ssh", "OpenSSH")])
    assets, _ = svc.reconcile([real], [DiscoveryScope(cidr="192.168.56.0/24")], previous={})
    svc._save_assets({a.id: a for a in assets})
    aid = next(a.id for a in assets if a.address == "192.168.56.40")
    monkeypatch.setenv("SOME_SECRET_TOKEN", "hunter2")
    for ref in ("SOME_SECRET_TOKEN", "../../etc/shadow", r"C:\keys\id_rsa", "~/.ssh/id_rsa", ".hidden", "x" * 65):
        with pytest.raises(ValueError, match="credential"):
            svc.accept(aid, "it1.jones", asset_type="linux", credential_ref=ref, in_scope=True, reason="probe")
    monkeypatch.setenv("CT_CRED_SOME_SECRET_TOKEN", "range-pw")      # the documented form is still fine
    t = svc.accept(aid, "it1.jones", asset_type="linux", credential_ref="SOME_SECRET_TOKEN", in_scope=True,
                   reason="probe")
    assert t.transport == "ssh" and t.credential_ref == "SOME_SECRET_TOKEN" and not t.simulated


def test_demo_load_then_simulated_sweep_knows_the_demo_targets(ctx):
    from cyberthunder import demo
    targets = demo.load(ctx, "it1.jones")
    assert len(targets) == 5 and all(t.address is None for t in targets)
    svc = DiscoveryService(ctx)
    run = svc.sweep(mode="simulated", actor="it1.jones", background=False)
    assert run.counts()["known"] == 5 and run.counts()["new"] == 2
    known = {a.inventory_target_id for a in svc.list_assets("known")}
    assert known == {t.id for t in targets}
    assert sorted(a.address for a in svc.list_assets("new")) == ["192.168.56.3", "192.168.56.66"]
    fs = svc.findings(run.id)
    unknown = sorted(f.host for f in fs if f.rule_id == "discovery:unknown_asset")
    assert unknown == ["discovered:192.168.56.3", "discovered:192.168.56.66"]
    listener = [f for f in fs if f.rule_id == "discovery:new_listener"]
    assert [f.host for f in listener] == ["sim-linux-01"]
    key = json.loads((Path(__file__).resolve().parents[2] / "range" / "answer_key" / "discovery.json")
                     .read_text(encoding="utf-8"))
    for item in key["items"]:                                       # D1, D2 and D3
        assert any(f.rule_id == item["check_id"] for f in fs), item["id"]
    assert ctx.audit.verify().ok


def test_ignore(ctx):
    svc, _ = _sim(ctx)
    pi = next(a for a in svc.list_assets("new") if a.address == "192.168.56.66")
    with pytest.raises(ValueError):
        svc.ignore(pi.id, "it1.jones", "")
    with pytest.raises(PermissionError):
        svc.ignore(pi.id, "system", "x")
    svc.ignore(pi.id, "it1.jones", "instructor demo board")
    assert svc.get_asset(pi.id).status == "ignored"
    rec = list(ctx.audit.records())[-1]
    assert rec["action"] == "discovery.ignore" and rec["details"]["reason"] == "instructor demo board"
    assert not [f for f in svc.findings() if f.host == "discovered:192.168.56.66"]
    run2 = svc.sweep(mode="simulated", actor="it1.jones", background=False)  # stays ignored on the next sweep
    assert svc.get_asset(pi.id).status == "ignored" and run2.new == 1
    assert ctx.audit.verify().ok


def test_findings(ctx):
    svc, run = _sim(ctx)
    fs = svc.findings(run.id)
    assert fs and all(f.references for f in fs)
    by = {(f.rule_id, f.host): f for f in fs}
    rogue = by[("discovery:unknown_asset", "discovered:192.168.56.66")]
    assert rogue.severity.value == "high" and {"T1200", "T1046"} <= set(rogue.citations)
    assert rogue.asset_type == "unknown" and "b8:27:eb:5a:66:01" in rogue.evidence and "23/tcp" in rogue.evidence
    assert by[("discovery:unknown_asset", "discovered:192.168.56.3")].severity.value == "high"
    iot = by[("discovery:consumer_device", "discovered:192.168.56.66")]
    assert iot.severity.value == "medium" and "T1200" in iot.citations
    nl = by[("discovery:new_listener", "rocky9-app01")]
    assert nl.severity.value == "medium" and "T1571" in nl.citations and "4444/tcp" in nl.title
    assert nl.asset_type == "linux"
    miss = by[("discovery:missing_asset", "retired-01")]
    assert miss.severity.value == "low" and "CCI-000366" in miss.citations
    assert fs[0].severity.value == "high"                          # ordered most severe first
    assert [f.id for f in svc.findings()] == [f.id for f in fs]   # latest run by default
    assert ctx.audit.verify().ok


def test_answer_key_items_are_found(ctx, fix):
    key = json.loads((fix.parent.parent.parent / "range" / "answer_key" / "discovery.json").read_text(encoding="utf-8"))
    svc, run = _sim(ctx)
    fs = svc.findings(run.id)
    for item in key["items"]:
        assert any(f.rule_id == item["check_id"] for f in fs), item["id"]
    assert ctx.audit.verify().ok


def test_type_changed(ctx):
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    scope = DiscoveryScope(cidr="192.168.56.0/24")
    imposter = DiscoveredAsset(address="192.168.56.10", mac="00:15:5d:00:00:10", sources=["nmap"],
                               open_ports=[OpenPort(3389, "tcp", "ms-wbt-server"), OpenPort(445, "tcp", "microsoft-ds"),
                                           OpenPort(135, "tcp", "msrpc", "Microsoft Windows RPC")])
    assets, counts = svc.reconcile([imposter], [scope], previous={})
    a = next(x for x in assets if x.address == "192.168.56.10")
    assert a.asset_type_guess == "windows" and a.changes[0]["kind"] == "type_changed"
    assert counts["changed"] == 1 and counts["missing"] == 2       # win11-ws01 and retired-01 not seen
    ctx.store.write_json(svc.dir / "runs" / "manual.json", {"id": "manual", "status": "finished",
                                                           "assets": [x.to_dict() for x in assets]})
    f = next(f for f in svc.findings("manual") if f.rule_id == "discovery:type_changed")
    assert f.host == "rocky9-app01" and "T1036" in f.citations and f.severity.value == "medium"
    assert ctx.audit.verify().ok


def test_ports_changed_versus_previous_sweep(ctx):
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    scope = DiscoveryScope(cidr="192.168.56.0/24")
    first = DiscoveredAsset(address="192.168.56.10", open_ports=[OpenPort(22, "tcp", "ssh", "OpenSSH")])
    assets, counts = svc.reconcile([first], [scope], previous={})
    assert counts["changed"] == 0
    prev = {a.id: a for a in assets}
    second = DiscoveredAsset(address="192.168.56.10", open_ports=[OpenPort(22, "tcp", "ssh", "OpenSSH"),
                                                                  OpenPort(8443, "tcp", "https")])
    assets, counts = svc.reconcile([second], [scope], previous=prev)
    a = next(x for x in assets if x.address == "192.168.56.10")
    assert counts["changed"] == 1
    assert [(c["kind"], c["ports"]) for c in a.changes] == [("new_listener", ["8443/tcp"])]
    assert ctx.audit.verify().ok


def test_scopes_validated_and_audited(ctx):
    svc = DiscoveryService(ctx)
    with pytest.raises(ValueError, match="reason"):
        svc.set_scopes(["192.168.56.0/24"], "it1.jones", "")
    with pytest.raises(ValueError, match="not private"):
        svc.set_scopes([{"cidr": "8.8.8.0/24"}], "it1.jones", "test")
    with pytest.raises(PermissionError):
        svc.set_scopes(["192.168.56.0/24"], "agent", "test")
    svc.set_scopes(["192.168.56.0/24", {"cidr": "8.8.8.0/24", "allow_public": True}], "it1.jones", "range plan v2")
    assert [s.cidr for s in svc.scopes()] == ["192.168.56.0/24", "8.8.8.0/24"]
    rec = list(ctx.audit.records())[-1]
    assert rec["action"] == "discovery.scopes" and rec["details"]["before"] == []
    assert rec["details"]["after"] == ["192.168.56.0/24", "8.8.8.0/24"] and rec["details"]["reason"] == "range plan v2"
    with pytest.raises(ValueError, match="not inside a saved"):
        svc.sweep(scopes=["192.168.60.0/24"], mode="quick", actor="it1.jones", background=False)
    assert ctx.audit.verify().ok


def test_quick_sweep_needs_saved_scope(ctx):
    svc = DiscoveryService(ctx)
    with pytest.raises(ValueError, match="no discovery scopes"):
        svc.sweep(mode="quick", actor="it1.jones", background=False)
    assert ctx.audit.verify().ok


def test_full_sweep_over_scanner_target_with_switch_tables(ctx, fixture_copy):
    _inventory(ctx)
    add_targets(ctx,
                Target(id="scanner", name="scanner", asset_type="linux", transport="fixture",
                       options={"fixture_dir": str(fixture_copy("scanner"))}),
                Target(id="sw-core-01", name="sw-core-01", asset_type="cisco_ios", transport="fixture",
                       address="192.168.56.2", options={"fixture_dir": str(fixture_copy("gear"))}))
    svc = DiscoveryService(ctx)
    svc.set_scopes([{"cidr": "192.168.56.0/24", "scanner_target": "scanner"}], "it1.jones", "enclave A")
    run = svc.sweep(mode="full", actor="it1.jones", background=False)
    assert run.status == "finished"
    by = {a.address: a for a in svc.run_assets(run.id)}
    # nmap: 8 up; switch tables add .3 (CDP), .70 (CDP phone) and .71 (ARP); 10.99.0.4 is outside the scope
    assert set(by) >= {"192.168.56.2", "192.168.56.3", "192.168.56.40", "192.168.56.66", "192.168.56.70",
                       "192.168.56.71", "192.168.56.99"}
    assert "10.99.0.4" not in by
    assert by["192.168.56.66"].facts.get("switch_port") == "Gi1/0/17"
    assert {"nmap", "switch_arp"} <= set(by["192.168.56.66"].sources)
    assert by["192.168.56.2"].status == "known" and by["192.168.56.10"].status == "known"
    assert by["192.168.56.40"].hostname == "DC01.fleet.lab"
    assert run.known == 3 and run.missing == 1 and run.new == 8
    assert any("show lldp neighbors detail" in e for e in run.errors)          # tolerated and recorded
    assert ctx.audit.verify().ok


def test_passive_sweep(ctx, fixture_copy):
    add_targets(ctx, Target(id="scanner", name="scanner", asset_type="linux", transport="fixture",
                            options={"fixture_dir": str(fixture_copy("scanner"))}))
    svc = DiscoveryService(ctx)
    svc.set_scopes([{"cidr": "192.168.56.0/24", "scanner_target": "scanner"}], "it1.jones", "enclave A")
    run = svc.sweep(mode="passive", actor="it1.jones", background=False)
    addrs = {a.address for a in svc.run_assets(run.id)}
    assert {"192.168.56.1", "192.168.56.2", "192.168.56.10", "192.168.56.11", "192.168.56.30",
            "192.168.56.66"} <= addrs
    assert "10.20.0.5" not in addrs and not any(":" in a for a in addrs)     # out of scope / IPv6 link-local
    assert run.status == "finished"
    assert ctx.audit.verify().ok


def test_inventory_sources_kube_ad_hypervisors(ctx, fix, fixture_copy, tmp_path):
    root = tmp_path / "winhost"
    (root / "files").mkdir(parents=True)
    (root / "commands.json").write_text(json.dumps([
        {"regex": "^Get-ADComputer ", "stdout": (fix / "ad_computers.json").read_text(encoding="utf-8")},
        {"regex": "^Get-VM ", "stdout": (fix / "hyperv_vms.json").read_text(encoding="utf-8")},
    ]), encoding="utf-8")
    kroot = tmp_path / "kube"
    kroot.mkdir()
    (kroot / "commands.json").write_text(json.dumps([
        {"match": "kubectl get nodes -o json", "stdout": (fix / "kube_nodes.json").read_text(encoding="utf-8")}]),
        encoding="utf-8")
    add_targets(ctx,
                Target(id="dc01", name="dc01", asset_type="windows", transport="fixture", address="192.168.56.40",
                       options={"fixture_dir": str(root), "directory_source": True, "hypervisor": "hyperv"}),
                Target(id="k3s", name="k3s", asset_type="kubernetes", transport="fixture", address="192.168.56.20",
                       options={"fixture_dir": str(kroot)}),
                Target(id="vmhost", name="vmhost", asset_type="windows", transport="fixture",
                       options={"fixture_dir": str(fixture_copy("vmware")), "hypervisor": "vmware"}),
                Target(id="ghost", name="ghost", asset_type="windows", transport="fixture", in_scope=False,
                       options={"fixture_dir": str(root), "directory_source": True}))
    svc = DiscoveryService(ctx)
    svc.set_scopes(["192.168.56.0/24"], "it1.jones", "enclave A")
    (tmp_path / "empty").mkdir()
    svc.local_transport_factory = lambda: FixtureTransport(tmp_path / "empty")     # nmap answers nothing
    run = svc.sweep(mode="quick", actor="it1.jones", background=False)
    assets = svc.run_assets(run.id)
    by = {a.address: a for a in assets if a.address}
    assert by["192.168.56.21"].asset_type_guess == "kubernetes"
    assert by["192.168.56.41"].facts["windows_role"] == "server"
    assert "hyperv" in by["192.168.56.12"].sources and "active_directory" in by["192.168.56.12"].sources
    offline = [a for a in assets if a.facts.get("vm_name") == "old-build-box"]
    assert offline and offline[0].facts["offline"] is True
    assert any(a.facts.get("vm_name") == "rocky9-lab" for a in assets)
    assert any("nmap" in e for e in run.errors)
    assert not any("ghost" in str(a.facts.get("reported_by")) for a in assets)    # out-of-scope target not asked
    assert ctx.audit.verify().ok


def test_kill_switch_blocks_sweep(ctx):
    _inventory(ctx)
    svc = DiscoveryService(ctx)
    ctx.killswitch.engage("it1.jones", "drill")
    with pytest.raises(KillSwitchEngaged):
        svc.sweep(mode="simulated", actor="it1.jones", background=False)
    recs = list(ctx.audit.records())
    blocked = [r for r in recs if r["action"] == "action.blocked"]
    assert blocked and blocked[-1]["details"]["action"] == "discovery.sweep" and blocked[-1]["outcome"] == "blocked"
    assert recs[-1]["action"] == "discovery.finish" and recs[-1]["details"]["status"] == "stopped"
    assert svc.runs()[0].status == "stopped"
    with pytest.raises(KillSwitchEngaged):
        svc.sweep(mode="simulated", actor="it1.jones", background=True)           # caller sees it synchronously
    assert ctx.audit.verify().ok


def test_kill_switch_between_scopes(ctx, tmp_path):
    svc = DiscoveryService(ctx)
    svc.set_scopes(["192.168.56.0/24", "192.168.57.0/24"], "it1.jones", "two enclaves")

    class Tripwire(FixtureTransport):
        def run(self, command, *, timeout=120, sudo=False):
            ctx.killswitch.engage("it2.smith", "stop the sweep")
            return super().run(command, timeout=timeout, sudo=sudo)

    (tmp_path / "trip").mkdir()
    seen = []
    svc.local_transport_factory = lambda: seen.append(1) or Tripwire(tmp_path / "trip")
    with pytest.raises(KillSwitchEngaged):
        svc.sweep(mode="passive", actor="it1.jones", background=False)
    assert len(seen) == 1                                          # the second scope never started
    assert svc.runs()[0].status == "stopped"
    assert any(r["action"] == "action.blocked" for r in ctx.audit.records())
    assert ctx.audit.verify().ok
