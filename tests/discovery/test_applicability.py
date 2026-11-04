"""Which inventory targets a STIG or bulletin applies to, from scan facts, hints and discovery records."""
from __future__ import annotations

import json

import pytest

from cyberthunder.discovery import applicability
from cyberthunder.discovery.service import DiscoveryService
from cyberthunder.inventory.targets import Target

from .conftest import add_targets


@pytest.fixture
def fleet(ctx):
    add_targets(ctx,
                Target(id="rhel9-a", name="rhel9-a", asset_type="linux", options={"os_name": "Rocky Linux", "os_version": "9.4"}),
                Target(id="rhel8-b", name="rhel8-b", asset_type="linux", options={"os_name": "Red Hat Enterprise Linux", "os_version": "8.10"}),
                Target(id="ubuntu-c", name="ubuntu-c", asset_type="linux", options={"os": "Ubuntu 22.04.4 LTS"}),
                Target(id="linux-new", name="linux-new", asset_type="linux"),
                Target(id="ws11", name="ws11", asset_type="windows", transport="winrm", options={"os": "Microsoft Windows 11 Enterprise"}),
                Target(id="srv22", name="srv22", asset_type="windows", transport="winrm", options={"os": "Windows Server 2022 Standard"}),
                Target(id="c9300", name="c9300", asset_type="cisco_ios", options={"product": "C9300-48P IOS-XE 17.9"}),
                Target(id="isr", name="isr", asset_type="cisco_ios", options={"product": "ISR4331"}),
                Target(id="k3s", name="k3s", asset_type="kubernetes", transport="kubeconfig"))
    return DiscoveryService(ctx)


def _ids(rows):
    return sorted(r["target"] for r in rows)


def test_rhel9(fleet, ctx):
    rows = fleet.applicable(benchmark_id="xccdf_org.ssgproject.content_benchmark_RHEL-9")
    assert _ids(rows) == ["linux-new", "rhel9-a"]
    by = {r["target"]: r for r in rows}
    assert by["rhel9-a"]["basis"] == "hint" and by["linux-new"]["basis"] == "type"
    assert _ids(fleet.applicable(title="Red Hat Enterprise Linux 9 Security Technical Implementation Guide")) == \
        ["linux-new", "rhel9-a"]
    assert ctx.audit.verify().ok


def test_windows_cisco_kubernetes(fleet, ctx):
    assert _ids(fleet.applicable(title="Microsoft Windows 11 STIG")) == ["ws11"]
    assert _ids(fleet.applicable(benchmark_id="MS_Windows_Server_2022_STIG")) == ["srv22"]
    assert _ids(fleet.applicable(title="Cisco IOS XE Switch NDM")) == ["c9300"]
    assert _ids(fleet.applicable(benchmark_id="Kubernetes_STIG")) == ["k3s"]
    assert _ids(fleet.applicable(product="openssh", asset_type="linux")) == ["linux-new", "rhel8-b", "rhel9-a", "ubuntu-c"]
    with pytest.raises(ValueError):
        fleet.applicable(title="Commodore 64 STIG")
    with pytest.raises(ValueError):
        fleet.applicable()
    assert ctx.audit.verify().ok


def test_scan_facts_win_and_glob_escaped_ids(ctx):
    add_targets(ctx, Target(id="web[1]", name="web[1]", asset_type="linux", options={"os": "Rocky Linux 9.4"}),
                Target(id="web1", name="web1", asset_type="linux"))
    raw = ctx.store.scan_dir("scan-1") / "raw"
    for tid, ver in (("web[1]", "8.9"), ("web1", "9.4")):
        ctx.store.write_json(raw / tid / "collected.json", {"facts": {"os_name": "Rocky Linux", "os_version": ver}})
    # "web[1]" unescaped would glob-match the web1 directory and pick up its 9.4 facts
    assert applicability.latest_scan_facts(ctx.store.root, "web[1]")["os_version"] == "8.9"
    rows = DiscoveryService(ctx).applicable(benchmark_id="RHEL_9_STIG")
    assert _ids(rows) == ["web1"]
    assert {r["basis"] for r in rows} == {"facts"}
    assert ctx.audit.verify().ok


def test_discovery_version_mismatch_excludes_but_coarse_guess_does_not(ctx):
    add_targets(ctx, Target(id="node-a", name="node-a", asset_type="linux"),
                Target(id="node-b", name="node-b", asset_type="linux"),
                Target(id="node-c", name="node-c", asset_type="linux"))
    assets = {
        "a1": {"id": "a1", "inventory_target_id": "node-a", "os_guess": "Rocky Linux 8.9 (Green Obsidian)", "facts": {}},
        "b1": {"id": "b1", "inventory_target_id": "node-b", "os_guess": "Linux 5.0 - 5.14", "facts": {}},
        "c1": {"id": "c1", "inventory_target_id": "node-c", "os_guess": None, "facts": {"os_image": "Rocky Linux 9.4 (Blue Onyx)"}},
    }
    (ctx.store.root / "discovery").mkdir(exist_ok=True)
    (ctx.store.root / "discovery" / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    rows = {r["target"]: r for r in DiscoveryService(ctx).applicable(benchmark_id="RHEL_9_STIG")}
    assert "node-a" not in rows                                   # right family, wrong major version
    assert rows["node-b"]["basis"] == "type"                      # coarse nmap guess falls through
    assert rows["node-c"]["basis"] == "discovery"
    assert ctx.audit.verify().ok


def test_accepted_asset_feeds_applicability(ctx):
    svc = DiscoveryService(ctx)
    svc.sweep(mode="simulated", actor="it1.jones", background=False)       # standard demo set, empty inventory
    linux = next(a for a in svc.list_assets("new") if a.hostname == "sim-linux-01")
    svc.accept(linux.id, "it1.jones", in_scope=True, reason="enclave host")
    rows = svc.applicable(benchmark_id="RHEL_9_STIG")
    assert [(r["target"], r["basis"]) for r in rows] == [("sim-linux-01", "discovery")]
    assert ctx.audit.verify().ok
