import copy
import json
from types import SimpleNamespace

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import operation_scope
from cyberthunder.discovery.models import DiscoveredAsset, DiscoveryRun, DiscoveryScope
from cyberthunder.discovery.service import DiscoveryService, SCOPE_COMPLETE
from cyberthunder.discovery.sources import vsphere, vsphere_client as wire
from cyberthunder.inventory.targets import Target
from .vsphere_support import PASSWORD, Response, Server, endpoint


def configured(ctx, monkeypatch, *, address="10.20.0.2"):
    monkeypatch.setattr(ctx.settings, "auth_mode", "dev")
    target = Target("vc", "Reviewed vSphere endpoint", "linux", address=address, sudo=False,
                    options={"hypervisor": "vsphere", "vsphere": {
                        "endpoint": "https://vc.lab/sdk", "tls_trust": "system",
                        "username": "readonly@lab", "credential_ref": "VSPHERE_FIXTURE"}})
    ctx.inventory.add_new(target)
    ctx.save_inventory("IT1 Reviewer")
    monkeypatch.setenv("CT_CRED_VSPHERE_FIXTURE", PASSWORD)
    svc = DiscoveryService(ctx)
    svc.set_scopes(["10.20.0.0/24"], "IT1 Reviewer", "Reviewed endpoint and guest range")
    monkeypatch.setattr(svc, "_passive", lambda scope, run: ([DiscoveredAsset(address="10.20.0.2")], SCOPE_COMPLETE))
    monkeypatch.setattr(ctx, "transport_for", lambda _: pytest.fail("vSphere must not reuse SSH or ambient transports"))
    server = Server(monkeypatch)
    return svc, target, server


def test_fixture_sweep_proposes_vm_and_hypervisor_inventory_and_persists(ctx, monkeypatch):
    svc, target, server = configured(ctx, monkeypatch)
    before = [t.to_dict() for t in ctx.inventory.all()]
    run = svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert run.status == "finished"
    assets = [a for a in svc.run_assets(run.id) if vsphere.is_observation(a)]
    assert len(assets) == 4 and all(a.status == "new" for a in assets)
    by = {a.facts["vsphere_ref"]: a for a in assets}
    assert by["host-10"].facts["hypervisor"] == "esxi"
    assert by["host-10"].address == "10.20.0.10"
    assert by["vm-101"].address == "10.20.0.21"
    assert by["vm-101"].facts["hypervisor_host"] == "host-10"
    assert by["vm-101"].hostname == by["vm-102"].hostname == "build-box"
    assert by["vm-101"].id != by["vm-102"].id
    assert by["vm-102"].address is None and by["vm-102"].facts["offline"] is True
    assert by["vm-103"].address is None and by["vm-103"].hostname == "编译机 & test"
    assert all(not a.open_ports and not a.inventory_target_id for a in assets)
    assert all(a.facts["reported_by"] == target.id for a in assets)
    after = [t.to_dict() for t in ctx.inventory.all()]
    assert after == before
    from cyberthunder.context import AppContext
    reopened = DiscoveryService(AppContext(ctx.settings))
    assert {a.id for a in reopened.run_assets(run.id)} == {a.id for a in svc.run_assets(run.id)}
    assert {a.id for a in assets} <= {a.id for a in reopened.list_assets()}
    saved = json.dumps([a.to_dict() for a in reopened.list_assets()] + list(ctx.audit.records()), ensure_ascii=False)
    assert PASSWORD not in saved and "session-fixture-only" not in saved
    assert not any(r["action"] == "inventory.add" and r["details"].get("source") == "discovery" for r in ctx.audit.records())
    assert ctx.audit.verify().ok
    assert server.methods.count("ContinueRetrievePropertiesEx") == 1


def test_stable_object_ids_survive_renames_missing_addresses_and_repeated_sweeps(ctx, monkeypatch):
    svc, _, server = configured(ctx, monkeypatch)
    run = svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    original = {a.facts["vsphere_ref"]: a for a in svc.run_assets(run.id) if vsphere.is_observation(a)}
    server = Server(monkeypatch)
    server.pages[0] = server.pages[0].replace(b"build-box", b"renamed-guest").replace(b"10.20.0.21", b"10.20.0.31")
    run = svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    current = {a.facts["vsphere_ref"]: a for a in svc.run_assets(run.id) if vsphere.is_observation(a)}
    assert {k: a.id for k, a in current.items()} == {k: a.id for k, a in original.items()}
    assert current["vm-101"].address == "10.20.0.31"
    assert current["vm-101"].first_seen == original["vm-101"].first_seen
    assert len([a for a in svc.list_assets() if vsphere.is_observation(a)]) == 4


def test_shared_reported_ip_and_network_observations_do_not_collapse_vm_identity(monkeypatch):
    server = Server(monkeypatch)
    server.pages[0] = server.pages[0].replace(b"10.20.0.22", b"10.20.0.21").replace(b"poweredOff", b"poweredOn")
    instance, typ, rows = wire.InventoryClient(endpoint(), lambda: None).inventory(lambda: ("reader", PASSWORD))
    assets = vsphere.observations(instance, typ, rows, endpoint=endpoint().url, reported_by="vc",
                                 scopes=[DiscoveryScope("10.20.0.0/24")])
    guests = [a for a in assets if a.hostname == "build-box"]
    assert len(guests) == 2 and all(a.address is None for a in guests)
    assert all(a.facts["address_conflicts"] == ["10.20.0.21"] for a in guests)
    merged = DiscoveryService.merge_observations([*guests, copy.deepcopy(guests[0]), DiscoveredAsset(address="10.20.0.21")])
    assert len(merged) == 3 and len({a.id for a in merged}) == 3
    # Even a unique inventory address is not treated as an active network probe.
    guests[0].address = "10.20.0.21"
    assert len(DiscoveryService.merge_observations([guests[0], DiscoveredAsset(address="10.20.0.21")])) == 2


def test_endpoint_scope_is_required_and_no_hostname_resolution_or_credential_fallback(ctx, monkeypatch):
    svc, target, server = configured(ctx, monkeypatch, address="192.168.50.2")
    with pytest.raises(PermissionError, match="endpoint_outside_sweep_scope"):
        svc._inventory_sources(svc._sweep_scopes(None, "passive"), DiscoveryRun("fixture", requested_by="IT1 Reviewer"))
    assert not server.calls


def test_out_of_scope_source_never_opens_client(ctx, monkeypatch):
    svc, target, server = configured(ctx, monkeypatch)
    target.in_scope = False
    ctx.save_inventory("IT1 Reviewer")
    assert svc._inventory_sources(svc.scopes(), DiscoveryRun("fixture", requested_by="IT1 Reviewer")) == []
    assert not server.calls


@pytest.mark.parametrize("change,expected", [
    ("kill", KillSwitchEngaged), ("target", PermissionError), ("scope", PermissionError),
    ("wider_scope", PermissionError), ("configuration", PermissionError), ("mode", wire.VsphereError),
])
def test_guard_revocation_after_page_prevents_next_call_and_persistence(ctx, monkeypatch, change, expected):
    svc, target, server = configured(ctx, monkeypatch)
    monkeypatch.setattr(ctx, "authorize", lambda *a, **k: None)

    def after(method):
        if method != "RetrievePropertiesEx":
            return
        if change == "kill":
            ctx.killswitch.engage("IT1 Reviewer", "Fixture stop")
        elif change == "target":
            target.in_scope = False
            ctx.save_inventory("IT1 Reviewer")
        elif change == "scope":
            svc.set_scopes([], "IT1 Reviewer", "Revoke range")
        elif change == "wider_scope":
            svc.set_scopes(["10.20.0.0/23"], "IT1 Reviewer", "New scope grant")
        elif change == "configuration":
            target.options["vsphere"]["endpoint"] = "https://replacement.lab/sdk"
            ctx.save_inventory("IT1 Reviewer")
        elif change == "mode":
            monkeypatch.setattr(ctx.settings, "auth_mode", "oidc")

    server.after = after
    with operation_scope("discover"), pytest.raises(expected):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert server.methods[-1] == "RetrievePropertiesEx"
    assert not svc.list_assets()
    assert svc.last_run().status in {"failed", "stopped"}


@pytest.mark.parametrize("operation", [None, "scan", "discover"])
def test_verified_mode_has_no_vSphere_credential_binding_and_never_uses_shared_secret(ctx, monkeypatch, operation):
    svc, target, server = configured(ctx, monkeypatch)
    monkeypatch.setattr(ctx.settings, "auth_mode", "oidc")
    authorized = []
    monkeypatch.setattr(ctx, "authorize", lambda action, **kwargs: authorized.append((action, kwargs)))
    class NoCredentials(dict):
        def get(self, *args):
            pytest.fail("Verified discovery must fail before reading shared credentials")

    monkeypatch.setattr(vsphere, "os", SimpleNamespace(environ=NoCredentials()))
    with operation_scope(operation), pytest.raises((PermissionError, wire.VsphereError)) as error:
        vsphere.collect(ctx, target, svc.scopes(), "IT1 Reviewer", lambda _: None)
    assert str(error.value) == ("vsphere:verified_binding_unavailable" if operation == "discover"
                                else "vsphere:discover_operation_required")
    assert len(authorized) == (1 if operation == "discover" else 0)
    assert not server.calls and not svc.list_assets()


def test_failed_page_is_redacted_in_run_audit_and_persisted_state(ctx, monkeypatch):
    svc, _, server = configured(ctx, monkeypatch)
    server.overrides["ContinueRetrievePropertiesEx"] = Response(
        f"<error>{PASSWORD} session-fixture-only</error>".encode(), status=500)
    with pytest.raises(wire.VsphereError, match="http_failure"):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert not svc.list_assets()
    run = svc.last_run()
    assert run.status == "failed"
    serialized = json.dumps(run.to_dict()) + json.dumps(list(ctx.audit.records()))
    assert PASSWORD not in serialized and "session-fixture-only" not in serialized
    assert "vsphere:http_failure" in serialized
    assert server.methods[-1] == "Logout"


def test_missing_password_never_falls_back_to_target_ssh_or_bare_environment(ctx, monkeypatch):
    svc, target, server = configured(ctx, monkeypatch)
    monkeypatch.delenv("CT_CRED_VSPHERE_FIXTURE")
    monkeypatch.setenv("VSPHERE_FIXTURE", PASSWORD)
    monkeypatch.setenv("VMWARE_PASSWORD", PASSWORD)
    target.username, target.credential_ref = "ssh-reader", "OTHER"
    ctx.save_inventory("IT1 Reviewer")
    with pytest.raises(wire.VsphereError, match="credential_unavailable"):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert server.methods == ["RetrieveServiceContent"]


def test_missing_host_ips_and_ipv6_remain_scoped(monkeypatch):
    server = Server(monkeypatch)
    server.pages[0] = server.pages[0].replace(b"10.20.0.10", b"0.0.0.0").replace(b"10.20.0.21", b"fd00::21")
    instance, typ, rows = wire.InventoryClient(endpoint(), lambda: None).inventory(lambda: ("reader", PASSWORD))
    assets = vsphere.observations(instance, typ, rows, endpoint=endpoint().url, reported_by="vc",
                                 scopes=[DiscoveryScope("fd00::/120")])
    by = {a.facts["vsphere_ref"]: a for a in assets}
    assert by["host-10"].address is None
    assert by["vm-101"].address == "fd00::21"
    assert "vm-102" not in by and "vm-104" not in by
