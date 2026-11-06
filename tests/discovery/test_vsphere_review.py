"""Adversarial wire and publication cases from the independent inventory review."""
import copy
import json
from types import SimpleNamespace
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.discovery.sources import vsphere, vsphere_client as wire
from .test_vsphere_source import configured
from .vsphere_support import PASSWORD, Response, Server, endpoint, envelope


def inventory(server):
    client = wire.InventoryClient(endpoint(), lambda: None)
    result = client.inventory(lambda: ("reader@lab", PASSWORD))
    assert client.cookie is None
    return result


@pytest.mark.parametrize("path", [
    r"\\unreviewed.invalid\share\ca.pem", "//unreviewed.invalid/share/ca.pem",
    r"\\?\UNC\unreviewed.invalid\share\ca.pem", r"\\.\C:\ca.pem",
])
def test_network_trust_paths_are_rejected_before_filesystem_access(monkeypatch, path):
    def probe(_):
        pytest.fail("Network/device trust path reached filesystem access")

    monkeypatch.setattr(wire.Path, "is_file", probe)
    with pytest.raises(wire.VsphereError, match="invalid_endpoint_or_trust"):
        wire.Endpoint.parse("https://vc.lab/sdk", "10.20.0.2", tls_trust="ca_file", ca_file=path)


@pytest.mark.parametrize("secret", [PASSWORD, "session-fixture-only"])
@pytest.mark.parametrize("field", ["name", "product"])
def test_successful_server_echo_cannot_publish_credentials(ctx, monkeypatch, secret, field):
    svc, _, server = configured(ctx, monkeypatch)
    prior = svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    saved = [a.to_dict() for a in svc.list_assets()]
    server = Server(monkeypatch)
    needle = b"build-box" if field == "name" else b"VMware ESXi 8.0.3"
    server.pages[0] = server.pages[0].replace(needle, escape("echo: " + secret).encode())
    with pytest.raises(wire.VsphereError, match="^vsphere:sensitive_response$"):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    failed = next(run for run in svc.runs() if run.id != prior.id)
    assert failed.id != prior.id and failed.status == "failed"
    assert svc.run_assets(failed.id) == []
    assert [a.to_dict() for a in svc.list_assets()] == saved
    serialized = json.dumps(saved + [failed.to_dict()] + list(ctx.audit.records()))
    assert PASSWORD not in serialized and "session-fixture-only" not in serialized
    assert all(c.closed for c in server.connections)


def test_documented_empty_inventory_result_is_successful(monkeypatch):
    server = Server(monkeypatch)
    server.overrides["RetrievePropertiesEx"] = Response(envelope("RetrievePropertiesEx", ""))
    assert inventory(server)[2] == []
    assert server.methods[-2:] == ["DestroyView", "Logout"]
    assert "ContinueRetrievePropertiesEx" not in server.methods


def test_absent_continuation_result_cannot_publish_first_page(monkeypatch):
    server = Server(monkeypatch)
    server.overrides["ContinueRetrievePropertiesEx"] = Response(envelope("ContinueRetrievePropertiesEx", ""))
    with pytest.raises(wire.VsphereError, match="missing_page"):
        inventory(server)


def test_fired_watchdog_cannot_return_a_successful_response(monkeypatch):
    server = Server(monkeypatch)
    timers = []

    class Timer:
        def __init__(self, interval, callback):
            self.callback = callback
            timers.append(self)

        def start(self):
            pass

        def cancel(self):
            pass

    # A timer may wake at the edge of the monotonic deadline. Its fired state
    # must win even if the body completes and a separate clock read is earlier.
    monkeypatch.setattr(wire.threading, "Timer", Timer)
    monkeypatch.setattr(wire, "time", SimpleNamespace(monotonic=lambda: 0.0))
    response = Response(server.service)

    def read(_):
        timers[0].callback()
        return server.service

    response.read = read
    server.overrides["RetrieveServiceContent"] = response
    with pytest.raises(wire.VsphereError, match="deadline"):
        inventory(server)
    assert server.methods == ["RetrieveServiceContent"]


@pytest.mark.parametrize("variant", ["body", "returnval", "token", "object_namespace", "object_ref", "property_value"])
def test_ambiguous_or_unrecognized_page_structure_never_becomes_complete(monkeypatch, variant):
    server = Server(monkeypatch)
    root = ET.fromstring(server.pages[0])
    body = root.find(f"{{{wire.SOAP}}}Body")
    result = body[0][0]
    if variant == "body":
        root.append(copy.deepcopy(body))
    elif variant == "returnval":
        body[0].append(copy.deepcopy(result))
    elif variant == "token":
        result.insert(0, ET.Element(f"{{{wire.VIM}}}token"))
    elif variant == "object_namespace":
        result.find(f"{{{wire.VIM}}}objects").tag = "{urn:unexpected}objects"
    elif variant == "object_ref":
        row = result.find(f"{{{wire.VIM}}}objects")
        row.insert(0, copy.deepcopy(row[0]))
    else:
        prop = result.find(f"{{{wire.VIM}}}objects/{{{wire.VIM}}}propSet")
        prop.append(copy.deepcopy(prop[1]))
    server.pages[0] = ET.tostring(root)
    with pytest.raises(wire.VsphereError):
        inventory(server)
    assert "ContinueRetrievePropertiesEx" not in server.methods


def test_powered_off_vm_with_explicit_null_runtime_host_is_metadata(ctx, monkeypatch):
    svc, _, server = configured(ctx, monkeypatch)
    root = ET.fromstring(server.pages[0])
    for row in root.findall(f".//{{{wire.VIM}}}objects"):
        if row.findtext(f"{{{wire.VIM}}}obj") == "vm-102":
            for prop in row.findall(f"{{{wire.VIM}}}propSet"):
                if prop.findtext(f"{{{wire.VIM}}}name") == "runtime.host":
                    val = prop.find(f"{{{wire.VIM}}}val")
                    val.clear()
                    val.set(f"{{{wire.XSI}}}nil", "true")
    server.pages[0] = ET.tostring(root)
    run = svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    asset = next(a for a in svc.run_assets(run.id) if a.facts.get("vsphere_ref") == "vm-102")
    assert run.status == "finished" and asset.address is None
    assert asset.facts["offline"] is True and asset.facts["hypervisor_host"] is None


@pytest.mark.parametrize("revocation", ["kill", "scope", "target"])
@pytest.mark.parametrize("stage", ["conversion", "reconciliation"])
def test_revocation_before_publication_discards_observations(ctx, monkeypatch, revocation, stage):
    svc, target, _ = configured(ctx, monkeypatch)
    owner, attribute = (vsphere, "observations") if stage == "conversion" else (svc, "reconcile")
    convert = getattr(owner, attribute)

    def revoke(*args, **kwargs):
        result = convert(*args, **kwargs)
        if revocation == "kill":
            ctx.killswitch.engage("IT1 Reviewer", "Stop before publication")
        elif revocation == "scope":
            svc.set_scopes([], "IT1 Reviewer", "Revoke before publication")
        else:
            target.in_scope = False
            ctx.save_inventory("IT1 Reviewer")
        return result

    monkeypatch.setattr(owner, attribute, revoke)
    with pytest.raises(KillSwitchEngaged if revocation == "kill" else PermissionError):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert not svc.list_assets() and not svc.run_assets(svc.last_run().id)
    assert svc.last_run().status in {"failed", "stopped"}


def test_source_added_mid_run_cannot_bypass_captured_publication_guard(ctx, monkeypatch):
    svc, target, _ = configured(ctx, monkeypatch)
    target.options.pop("hypervisor")
    ctx.save_inventory("IT1 Reviewer")
    passive = svc._passive

    def add_source(scope, run):
        target.options["hypervisor"] = "vsphere"
        ctx.save_inventory("IT1 Reviewer")
        return passive(scope, run)

    monkeypatch.setattr(svc, "_passive", add_source)
    with pytest.raises(PermissionError, match="source_configuration_changed"):
        svc.sweep(mode="passive", actor="IT1 Reviewer", background=False)
    assert not svc.list_assets() and not svc.run_assets(svc.last_run().id)
    assert svc.last_run().status == "failed"
