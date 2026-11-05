"""Guided host and scope APIs use local isolated state and fake connection tests only."""
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys

import pytest

from cyberthunder.inventory import deployment
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.transport.base import TransportError
from .conftest import ACTOR, FIXTURES

API = "/api/v1"


def registration(**changes):
    return {"id": "host-01", "name": "Authorized host", "asset_type": "linux", "transport": "ssh",
            "address": "192.168.56.10", "username": "auditor", "credential_ref": "HOST_ACCESS",
            "in_scope": False, "reason": "Operator-approved lab host", **changes}


def no_network(ctx, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("read-only operation attempted DNS or transport access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    monkeypatch.setattr(ctx.scanner, "start", forbidden)


def test_runtime_registration_readiness_preview_never_connect(client, ctx, monkeypatch):
    no_network(ctx, monkeypatch)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "private-marker-value")
    monkeypatch.setenv("CT_CRED_HOST_ACCESS", "private-credential-value")
    runtime = client.get(f"{API}/runtime/context").json()
    assert runtime["kind"] == "kubernetes" and runtime["physical_host_os"] == "unknown"
    assert runtime["host_address"] is None and runtime["local_transport"]["boundary"] == "container"
    assert "private-marker" not in json.dumps(runtime)
    response = client.post(f"{API}/targets/register-host", json=registration(), headers=ACTOR)
    assert response.status_code == 201, response.text
    assert not response.json()["in_scope"] and not response.json()["simulated"]
    before = len(list(ctx.audit.records()))
    ready = client.get(f"{API}/targets/host-01/readiness").json()
    assert not ready["ready_for_connection_test"] and ready["checked"] == "declarations_only"
    preview = client.post(f"{API}/discovery/scopes/preview", json={"include": ["192.168.56.0/24"], "exclude": ["192.168.56.10"]})
    assert preview.status_code == 200 and preview.json()["address_count"] == "255"
    assert len(list(ctx.audit.records())) == before
    assert not ctx.inventory.get("host-01").in_scope
    assert "private-credential" not in json.dumps(response.json()) + json.dumps(list(ctx.audit.records()))


@pytest.mark.parametrize("changes", [{"in_scope": None}, {"in_scope": "true"}, {"in_scope": 1}, {"reason": " "},
    {"asset_type": "containers"}, {"asset_type": "windows", "transport": "ssh"}, {"transport": "local"},
    {"address": "ssh://192.168.0.1"}, {"address": "10.0.0.999"}, {"address": "10.0.0.1/24"},
    {"credential_ref": "password\nvalue"}, {"credential_ref": "/keys/private"}, {"password": "secret"},
    {"options": {"password": "secret"}}, {"port": True}, {"port": 65536}, {"username": ""}])
def test_registration_rejects_implicit_scope_and_invalid_declarations(client, ctx, changes):
    response = client.post(f"{API}/targets/register-host", json=registration(**changes), headers=ACTOR)
    assert response.status_code == 400
    assert not ctx.inventory.all()


def test_registration_explicit_os_scope_audit_and_duplicate(client, ctx):
    body = registration(asset_type="windows", transport="winrm", address="Host.Example.", in_scope=True)
    assert client.post(f"{API}/targets/register-host", json=body).status_code == 400
    assert client.post(f"{API}/targets/register-host", json=body, headers={"X-Actor": "agent"}).status_code == 400
    response = client.post(f"{API}/targets/register-host", json=body, headers=ACTOR)
    assert response.status_code == 201 and response.json()["port"] == 5986
    assert response.json()["address"] == "host.example."  # preserve the operator's absolute DNS name
    assert client.post(f"{API}/targets/register-host", json=body, headers=ACTOR).status_code == 409
    records = [r for r in ctx.audit.records() if r["action"] == "scope.change"]
    assert records[-1]["details"]["explicit_choice"] and records[-1]["details"]["reason"] == body["reason"]
    assert client.get(f"{API}/targets/host-01/readiness").json()["ready_for_connection_test"]
    ctx.killswitch.engage("operator", "hold")
    assert not client.get(f"{API}/targets/host-01/readiness").json()["ready_for_connection_test"]


def test_scope_range_save_is_audited_without_scope_grants(client, ctx, monkeypatch):
    no_network(ctx, monkeypatch)
    client.post(f"{API}/targets/register-host", json=registration(), headers=ACTOR)
    body = {"include": ["192.168.56.1-192.168.56.9", "fd00::1"], "exclude": ["192.168.56.3"], "reason": "Approved search boundary"}
    assert client.put(f"{API}/discovery/scopes/ranges", json={**body, "reason": ""}, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/discovery/scopes/ranges", json=body).status_code == 400
    response = client.put(f"{API}/discovery/scopes/ranges", json=body, headers=ACTOR)
    assert response.status_code == 200, response.text
    assert response.json()["preview"]["address_count"] == "9"
    from cyberthunder.discovery.service import service_for
    saved = service_for(ctx).scopes()
    assert not any(s.contains("192.168.56.3") for s in saved)
    assert not ctx.inventory.get("host-01").in_scope
    assert not service_for(ctx).runs()
    audit = [r for r in ctx.audit.records() if r["action"] == "discovery.scopes"][-1]
    assert audit["details"]["range_input"]["exclude"] == body["exclude"]
    assert audit["details"]["reason"] == body["reason"]
    public = {"include": ["8.8.8.8"], "reason": "Explicit permitted external address"}
    assert client.put(f"{API}/discovery/scopes/ranges", json=public, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/discovery/scopes/ranges", json={**public, "allow_public": True}, headers=ACTOR).status_code == 200
    assert client.put(f"{API}/discovery/scopes/ranges", json={"include": ["fd00::/64"], "reason": "too big"}, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/discovery/scopes/ranges", json={"include": [], "reason": "Remove search authorization"}, headers=ACTOR).json()["scopes"] == []


@pytest.mark.parametrize("stop", ["scope", "kill", "missing", "after_start", "after_transport"])
def test_explicit_connection_test_guards_before_target_io(client, ctx, monkeypatch, stop):
    client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR)
    called = []
    def forbidden(*args):
        called.append("transport")
        pytest.fail("connection should be blocked before creating a transport")
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    if stop == "scope":
        ctx.inventory.update("host-01", in_scope=False)
        ctx.inventory.save()
    elif stop == "kill":
        ctx.killswitch.engage("operator", "hold")
    elif stop == "missing":
        ctx.inventory.path.unlink()
    elif stop == "after_start":
        append = ctx.audit.append
        def remove(action, *args, **kwargs):
            result = append(action, *args, **kwargs)
            if action == "inventory.discover_started":
                ctx.inventory.path.unlink()
            return result
        monkeypatch.setattr(ctx.audit, "append", remove)
    else:
        from cyberthunder.transport.fixture import FixtureTransport
        transport = FixtureTransport(FIXTURES / "host1")
        def remove(target):
            ctx.inventory.path.unlink()
            return transport
        monkeypatch.setattr(ctx, "transport_for", remove)
        monkeypatch.setattr(ctx.adapter_for(ctx.inventory.get("host-01")), "discover", lambda *args: pytest.fail("adapter called without scope"))
    response = client.post(f"{API}/targets/host-01/discover", headers=ACTOR)
    assert response.status_code == (423 if stop == "kill" else 403), response.text
    assert not called


def test_explicit_fake_connection_success_and_failure_are_audited(client, ctx, monkeypatch):
    from cyberthunder.transport.fixture import FixtureTransport
    client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR)
    monkeypatch.setattr(ctx, "transport_for", lambda target: FixtureTransport(FIXTURES / "host1"))
    response = client.post(f"{API}/targets/host-01/discover", headers=ACTOR)
    assert response.status_code == 200 and response.json()["os_name"] == "Rocky Linux"
    assert not ctx.store.list_scan_runs()
    def fail(target):
        raise TransportError("not connected")
    monkeypatch.setattr(ctx, "transport_for", fail)
    assert client.post(f"{API}/targets/host-01/discover", headers=ACTOR).status_code == 503
    assert [r["outcome"] for r in ctx.audit.records() if r["action"] == "inventory.discover"] == ["ok", "error"]


def test_registration_preserves_stale_and_concurrent_inventory_writers(ctx):
    first = Inventory.load(ctx.inventory.path)
    second = Inventory.load(ctx.inventory.path)
    first.add_new(Target("existing", "Existing", "linux", in_scope=False))
    second.add_new(Target("new", "New", "windows", transport="winrm", in_scope=False))
    assert {t.id for t in Inventory.load(ctx.inventory.path).all()} == {"existing", "new"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        writers = [Inventory.load(ctx.inventory.path) for _ in range(2)]
        def create(writer):
            try:
                writer.add_new(Target("same", "Same", "linux", in_scope=False))
                return "created"
            except FileExistsError:
                return "duplicate"
        assert sorted(pool.map(create, writers)) == ["created", "duplicate"]
    stale = Inventory.load(ctx.inventory.path)
    code = "from cyberthunder.inventory.targets import Inventory,Target;import sys;Inventory.load(sys.argv[1]).add_new(Target('child','Child','linux',in_scope=False))"
    subprocess.run([sys.executable, "-c", code, str(ctx.inventory.path)], cwd=Path(__file__).resolve().parents[2], check=True, timeout=15)
    stale.update("existing", name="Locally edited")
    stale.save()
    saved = Inventory.load(ctx.inventory.path)
    assert saved.get("child").in_scope is False and saved.get("existing").name == "Locally edited"


def test_local_transport_readiness_explains_container_boundary(client, ctx, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "marker")
    ctx.inventory.add_new(Target("local", "Local", "linux", transport="local", in_scope=True))
    response = client.get(f"{API}/targets/local/readiness")
    assert response.status_code == 200 and not response.json()["ready_for_connection_test"]
    assert any("inside this container" in text for text in response.json()["warnings"])


def test_normalization_save_requires_server_ack_and_recomputes_inputs(client, ctx):
    from cyberthunder.discovery.service import service_for
    body = {"include": ["192.168.1.20/24"], "reason": "Authorized subnet"}
    preview = client.post(f"{API}/discovery/scopes/preview", json={"include": body["include"]}).json()
    assert preview["requires_normalization_acknowledgment"] and not preview["can_save"]
    assert preview["normalizations"][0]["normalized"] == "192.168.1.0/24"
    assert client.put(f"{API}/discovery/scopes/ranges", json=body, headers=ACTOR).status_code == 400
    assert not service_for(ctx).scopes()
    for value in ("true", 1, None):
        assert client.put(f"{API}/discovery/scopes/ranges", json={**body, "acknowledge_normalization": value}, headers=ACTOR).status_code == 400
    response = client.put(f"{API}/discovery/scopes/ranges", json={**body, "acknowledge_normalization": True}, headers=ACTOR)
    assert response.status_code == 200 and response.json()["preview"]["can_save"]
    assert response.json()["scopes"][0]["cidr"] == "192.168.1.0/24"
    # A prior valid preview cannot authorize changed input. The server recomputes the submitted body.
    changed = {**body, "include": ["192.168.1.20/8"], "acknowledge_normalization": True}
    assert client.put(f"{API}/discovery/scopes/ranges", json=changed, headers=ACTOR).status_code == 400
    assert [s.cidr for s in service_for(ctx).scopes()] == ["192.168.1.0/24"]
    audit = [r for r in ctx.audit.records() if r["action"] == "discovery.scopes"][-1]
    assert audit["details"]["range_input"]["acknowledge_normalization"] is True
    assert audit["details"]["range_input"]["include"] == body["include"]
    legacy = {"scopes": [{"cidr": "192.168.2.20/24"}], "reason": "Legacy caller"}
    assert client.put(f"{API}/discovery/scopes", json=legacy, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/discovery/scopes", json={**legacy, "acknowledge_normalization": True}, headers=ACTOR).status_code == 200
