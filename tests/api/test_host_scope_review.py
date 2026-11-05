"""Frozen host/scope review regressions: isolated state, fake transports, no probes."""
import ipaddress
import json
import random
from urllib.parse import urlsplit

import pytest
import yaml

from cyberthunder.discovery.ranges import preview_ranges
from cyberthunder.inventory.targets import Inventory, ScopeViolation, Target
from cyberthunder.transport.base import CommandResult
from .conftest import ACTOR
from .test_host_scope import API, no_network, registration


def rewrite_inventory(ctx, change):
    document = yaml.safe_load(ctx.inventory.path.read_text(encoding="utf-8"))
    change(document)
    ctx.inventory.path.write_text(yaml.safe_dump(document), encoding="utf-8")


def test_missing_persisted_scope_never_defaults_to_authorized(client, ctx, monkeypatch):
    assert client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR).status_code == 201
    rewrite_inventory(ctx, lambda doc: doc["targets"][0].pop("in_scope"))
    no_network(ctx, monkeypatch)
    assert client.get(f"{API}/targets/host-01/readiness").status_code == 403
    assert client.post(f"{API}/targets/host-01/discover", headers=ACTOR).status_code == 403


@pytest.mark.parametrize("stop", ["scope", "kill", "address"])
def test_connection_rechecks_between_remote_operations(client, ctx, monkeypatch, stop):
    from cyberthunder.adapters.linux.adapter import LinuxAdapter
    assert client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR).status_code == 201
    calls = []

    class FakeTransport:
        kind = "ssh"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            calls.append("closed")

        def run(self, command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                if stop == "kill":
                    ctx.killswitch.engage("ITC Rivera", "Stop connection test")
                else:
                    field, value = ("in_scope", False) if stop == "scope" else ("address", "192.168.56.11")
                    rewrite_inventory(ctx, lambda doc: doc["targets"][0].update({field: value}))
            return CommandResult(command, 0, 'NAME="Fixture Linux"\n')

    monkeypatch.setattr(ctx, "adapter_for", lambda target: LinuxAdapter())
    monkeypatch.setattr(ctx, "transport_for", lambda target: FakeTransport())
    response = client.post(f"{API}/targets/host-01/discover", headers=ACTOR)
    assert response.status_code == (423 if stop == "kill" else 403), response.text
    assert len(calls) == 2 and calls[-1] == "closed"
    assert [r["outcome"] for r in ctx.audit.records() if r["action"] == "inventory.discover"] == ["blocked"]


def test_factory_revocation_blocks_transport_enter(client, ctx, monkeypatch):
    assert client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR).status_code == 201
    calls = []

    class FakeTransport:
        def __enter__(self):
            calls.append("entered")
            return self

        def __exit__(self, *exc):
            self.close()

        def close(self):
            calls.append("closed")

    def factory(target):
        ctx.killswitch.engage("ITC Rivera", "Stop during setup")
        return FakeTransport()

    monkeypatch.setattr(ctx, "transport_for", factory)
    response = client.post(f"{API}/targets/host-01/discover", headers=ACTOR)
    assert response.status_code == 423
    assert calls == ["closed"]


@pytest.mark.parametrize("headers", [{}, {"X-Actor": "agent"}, {"X-Actor": "policy:example"}])
def test_connection_actor_refusal_precedes_io(client, ctx, monkeypatch, headers):
    assert client.post(f"{API}/targets/register-host", json=registration(in_scope=True), headers=ACTOR).status_code == 201
    no_network(ctx, monkeypatch)
    assert client.post(f"{API}/targets/host-01/discover", headers=headers).status_code == 400


def test_registration_cannot_replace_persisted_id_with_pending_local_delete(ctx):
    ctx.inventory.add_new(Target("existing", "Original", "linux", in_scope=False))
    ctx.inventory.remove("existing")  # an unsaved local edit cannot authorize replacement
    before = ctx.inventory.path.read_bytes()
    with pytest.raises(FileExistsError):
        ctx.inventory.add_new(Target("existing", "Replacement", "linux", in_scope=True))
    assert ctx.inventory.path.read_bytes() == before


@pytest.mark.parametrize("document", [{}, {"targets": [{"id": "old", "name": "Old", "asset_type": "linux"}]},
                                      {"targets": [{"id": "old", "name": "Old", "asset_type": "linux", "in_scope": "false"}]}])
def test_registration_does_not_rewrite_invalid_inventory_or_grant_scope(ctx, document):
    ctx.inventory.add_new(Target("old", "Old", "linux", in_scope=False))
    ctx.inventory.path.write_text(json.dumps(document), encoding="utf-8")
    before = ctx.inventory.path.read_bytes()
    with pytest.raises(ScopeViolation):
        ctx.inventory.add_new(Target("new", "New", "linux", in_scope=False))
    assert ctx.inventory.path.read_bytes() == before


def test_registration_preserves_concurrent_revocation_and_address(ctx):
    ctx.inventory.add_new(Target("old", "Old", "linux", in_scope=True, address="192.168.56.10"))
    stale = Inventory.load(ctx.inventory.path)
    ctx.inventory.update("old", in_scope=False, address="192.168.56.11")
    ctx.inventory.save()
    stale.add_new(Target("new", "New", "linux", in_scope=False))
    old = Inventory.load(ctx.inventory.path).get("old")
    assert old.in_scope is False and old.address == "192.168.56.11"


@pytest.mark.parametrize("address,private", [("10.0.0.1", True), ("172.15.255.255", False),
    ("172.16.0.0", True), ("172.31.255.255", True), ("172.32.0.0", False), ("169.254.0.1", True),
    ("127.0.0.1", True), ("192.0.2.1", False), ("100.64.0.1", False), ("224.0.0.1", False),
    ("0.0.0.0", False), ("::", False), ("::1", True), ("fc00::1", True), ("fe80::1", True),
    ("2001:db8::1", False), ("::ffff:10.0.0.1", False)])
def test_public_classification_uses_explicit_private_allowlist(address, private):
    assert preview_ranges([address])["can_save"] is private


def test_range_arithmetic_against_small_independent_set_oracle():
    rng = random.Random(4435524)
    for base in (ipaddress.ip_address("10.0.0.0"), ipaddress.ip_address("fd00::")):
        for _ in range(100):
            def entries():
                text, values = [], set()
                for _ in range(rng.randrange(1, 9)):
                    start, end = sorted((rng.randrange(256), rng.randrange(256)))
                    text.append(f"{base + start}-{base + end}")
                    values.update(range(int(base) + start, int(base) + end + 1))
                return text, values
            include, included = entries()
            exclude, excluded = entries()
            result = preview_ranges(include, exclude)
            expected = included - excluded
            actual = {int(a) for n in result["networks"] for a in ipaddress.ip_network(n)}
            assert actual == expected
            assert result["address_count"] == str(len(expected))
            assert result["excluded_address_count"] == str(len(included & excluded))
            assert result["input_address_count"] == str(len(included))


def test_public_exclusion_boundary_and_empty_scope_normalization():
    assert not preview_ranges(["172.15.255.255-172.16.0.1"])["can_save"]
    result = preview_ranges(["172.15.255.255-172.16.0.1"], ["172.15.255.255"])
    assert result["can_save"] and result["address_count"] == "2"
    assert not preview_ranges(["10.0.0.0/24"], ["10.0.0.1/24"], acknowledge_normalization=True)["can_save"]


@pytest.mark.parametrize("address", ["fd00::1234", "192.168.56.10", "host.example."])
def test_registered_windows_address_is_exact_in_transport_endpoint(address, monkeypatch):
    from cyberthunder.inventory.host import host_registration
    from cyberthunder.transport.winrm import WinRMTransport
    monkeypatch.setenv("CT_CRED_HOST_ACCESS", "fixture-only")
    target, _ = host_registration(registration(asset_type="windows", transport="winrm", address=address))
    endpoint = urlsplit(WinRMTransport.from_target(target).endpoint)
    assert endpoint.hostname == address
    assert endpoint.port == 5986 and endpoint.scheme == "https" and endpoint.path == "/wsman"


def test_windows_connection_uses_existing_readonly_facts_script(client, ctx, monkeypatch):
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.transport.base import Transport
    calls = []

    class FakeWindows(Transport):
        kind = "winrm"

        def run(self, command, **kwargs):
            calls.append(command)
            return CommandResult(command, 0, json.dumps({"hostname": "fixture", "os_name": "Windows"}))

        def read_file(self, path):
            pytest.fail("facts should not fetch files")

        def write_file(self, *args, **kwargs):
            pytest.fail("connection test should not stage files")

        def close(self):
            calls.append("closed")

    body = registration(asset_type="windows", transport="winrm", in_scope=True)
    assert client.post(f"{API}/targets/register-host", json=body, headers=ACTOR).status_code == 201
    monkeypatch.setattr(ctx, "adapter_for", lambda target: WindowsAdapter())
    monkeypatch.setattr(ctx, "transport_for", lambda target: FakeWindows())
    response = client.post(f"{API}/targets/host-01/discover", headers=ACTOR)
    assert response.status_code == 200 and response.json()["hostname"] == "fixture", response.text
    assert len(calls) == 2 and calls[-1] == "closed"
