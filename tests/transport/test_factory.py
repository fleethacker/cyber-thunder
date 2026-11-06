"""Factory integration tests exercise policy/callback routing without network I/O."""
from types import SimpleNamespace

import pytest

from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import make_transport
from cyberthunder.transport.trust import TrustError


def target(kind, **options):
    return Target("factory-target", "factory-target", "linux" if kind == "ssh" else "windows",
                  transport=kind, address="localhost", username="fixture-user", credential_ref="FACTORY",
                  options=options)


@pytest.mark.parametrize("kind", ["ssh", "winrm"])
@pytest.mark.parametrize("auth_mode", ["dev", "oidc", "mesh"])
def test_factory_applies_fleet_policy_without_target_or_auth_mode_downgrade(kind, auth_mode, monkeypatch):
    monkeypatch.setenv("CT_CRED_FACTORY", "fixture-secret")
    settings = SimpleNamespace(security_mode="fleet", auth_mode=auth_mode)
    item = target(kind, security_mode="range", allow_insecure_range=True, ssl=False)
    with pytest.raises(TrustError) as error:
        make_transport(item, settings)
    assert error.value.code == ("transport:ssh_trust_required" if kind == "ssh" else "transport:https_required")


@pytest.mark.parametrize("kind", ["ssh", "winrm"])
def test_factory_preserves_range_default_for_older_settings(kind, monkeypatch):
    monkeypatch.setenv("CT_CRED_FACTORY", "fixture-secret")
    assert make_transport(target(kind), SimpleNamespace()).security_mode == "range"
    assert make_transport(target(kind)).security_mode == "range"


def test_factory_preserves_trust_and_kerberos_configuration(certificates, monkeypatch):
    monkeypatch.setenv("CT_CRED_FACTORY", "fixture-secret")
    settings = SimpleNamespace(security_mode="fleet")
    pin = "SHA256:" + "A" * 43
    ssh = make_transport(target("ssh", host_key_sha256=pin), settings)
    winrm = make_transport(target("winrm", ca_trust_path=certificates["ca"]), settings)
    assert ssh.security_mode == "fleet" and ssh.host_key_sha256 == pin
    assert winrm.security_mode == "fleet" and winrm.ssl and winrm.auth == "kerberos"


@pytest.mark.parametrize("kind", ["ssh", "winrm"])
def test_factory_callbacks_are_per_instance_and_guard_cached_operations(kind, monkeypatch):
    from cyberthunder.transport.ssh import SSHTransport
    import winrm

    monkeypatch.setenv("CT_CRED_FACTORY", "fixture-secret")
    monkeypatch.setattr(SSHTransport, "connect_client", lambda *a, **kw: pytest.fail("revoked SSH opened connection"))
    monkeypatch.setattr(winrm, "Session", lambda *a, **kw: pytest.fail("revoked WinRM opened session"))
    events, guards = [[], []], []

    def guard_for(index):
        def guard():
            guards.append(index)
            raise PermissionError("revoked")
        return guard

    transports = [make_transport(target(kind, allow_insecure_range=True), SimpleNamespace(security_mode="range"),
                                 guard=guard_for(index), on_security_event=events[index].append)
                  for index in range(2)]
    if kind == "winrm":
        # Policy evaluation is separate from opening a network session.
        for tr in transports:
            tr._check_policy()
    assert len(events[0]) == len(events[1]) == 1
    assert transports[0].security_events == events[0] and transports[1].security_events == events[1]
    transports[0]._event("transport:test_failure", "Fixed test event")
    assert len(events[0]) == 2 and len(events[1]) == 1
    for tr in transports:
        with pytest.raises(PermissionError, match="revoked"):
            tr.run("must-not-run")
    assert guards == [0, 1]


def test_factory_keeps_adapter_settings_forwarding(monkeypatch):
    from cyberthunder.adapters import registry

    calls = []
    result = object()
    settings = SimpleNamespace(security_mode="fleet", auth_mode="oidc")
    item = Target("sim", "sim", "linux", transport="simulated")
    adapter = SimpleNamespace(make_transport=lambda item, settings: calls.append((item, settings)) or result)
    monkeypatch.setattr(registry, "get", lambda kind: adapter)
    assert make_transport(item, settings) is result
    assert calls == [(item, settings)]
