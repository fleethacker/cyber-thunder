from __future__ import annotations

import traceback
from types import SimpleNamespace

import paramiko
import pytest

from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.trust import TrustError, key_fingerprint


def fleet(peer, key, **kwargs):
    return SSHTransport("127.0.0.1", port=peer.port, username="loopback-user", password="loopback-secret",
                        security_mode="fleet", host_key_sha256=key_fingerprint(key), connect_timeout=3, **kwargs)


def test_real_pin_handshake_then_command(ssh_keys, ssh_peer):
    with ssh_peer(ssh_keys[0]) as peer, fleet(peer, ssh_keys[0]) as transport:
        result = transport.run("loopback-read")
        assert result.ok and result.stdout == "loopback-ok\n"
        assert peer.auth == [("loopback-user", "loopback-secret")]
        assert peer.commands == [b"loopback-read"]
        assert transport.security_events == []


def test_changed_pin_rejected_before_authentication(ssh_keys, ssh_peer, caplog):
    events = []
    with ssh_peer(ssh_keys[1]) as peer, fleet(peer, ssh_keys[0], on_security_event=events.append) as transport:
        with pytest.raises(TrustError, match="provisioned pin") as error:
            transport.run("must-never-run")
        assert error.value.code == "discovery:identity_changed"
        assert peer.auth == [] and peer.commands == []
        assert events == transport.security_events and events[0].severity == "high"
        assert events[0].to_dict()["verified"] is False
        assert "loopback-secret" not in caplog.text + repr(events) + str(error.value)
        assert transport._client is None


@pytest.mark.parametrize("hashed", [False, True])
def test_provisioned_known_hosts_handshake(ssh_keys, ssh_peer, tmp_path, hashed):
    with ssh_peer(ssh_keys[0]) as peer:
        host = f"[127.0.0.1]:{peer.port}"
        if hashed:
            host = paramiko.HostKeys.hash_host(host)
        path = tmp_path / "known_hosts"
        original = f"{host} {ssh_keys[0].get_name()} {ssh_keys[0].get_base64()}\n"
        path.write_text(original)
        with SSHTransport("127.0.0.1", port=peer.port, username="u", password="p", security_mode="fleet",
                          known_hosts=str(path), connect_timeout=3) as transport:
            assert transport.run("read").ok
        assert path.read_text() == original


@pytest.mark.parametrize("unknown", [False, True])
def test_known_hosts_unknown_or_changed_never_authenticates(ssh_keys, ssh_peer, tmp_path, unknown):
    with ssh_peer(ssh_keys[1]) as peer:
        path = tmp_path / "known_hosts"
        host = "other.invalid" if unknown else f"[127.0.0.1]:{peer.port}"
        path.write_text(f"{host} {ssh_keys[0].get_name()} {ssh_keys[0].get_base64()}\n")
        with SSHTransport("127.0.0.1", port=peer.port, username="u", password="p", security_mode="fleet",
                          known_hosts=str(path), connect_timeout=3) as transport:
            with pytest.raises(TrustError) as error:
                transport.run("must-never-run")
            assert error.value.code == ("transport:unknown_host_key" if unknown else "discovery:identity_changed")
            assert peer.auth == [] and peer.commands == []
            assert transport.security_events[0].severity == "high"


@pytest.mark.parametrize("overrides", [{}, {"allow_insecure_range": True}])
def test_fleet_missing_trust_refused_without_client(monkeypatch, overrides):
    monkeypatch.setattr(paramiko, "SSHClient", lambda: pytest.fail("untrusted target constructed client"))
    with pytest.raises(TrustError, match="requires a host key"):
        SSHTransport("localhost", security_mode="fleet", **overrides)


@pytest.mark.parametrize("pin", ["", "MD5:abcd", "SHA256:abc", "SHA256:" + "!" * 43,
                                 "SHA256:" + "A" * 42 + "B", False, ["SHA256:abc"]])
def test_malformed_pins_fail_closed(pin):
    with pytest.raises(TrustError, match="SHA256"):
        SSHTransport("localhost", security_mode="fleet", host_key_sha256=pin)


def test_range_requires_explicit_exception_and_never_claims_verified(ssh_keys, ssh_peer):
    with ssh_peer(ssh_keys[0]) as peer:
        with SSHTransport("127.0.0.1", port=peer.port, password="p") as transport:
            with pytest.raises(TrustError, match="requires a host key"):
                transport._conn()
            assert peer.auth == []
        with SSHTransport("127.0.0.1", port=peer.port, password="p", allow_insecure_range=True) as transport:
            assert transport.run("read").ok
            assert len(transport.security_events) == 1
            assert transport.security_events[0].verified is False
            assert "unverified" in transport.security_events[0].message


@pytest.mark.parametrize("credential", ["password", "key", "interactive_agent"])
def test_no_implicit_keys_and_agent_only_explicit_interactive(monkeypatch, tmp_path, ssh_keys, credential):
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda _self, *args, **kw: calls.append(kw))
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda *args: pytest.fail("implicit host trust"))
    key = tmp_path / "explicit_key"
    key.write_text("fixture; connect is replaced")
    kwargs = {"password": "p"} if credential == "password" else (
        {"key_filename": str(key)} if credential == "key" else {"interactive": True, "allow_agent": True})
    with SSHTransport("localhost", security_mode="fleet", host_key_sha256=key_fingerprint(ssh_keys[0]), **kwargs) as tr:
        tr._conn()
    assert calls[0]["look_for_keys"] is False
    assert calls[0]["allow_agent"] is (credential == "interactive_agent")
    assert calls[0]["auth_timeout"] == calls[0]["banner_timeout"] == calls[0]["channel_timeout"] == 20
    if credential == "key":
        assert calls[0]["key_filename"] == str(key)


def test_no_credential_fails_before_network(monkeypatch):
    monkeypatch.setattr(paramiko, "SSHClient", lambda: pytest.fail("implicit credential attempt"))
    with pytest.raises(TransportError, match="explicit password"):
        SSHTransport("localhost", allow_insecure_range=True)._conn()


def test_connector_agent_override_cannot_grant_interactive_access(monkeypatch):
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda _self, *a, **kw: calls.append(kw))
    with SSHTransport("localhost", password="p", allow_insecure_range=True) as tr:
        client = tr.connect_client(allow_agent=True)
        client.close()
    assert calls[0]["allow_agent"] is False and calls[0]["look_for_keys"] is False


def test_connector_combines_transport_authorization_with_probe_guard(monkeypatch):
    connected, closed, probe_checks = [], [], []

    def authorization():
        if connected:
            raise PermissionError("authorization revoked during connection")

    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **kw: connected.append(True))
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda *a: closed.append(True))
    tr = SSHTransport("localhost", password="p", allow_insecure_range=True, guard=authorization)
    with pytest.raises(PermissionError, match="revoked during connection"):
        tr.connect_client(guard=lambda: probe_checks.append(True))
    assert closed == [True] and probe_checks


def test_inventory_cannot_enable_interactive_agent_by_itself(ssh_keys):
    target = Target("t", "t", "linux", address="localhost",
                    options={"host_key_sha256": key_fingerprint(ssh_keys[0]), "allow_agent": True, "interactive": True})
    with pytest.raises(TrustError, match="interactive invocation"):
        SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet"))
    tr = SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet"), interactive=True)
    assert tr.allow_agent and tr.interactive


@pytest.mark.parametrize("operation", ["run", "read_file", "write_file", "open_shell", "fetch", "connect_client"])
def test_guard_checked_even_with_cached_connection(operation, tmp_path):
    class Revoked(RuntimeError):
        pass

    calls = []

    def guard():
        calls.append(True)
        raise Revoked("scope revoked")

    tr = SSHTransport("localhost", password="p", allow_insecure_range=True, guard=guard)
    tr._client = object()  # would explode if touched before the guard
    args = {"run": ("read",), "read_file": ("/path",), "write_file": ("/path", b"x"),
            "open_shell": (), "fetch": ("/path", str(tmp_path / "out")), "connect_client": ()}
    with pytest.raises(Revoked):
        getattr(tr, operation)(*args[operation])
    assert calls == [True]


def test_guard_failure_after_handshake_closes_client_without_translation(monkeypatch):
    class Revoked(RuntimeError):
        pass

    calls, closed = [], []

    def guard():
        calls.append(True)
        if len(calls) == 4:
            raise Revoked("killed after handshake")

    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *args, **kwargs: None)
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda *args: closed.append(True))
    tr = SSHTransport("localhost", password="p", allow_insecure_range=True, guard=guard)
    with pytest.raises(Revoked):
        tr.connect_client()
    assert closed == [True]


def test_exception_text_and_traceback_do_not_expose_credentials(monkeypatch):
    def connect(*args, **kwargs):
        raise RuntimeError("secret-password private-key body auth-header")

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    tr = SSHTransport("localhost", password="secret-password", allow_insecure_range=True)
    with pytest.raises(TransportError) as error:
        tr.run("sensitive-command")
    formatted = "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "private-key body auth-header" not in formatted
    assert str(error.value) == "SSH connection or authentication failed"


def test_event_sink_failure_aborts_before_authentication(ssh_keys, ssh_peer):
    def unavailable(_event):
        raise RuntimeError("sink secret")

    with ssh_peer(ssh_keys[1]) as peer, fleet(peer, ssh_keys[0], on_security_event=unavailable) as tr:
        with pytest.raises(TrustError, match="could not be recorded"):
            tr._conn()
        assert peer.auth == []


def test_settings_defaults_and_no_target_mode_override(ssh_keys, monkeypatch, tmp_path):
    monkeypatch.setenv("CT_CRED_LOOPBACK", "p")
    target = Target("t", "t", "linux", address="localhost", credential_ref="LOOPBACK",
                    options={"security_mode": "range"})
    assert SSHTransport.from_target(target, SimpleNamespace()).security_mode == "range"
    with pytest.raises(TrustError):
        SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet"))
    target.options["host_key_sha256"] = key_fingerprint(ssh_keys[0])
    with pytest.raises(TrustError) as error:
        SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet"))
    assert error.value.code == "transport:credential_resolver_required"
    target.credential_ref = None
    target.options["key_file"] = str(tmp_path / "fixture-key")
    assert SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet")).security_mode == "fleet"


@pytest.mark.parametrize("kind", ["missing", "directory", "malformed_hash", "oversized"])
def test_invalid_known_hosts_never_reaches_connect(kind, ssh_keys, tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    if kind == "directory":
        path.mkdir()
    elif kind == "malformed_hash":
        path.write_text(f"|1|!secret!|!secret! {ssh_keys[0].get_name()} {ssh_keys[0].get_base64()}\n")
    elif kind == "oversized":
        path.write_bytes(b"#" * (1024 * 1024 + 1))
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **kw: pytest.fail("invalid trust reached network"))
    with SSHTransport("localhost", security_mode="fleet", password="p", known_hosts=str(path)) as tr:
        with pytest.raises(TrustError) as error:
            tr._conn()
        assert "secret" not in str(error.value)
