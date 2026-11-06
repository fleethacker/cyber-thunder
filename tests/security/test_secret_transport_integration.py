"""Lease integration through real loopback SSH and inert WinRM sessions."""
from dataclasses import replace
import json
from types import SimpleNamespace
import traceback
import uuid

import paramiko
import pytest
import requests
import winrm

from cyberthunder.control.principal import current_principal, principal_scope
from cyberthunder.security import secret_resolver as sr
from cyberthunder.security.credentials import bind_target
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.trust import TrustError, key_fingerprint
from cyberthunder.transport.winrm import WinRMTransport
from tests.security.test_secret_resolver import account, no_canary
from tests.transport.conftest import certificates, ssh_keys, ssh_peer


def selected_use(a, target):
    a.ctx.inventory.add(target)
    a.ctx.inventory.save()
    credential = a.policy["entries"][0]["grants"][0]["credential"]
    credential["options"] = {"transport": "ntlm"} if target.transport == "winrm" else {}
    a.policy_path.write_text(json.dumps(a.policy), encoding="utf-8")
    binding = a.ctx.access.credential(a.person, "scan", target)
    stamp = target.to_dict()

    def guard():
        if current_principal() != a.person:
            raise PermissionError("wrong session")
        a.ctx.authorize("scan", target=target)
        a.ctx.killswitch.guard("target.access", a.person.actor)
        if (a.ctx.inventory.get(target.id).to_dict() != stamp
                or a.ctx.access.credential(a.person, "scan", target).evidence() != binding.evidence()):
            raise PermissionError("changed target or binding")

    use = a.resolver.bind(binding, principal=a.person, target=target, purpose="scan", guard=guard, on_event=a.audit)
    return bind_target(target, binding), use


@pytest.mark.parametrize("backend", ["mounted", "wincred"])
def test_real_loopback_ssh_authenticates_without_environment_secret(account, ssh_keys, ssh_peer, monkeypatch, backend):
    a = account
    monkeypatch.delenv("CT_CRED_SCOPED", raising=False)
    with principal_scope(a.person), ssh_peer(ssh_keys[0]) as peer:
        target = replace(a.target, port=peer.port, options={"host_key_sha256": key_fingerprint(ssh_keys[0])})
        selected, use = selected_use(a, target)
        if backend == "wincred":
            from cyberthunder.security import _wincred
            from tests.security.test_wincred_resolver import FakeNative
            name = sr.windows_target_name(use.binding, a.person, target)
            native = FakeNative(name, use.binding.username, a.canary)
            monkeypatch.setattr(_wincred, "_api", lambda: native)
            resolver = sr.SecretResolver({"SCOPED": sr.WindowsCredential(name)}, security_mode="fleet", auth_mode="oidc")
            use = resolver.bind(use.binding, principal=a.person, target=target, purpose="scan",
                                guard=use.guard, on_event=a.audit)
        with SSHTransport.from_target(selected, a.ctx.settings, credential_use=use) as transport:
            assert transport._password is None and transport._key is None
            assert transport.run("fixture-read").stdout == "loopback-ok\n"
            assert transport._client.get_transport().auth_handler.password is None
        assert peer.auth == [(a.binding.username, a.canary)]
        assert peer.commands == [b"fixture-read"] and not peer.failures
    assert [event.action for event in a.events] == ["credential.resolve"]
    assert a.events[0].backend == backend
    no_canary(a.ctx.audit.path.read_text(), a.canary)


def test_ssh_authentication_failure_sanitizes_and_releases_lease(account, monkeypatch):
    a = account
    closed, leases = [], []
    original = sr.CredentialUse.lease
    def record(use):
        lease = original(use)
        leases.append(lease)
        return lease
    monkeypatch.setattr(sr.CredentialUse, "lease", record)
    def connect(client, host, **kwargs):
        assert kwargs["password"] == a.canary
        assert kwargs["look_for_keys"] is False and kwargs["allow_agent"] is False
        assert kwargs["timeout"] <= 30
        raise paramiko.AuthenticationException(a.canary)
    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    monkeypatch.setattr(paramiko.SSHClient, "close", lambda _: closed.append(True))
    with principal_scope(a.person):
        transport = SSHTransport.from_target(a.selected, a.ctx.settings, credential_use=a.use)
        with pytest.raises(TransportError) as error:
            transport.run("safe-command")
    assert closed and transport._password is None and transport._client is None
    assert len(leases) == 1 and leases[0]._closed and leases[0]._secret is None
    assert [e.action for e in a.events] == ["credential.resolve", "credential.failed"]
    assert a.events[-1].reason == "authentication"
    assert error.value.__context__ is None
    no_canary("".join(traceback.format_exception(error.value)) + a.ctx.audit.path.read_text(), a.canary)


@pytest.fixture
def winrm_case(account, certificates, monkeypatch):
    a = account
    made, leases = [], []
    target = replace(a.target, asset_type="windows", transport="winrm", options={
        "ssl": True, "ca_trust_path": certificates["ca"], "transport": "ntlm"})
    with principal_scope(a.person):
        selected, use = selected_use(a, target)
    original = sr.CredentialUse.lease
    def record(use):
        lease = original(use)
        leases.append(lease)
        return lease
    monkeypatch.setattr(sr.CredentialUse, "lease", record)

    class Session:
        def __init__(self, endpoint, *, auth, **kwargs):
            self.endpoint, self.auth, self.kwargs = endpoint, auth, kwargs
            self.closed, self.messages, self.commands = False, [], []
            self.failure, self.after_send = None, None
            self.http = requests.Session()
            self.protocol = SimpleNamespace(transport=SimpleNamespace(
                build_session=lambda: self.http, send_message=self.send, close_session=self.close,
                password=auth[1], session=self.http))
            made.append(self)

        def close(self):
            self.closed = True
            self.http.close()

        def send(self, message):
            self.messages.append(message)
            if self.after_send:
                self.after_send()
            if self.failure:
                raise self.failure
            return b"fixture-response"

        def run_ps(self, command):
            self.commands.append(command)
            self.protocol.transport.send_message("fixture SOAP without credentials")
            return SimpleNamespace(status_code=0, std_out=b"fixture-ok", std_err=b"")

    monkeypatch.setattr(winrm, "Session", Session)
    monkeypatch.delenv("CT_CRED_SCOPED", raising=False)
    with principal_scope(a.person):
        transport = WinRMTransport.from_target(selected, a.ctx.settings, credential_use=use)
    return a, transport, made, leases, Session


def test_winrm_per_operation_lease_closes_session_and_reads_rotation(winrm_case):
    a, transport, made, leases, _ = winrm_case
    rotated = "rotated-fixture-" + uuid.uuid4().hex
    with principal_scope(a.person):
        assert transport.run("safe-one").stdout == "fixture-ok"
        a.path.write_text(rotated, encoding="utf-8")
        assert transport.run("safe-two").ok
    assert [s.auth for s in made] == [(a.binding.username, a.canary), (a.binding.username, rotated)]
    assert all(s.closed for s in made) and all(lease._closed for lease in leases)
    assert all(s.protocol.transport.password is None and s.http.auth is None for s in made)
    assert transport._password is None and transport._session is None
    assert all(s.kwargs["transport"] == "ntlm" and s.kwargs["read_timeout_sec"] <= 30
               and s.kwargs["operation_timeout_sec"] < s.kwargs["read_timeout_sec"] for s in made)
    no_canary(repr([s.commands + s.messages for s in made]) + a.ctx.audit.path.read_text(), a.canary)
    no_canary(a.ctx.audit.path.read_text(), rotated)


def test_winrm_logon_failure_sanitizes_audits_and_closes(winrm_case, monkeypatch):
    from winrm.exceptions import InvalidCredentialsError
    a, transport, made, leases, Session = winrm_case
    original = Session.send
    def fail(session, message):
        session.failure = InvalidCredentialsError(a.canary)
        return original(session, message)
    monkeypatch.setattr(Session, "send", fail)
    with principal_scope(a.person), pytest.raises(TransportError) as error:
        transport.run("safe-command")
    assert made[0].closed and leases[0]._closed and transport._session is None
    assert [e.action for e in a.events] == ["credential.resolve", "credential.failed"]
    assert error.value.__context__ is None
    no_canary("".join(traceback.format_exception(error.value)) + a.ctx.audit.path.read_text(), a.canary)


def test_winrm_rechecks_revocation_between_protocol_messages(winrm_case, monkeypatch):
    a, transport, made, leases, Session = winrm_case
    original = Session.send
    def revoke(session, message):
        a.policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        return original(session, message)
    monkeypatch.setattr(Session, "send", revoke)
    with principal_scope(a.person), pytest.raises(TransportError):
        transport.run("safe-command")
    assert len(made[0].messages) == 1 and made[0].closed and leases[0]._closed
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        transport.run("must-not-start")
    assert len(made) == 1


def test_actual_winrm_sdk_password_references_are_released_without_network(account, certificates, monkeypatch):
    a = account
    monkeypatch.setattr(requests.Session, "send", lambda *_args, **_kw: pytest.fail("unexpected network call"))
    target = replace(a.target, asset_type="windows", transport="winrm", options={
        "ssl": True, "ca_trust_path": certificates["ca"], "transport": "ntlm"})
    with principal_scope(a.person):
        selected, use = selected_use(a, target)
        transport = WinRMTransport.from_target(selected, a.ctx.settings, credential_use=use)
        with transport._operation_session() as (session, lease):
            provider = session.protocol.transport
            http = provider.session
            assert provider.password == a.canary and http.auth is not None
        assert provider.password is None and http.auth is None and lease._closed


@pytest.mark.parametrize("kind", ["ssh", "winrm"])
def test_fleet_refuses_legacy_environment_reference_before_read(account, certificates, monkeypatch, kind):
    a = account
    target = replace(a.selected, transport=kind, asset_type="linux" if kind == "ssh" else "windows")
    if kind == "winrm":
        target.options = {**target.options, "transport": "ntlm", "ssl": True, "ca_trust_path": certificates["ca"]}
    def forbidden(*args):
        pytest.fail("fleet consulted environment credentials")
    monkeypatch.setattr("cyberthunder.transport.ssh.credential_from_env", forbidden)
    transport_type = SSHTransport if kind == "ssh" else WinRMTransport
    with pytest.raises(TrustError) as error:
        transport_type.from_target(target, a.ctx.settings)
    assert error.value.code == "transport:credential_resolver_required"


def test_development_environment_reference_still_works(account, monkeypatch):
    monkeypatch.setenv("CT_CRED_SCOPED", account.canary)
    transport = SSHTransport.from_target(account.selected, SimpleNamespace(security_mode="range", auth_mode="dev"))
    assert transport._password == account.canary and transport._key is None


def test_unbound_fleet_alias_never_probes_a_same_named_local_file(account, monkeypatch):
    from pathlib import Path
    target = replace(account.target, credential_ref="SCOPED", username="remote-reader")
    monkeypatch.setattr(Path, "is_file", lambda *_: pytest.fail("fleet alias reinterpreted as a file"))
    with pytest.raises(TrustError) as error:
        SSHTransport.from_target(target, account.ctx.settings)
    assert error.value.code == "transport:credential_resolver_required"


@pytest.mark.parametrize("change", [{"username": "other"}, {"address": "different.fixture.test"}, {"credential_ref": "OTHER"}])
def test_transport_rejects_another_selected_account_before_lookup(account, monkeypatch, change):
    a = account
    monkeypatch.setattr(sr, "_read_mounted", lambda *_: pytest.fail("mismatched credential lookup"))
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        SSHTransport.from_target(replace(a.selected, **change), a.ctx.settings, credential_use=a.use)
