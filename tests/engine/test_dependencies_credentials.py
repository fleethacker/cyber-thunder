"""Scoped dependency reads against inert peers and unique disposable credentials."""
from dataclasses import replace
import base64
import json
import time
import traceback
from types import SimpleNamespace
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import paramiko
import pytest
import requests
import winrm

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.control.principal import principal_scope
from cyberthunder.remediation import dependencies_io as io
from cyberthunder.security import secret_resolver as sr
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.winrm import WinRMTransport
from tests.security.test_secret_resolver import account, no_canary
from tests.security.test_secret_transport_integration import selected_use
from tests.transport.conftest import certificates


def release_message(shell, command=None):
    action = ("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal" if command is not None
              else "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete")
    body = (f'<rsp:Signal CommandId="{escape(command)}"><rsp:Code>'
            'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate'
            '</rsp:Code></rsp:Signal>') if command is not None else ""
    return ('<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
            'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            f'<env:Header><a:Action>{action}</a:Action><w:SelectorSet>'
            f'<w:Selector Name="ShellId">{escape(shell)}</w:Selector></w:SelectorSet></env:Header>'
            f'<env:Body>{body}</env:Body></env:Envelope>')


@pytest.fixture(params=["ssh", "winrm"])
def peer(account, certificates, monkeypatch, request):
    a = account
    p = SimpleNamespace(account=a, kind=request.param, calls=[], authenticated=[], sessions=[], leases=[],
                        output=b'{"dependency":"fixture"}', stderr=b"", exit_code=0, done=True,
                        hook=lambda stage: None, fail_cleanup=False, clock=[100.0], wire_timeouts=[])
    # Patch only module-local clocks; authentication's wall clock remains real.
    clock = SimpleNamespace(monotonic=lambda: p.clock[0], time=time.time, sleep=lambda dt: p.clock.__setitem__(0, p.clock[0] + dt))
    p.time = clock
    monkeypatch.setattr(io, "time", clock)
    monkeypatch.setattr(sr, "time", clock)
    monkeypatch.setattr("cyberthunder.transport.ssh.time", clock)
    monkeypatch.setattr("cyberthunder.transport.winrm.time", clock)
    original = sr.CredentialUse.lease

    def lease(use):
        result = original(use)
        p.leases.append(result)
        return result

    monkeypatch.setattr(sr.CredentialUse, "lease", lease)

    class Channel:
        def __init__(self):
            self.read = self.read_error = self.closed = False

        def settimeout(self, timeout):
            p.wire_timeouts.append(timeout)

        def exec_command(self, command):
            p.calls.append("run")
            p.hook("run")

        def recv_ready(self):
            return not self.read and bool(p.output)

        def recv(self, size):
            self.read = True
            p.calls.append("read")
            p.hook("read")
            return p.output

        def recv_stderr_ready(self):
            return not self.read_error and bool(p.stderr)

        def recv_stderr(self, size):
            self.read_error = True
            return p.stderr

        def exit_status_ready(self):
            return p.done

        def recv_exit_status(self):
            return p.exit_code

        def close(self):
            self.closed = True
            p.calls.append("channel_close")
            if p.fail_cleanup:
                raise RuntimeError(a.canary)

    class Client:
        def __init__(self):
            self.channel = Channel()
            self.auth_handler = SimpleNamespace(password=None)
            self.closed = False
            p.sessions.append(self)

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, host, **kwargs):
            assert not kwargs["allow_agent"] and not kwargs["look_for_keys"]
            p.authenticated.append(kwargs["password"])
            self.auth_handler.password = kwargs["password"]
            p.wire_timeouts.append(kwargs["timeout"])
            p.calls.append("auth")
            p.hook("auth")

        def get_transport(self):
            return self

        def open_session(self, *, timeout):
            p.wire_timeouts.append(timeout)
            p.calls.append("open")
            p.hook("open")
            return self.channel

        def close(self):
            self.closed = True
            p.calls.append("client_close")

    class Provider:
        def __init__(self, password):
            self.password, self.encryption = password, None
            self.session = requests.Session()
            self.closed = False
            self.read_timeout_sec = 90

        def build_session(self):
            return self.session

        def send_message(self, stage):
            if stage.startswith("<"):
                action = ET.fromstring(stage).find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action").text
                stage = "cleanup" if action.endswith("/Signal") else "close"
            p.calls.append(stage)
            p.wire_timeouts.append(self.read_timeout_sec)
            if stage == "open":
                p.authenticated.append(self.password)
            p.hook(stage)
            if p.fail_cleanup and stage in {"cleanup", "close"}:
                raise RuntimeError(a.canary)
            return b"fixture"

        def close_session(self):
            self.closed = True
            if self.session is not None:
                self.session.close()
            p.calls.append("session_close")

    class Protocol:
        def __init__(self, password):
            self.password = password
            self.transport = Provider(password)
            self.operation_timeout_sec = 60

        def open_shell(self, **kwargs):
            self.transport.send_message("open")
            return "owned-shell"

        def run_command(self, shell, program, arguments):
            assert shell == "owned-shell"
            self.transport.send_message("run")
            return "owned-command"

        def get_command_output_raw(self, shell, command):
            assert (shell, command) == ("owned-shell", "owned-command")
            self.transport.send_message("read")
            return p.output, p.stderr, p.exit_code, p.done

        def cleanup_command(self, shell, command):
            assert (shell, command) == ("owned-shell", "owned-command")
            self.transport.send_message(release_message(shell, command))

        def close_shell(self, shell, close_session=True):
            assert shell == "owned-shell"
            self.transport.send_message(release_message(shell))
            if close_session:
                self.transport.close_session()

    class Session:
        def __init__(self, endpoint, *, auth, **kwargs):
            self.protocol = Protocol(auth[1])
            p.sessions.append(self)
            p.hook("session")

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    monkeypatch.setattr(winrm, "Session", Session)
    monkeypatch.setattr(requests.Session, "send", lambda *_a, **_k: pytest.fail("live network forbidden"))
    with principal_scope(a.person):
        if p.kind == "ssh":
            p.transport = SSHTransport.from_target(a.selected, a.ctx.settings, credential_use=a.use)
        else:
            target = replace(a.target, asset_type="windows", transport="winrm", options={
                "ssl": True, "ca_trust_path": certificates["ca"], "transport": "ntlm"})
            selected, use = selected_use(a, target)
            p.transport = WinRMTransport.from_target(selected, a.ctx.settings, credential_use=use)
    return p


def read(p, *, guard=lambda: None, timeout=10):
    with principal_scope(p.account.person):
        return io.read_command(p.transport, "fixed-read", timeout=timeout, guard=guard)


def clean(p):
    assert p.transport._password is None
    assert all(lease._closed and lease._secret is None for lease in p.leases)
    if p.kind == "ssh":
        assert p.transport._client is None
        assert all(s.closed and s.auth_handler.password is None for s in p.sessions)
    else:
        assert p.transport._session is None
        assert all(s.protocol.transport.closed and s.protocol.transport.password is None
                   and s.protocol.password is None for s in p.sessions)
    if p.account.ctx.audit.path.exists():
        no_canary(p.account.ctx.audit.path.read_text(), p.account.canary)


def test_bounded_resolver_success_and_rotation(peer):
    p = peer
    first = read(p)
    rotated = "rotated-" + uuid.uuid4().hex
    p.account.path.write_text(rotated, encoding="utf-8")
    second = read(p)
    assert first == second == p.output.decode()
    assert p.authenticated == [p.account.canary, rotated]
    assert len(p.sessions) == len(p.leases) == 2
    assert all(0 < timeout <= 10 for timeout in p.wire_timeouts)
    clean(p)
    for canary in (p.account.canary, rotated):
        no_canary(first + second + repr(p.calls) + p.account.ctx.audit.path.read_text(), canary)


@pytest.mark.parametrize("change", ["cancel", "deadline", "lease"])
def test_resolution_change_blocks_before_authentication(peer, monkeypatch, change):
    p = peer
    original = sr._read_mounted
    changed = []

    def source(source):
        result = original(source)
        changed.append(True)
        if change == "deadline":
            p.clock[0] += 61
        elif change == "lease":
            p.clock[0] += 31
        return result

    def guard():
        if changed and change == "cancel":
            raise KillSwitchEngaged("cancelled before authentication")

    monkeypatch.setattr(sr, "_read_mounted", source)
    with pytest.raises((PermissionError, TransportError, TimeoutError)):
        read(p, timeout=60, guard=guard)
    assert changed and not p.authenticated
    clean(p)


@pytest.mark.parametrize("stage", ["initial_guard", "credential_guard", "connection", "read"])
def test_absolute_deadline_includes_guards_connection_and_reads(peer, monkeypatch, stage):
    p = peer
    triggered = []

    def expire():
        triggered.append(True)
        p.clock[0] += 11

    if stage == "credential_guard":
        original = p.transport._guard

        def slow_guard():
            original()
            if p.leases and not triggered:
                expire()

        monkeypatch.setattr(p.transport, "_guard", slow_guard)
        monkeypatch.setattr(sr, "_read_mounted", lambda *_: pytest.fail("expired guard reached secret"))
    elif stage in {"connection", "read"}:
        trigger = "auth" if p.kind == "ssh" else "open"
        p.hook = lambda point: expire() if point == ("read" if stage == "read" else trigger) else None

    def guard():
        if stage == "initial_guard" and not triggered:
            expire()

    with pytest.raises((PermissionError, TransportError, TimeoutError)):
        read(p, guard=guard)
    assert triggered
    if stage in {"initial_guard", "credential_guard"}:
        assert not p.authenticated
    elif stage == "connection":
        assert "run" not in p.calls
    clean(p)


def test_remaining_connection_timeout_is_not_reset_after_authorization(peer):
    p = peer
    advanced = []

    def guard():
        if not advanced:
            p.clock[0] += 8
            advanced.append(True)

    assert read(p, guard=guard) == p.output.decode()
    assert p.wire_timeouts and all(0 < value <= 2 for value in p.wire_timeouts)
    clean(p)


@pytest.mark.parametrize("change", ["kill", "principal", "scope", "account", "generation"])
def test_revocation_during_read_discards_output_and_cleans_owned_resources(peer, change):
    p, a = peer, peer.account
    changed = []

    def revoke(stage):
        if stage != "read":
            return
        changed.append(True)
        if change == "principal":
            p.time.time = lambda: a.person.expires_at + 1
        elif change == "scope":
            a.ctx.inventory.get(a.target.id).in_scope = False
            a.ctx.inventory.save()
        elif change == "account":
            a.policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        elif change == "generation":
            a.ctx.inventory.get(a.target.id).authorization_id = uuid.uuid4().hex
            a.ctx.inventory.save()

    def guard():
        if changed and change == "kill":
            raise KillSwitchEngaged("read cancelled")

    p.hook = revoke
    with pytest.raises((KillSwitchEngaged, PermissionError, TransportError)):
        read(p, guard=guard)
    assert p.calls.count("read") == 1
    if p.kind == "winrm":
        assert p.calls[-3:] == ["cleanup", "close", "session_close"]
    clean(p)


@pytest.mark.parametrize("failure", ["stdout", "stderr", "timeout", "exit", "invalid_exit", "exception", "permission", "cleanup"])
def test_failed_or_uncertain_reads_never_return_evidence_or_canaries(peer, failure):
    p = peer
    if failure == "stdout":
        p.output = b"x" * (io.MAX_OUTPUT + 1)
    elif failure == "stderr":
        p.stderr = b"x" * (io.MAX_OUTPUT + 1)
    elif failure == "exit":
        p.exit_code, p.stderr = 1, p.account.canary.encode()
    elif failure == "invalid_exit":
        p.exit_code = False
    elif failure == "cleanup":
        p.fail_cleanup = True
    else:
        def hook(stage):
            if stage == "read":
                if failure == "timeout":
                    p.clock[0] += 11
                else:
                    raise (PermissionError if failure == "permission" else RuntimeError)(p.account.canary)
        p.hook = hook
    with pytest.raises((TransportError, PermissionError)) as error:
        read(p)
    assert error.value.__context__ is None and error.value.__cause__ is None
    no_canary("".join(traceback.format_exception(error.value)), p.account.canary)
    clean(p)


def test_authentication_lease_lifetime_during_collection(peer):
    p = peer
    if p.kind == "ssh":
        # SSH leases cover authentication only; subsequent reads retain fresh
        # account guards and the collector deadline, tested independently above.
        p.hook = lambda stage: p.clock.__setitem__(0, 131) if stage == "read" else None
        assert read(p, timeout=60) == p.output.decode()
    else:
        p.hook = lambda stage: p.clock.__setitem__(0, 131) if stage == "read" else None
        with pytest.raises(PermissionError):
            read(p, timeout=60)
        assert p.calls[-3:] == ["cleanup", "close", "session_close"]
    clean(p)


def test_cleanup_failure_does_not_mask_a_kill_signal(peer):
    p = peer
    p.fail_cleanup = True
    cancelled = []
    p.hook = lambda stage: cancelled.append(True) if stage == "read" else None
    def guard():
        if cancelled:
            raise KillSwitchEngaged("bounded read cancelled")
    with pytest.raises(KillSwitchEngaged):
        read(p, guard=guard)
    assert p.calls.count("read") == 1
    clean(p)


@pytest.mark.parametrize("scenario", ["success", "revoke_open", "revoke_read", "cleanup_receive", "cleanup_budget", "session_close_failure", "authentication", "foreign_cleanup", "uncertain_open"])
def test_actual_winrm_sdk_cleanup_contract_without_network(account, certificates, monkeypatch, scenario):
    from winrm.transport import Transport as Provider
    a = account
    calls, made, passwords, timeouts, refused = [], [], [], [], []
    clock = [100.0]
    local_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    monkeypatch.setattr(io, "time", local_time)
    monkeypatch.setattr("cyberthunder.transport.winrm.time", local_time)
    original = winrm.Session

    def session(*args, **kwargs):
        result = original(*args, **kwargs)
        made.append(result)
        return result

    def send(provider, message):
        root = ET.fromstring(message)
        action = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action").text.rsplit("/", 1)[-1]
        message_id = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}MessageID").text
        calls.append(action)
        passwords.append(provider.password)
        timeouts.append(provider.read_timeout_sec)
        assert provider.session is not None and provider.session.trust_env is False
        if scenario == "authentication" and action == "Create":
            from winrm.exceptions import InvalidCredentialsError
            raise InvalidCredentialsError(a.canary)
        if scenario == "revoke_open" and action == "Create" or scenario == "revoke_read" and action == "Receive":
            a.policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        if scenario == "cleanup_receive" and action == "Signal":
            with pytest.raises(TransportError, match="cleanup message was refused"):
                made[0].protocol.get_command_output_raw("owned-shell", "owned-command")
            refused.append(True)
        if scenario == "cleanup_budget" and action == "Signal":
            clock[0] += 4
        if action == "Create":
            body = ('<w:Selector Name="ShellId">owned-shell</w:Selector>'
                    if scenario != "uncertain_open" else "")
        elif action == "Command":
            body = '<rsp:CommandId>owned-command</rsp:CommandId>'
        elif action == "Receive":
            body = ('<rsp:Stream Name="stdout">' + base64.b64encode(b'{"fact":"fixture"}').decode()
                    + '</rsp:Stream><rsp:CommandState State="CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>')
        else:
            body = ""
        return ('<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" '
                'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
                'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
                'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
                f'<env:Header><a:RelatesTo>{message_id}</a:RelatesTo></env:Header>'
                f'<env:Body>{body}</env:Body></env:Envelope>').encode()

    monkeypatch.setattr(winrm, "Session", session)
    monkeypatch.setattr(Provider, "send_message", send)
    monkeypatch.setattr(requests.Session, "send", lambda *_a, **_kw: pytest.fail("live network forbidden"))
    if scenario == "session_close_failure":
        def close(provider):
            raise RuntimeError(a.canary)
        monkeypatch.setattr(Provider, "close_session", close)
    elif scenario == "foreign_cleanup":
        from winrm.protocol import Protocol
        cleanup = Protocol.cleanup_command
        def foreign(protocol, shell, command):
            return cleanup(protocol, "foreign-shell", command)
        monkeypatch.setattr(Protocol, "cleanup_command", foreign)
    target = replace(a.target, asset_type="windows", transport="winrm", options={
        "ssl": True, "ca_trust_path": certificates["ca"], "transport": "ntlm"})
    with principal_scope(a.person):
        selected, use = selected_use(a, target)
        transport = WinRMTransport.from_target(selected, a.ctx.settings, credential_use=use)
        if scenario in {"success", "cleanup_receive"}:
            result = io.read_command(transport, "fixed-read", timeout=10, guard=lambda: None)
            assert result == '{"fact":"fixture"}'
            no_canary(result, a.canary)
        else:
            with pytest.raises((PermissionError, TransportError)) as error:
                io.read_command(transport, "fixed-read", timeout=10, guard=lambda: None)
            no_canary("".join(traceback.format_exception(error.value)), a.canary)
    assert len(made) == 1 and transport._session is None and transport._password is None
    assert made[0].protocol.password is None and made[0].protocol.transport.password is None
    assert all(p == a.canary for p in passwords) and all(0 < t <= 1.5 for t in timeouts)
    assert calls == (["Create"] if scenario in {"authentication", "uncertain_open"} else
                     ["Create", "Delete"] if scenario == "revoke_open" else
                     ["Create", "Command", "Receive", "Signal"] if scenario == "cleanup_budget" else
                     ["Create", "Command", "Receive", "Delete"] if scenario == "foreign_cleanup" else
                     ["Create", "Command", "Receive", "Signal", "Delete"])
    assert bool(refused) == (scenario == "cleanup_receive")
    if scenario == "authentication":
        assert [(event.action, event.reason) for event in a.events] == [
            ("credential.resolve", None), ("credential.failed", "authentication")]
    no_canary(a.ctx.audit.path.read_text(), a.canary)


def test_cleanup_failure_is_unknown_in_dependency_packet(peer, ctx, tmp_path, monkeypatch):
    from .test_dependencies import ACTOR, SYSTEMD, WINDOWS, seed
    from cyberthunder.remediation import dependencies as dep
    p = peer
    proposal, _, _, _ = seed(ctx, tmp_path, asset="linux" if p.kind == "ssh" else "windows")
    p.output = (SYSTEMD if p.kind == "ssh" else json.dumps(WINDOWS)).encode()
    p.fail_cleanup = True
    monkeypatch.setattr(ctx, "transport_for", lambda target: p.transport)
    with principal_scope(p.account.person):
        packet = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert not packet["dependencies"] and not packet["complete"]
    assert not any(e["kind"] in {"systemd", "windows-service"} for e in packet["evidence"])
    assert any("bounded dependency read failed" in text for text in packet["unknowns"])
    no_canary(json.dumps(packet) + ctx.audit.path.read_text(), p.account.canary)
    clean(p)
