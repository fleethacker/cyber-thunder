"""Bounded transport readers use fake protocols or local inert subprocesses only."""
import base64
import json
import os
import sys
import time
from types import SimpleNamespace

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.remediation import dependencies as dep, dependencies_io as io
from cyberthunder.remediation.dependencies_services import systemd_command
from cyberthunder.transport.base import CommandResult
from cyberthunder.transport.fixture import FixtureTransport
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.winrm import WinRMTransport

from .test_dependencies import ACTOR, HOST, SYSTEMD, seed, wire


def test_subprocess_bounds_and_unicode():
    result = io._process([sys.executable, "-B", "-c", "print('operational')"], 3)
    assert result.exit_code == 0 and result.stdout.strip() == "operational"
    with pytest.raises(io.ReadFailure, match="output_limit"):
        io._process([sys.executable, "-B", "-c", "import sys;sys.stdout.write('x'*200000)"], 3)
    with pytest.raises(io.ReadFailure, match="output_limit"):
        io._process([sys.executable, "-B", "-c", "import sys;sys.stderr.write('x'*200000)"], 3)
    with pytest.raises(io.ReadFailure, match="timeout"):
        io._process([sys.executable, "-B", "-c", "import time;time.sleep(3)"], 0.05)


@pytest.mark.parametrize("parent_exits", [False, True])
def test_inherited_pipes_do_not_extend_deadline(tmp_path, parent_exits):
    marker = tmp_path / "descendant-finished"
    # Self-terminating inert child; no network or target commands. Parent-exit
    # case also exercises Windows' documented lack of orphan containment.
    child = "import time,pathlib;time.sleep(5);pathlib.Path(" + repr(str(marker)) + ").write_text('finished')"
    parent = ("import subprocess,sys,time;subprocess.Popen([sys.executable,'-B','-c'," + repr(child) + "]);"
              + ("" if parent_exits else "time.sleep(6)"))
    start = time.monotonic()
    with pytest.raises(io.ReadFailure, match="timeout"):
        io._process([sys.executable, "-B", "-c", parent], 0.3)
    elapsed = time.monotonic() - start
    assert elapsed < 0.3 + io.PROCESS_CLEANUP_TIMEOUT + 0.5
    if os.name != "nt" or not parent_exits:
        # The child must have been killed with the owned group/tree. A short
        # liveness check would not distinguish a sleeping child from a dead one.
        time.sleep(max(0, 5.4 - elapsed))
        assert not marker.exists()


def test_process_polls_guard_and_closes_raw_pipes(monkeypatch):
    opened = []
    original = io.subprocess.Popen
    def track(*args, **kwargs):
        proc = original(*args, **kwargs)
        opened.append(proc)
        return proc
    monkeypatch.setattr(io.subprocess, "Popen", track)
    calls = []
    def guard():
        calls.append(True)
        if len(calls) == 3:
            raise KillSwitchEngaged("synthetic cancellation")
    start = time.monotonic()
    with pytest.raises(KillSwitchEngaged):
        io._process([sys.executable, "-B", "-c", "import time;time.sleep(5)"], 3, guard=guard)
    assert time.monotonic() - start < io.PROCESS_CLEANUP_TIMEOUT + 1
    assert opened[0].poll() is not None
    assert opened[0].stdout.closed and opened[0].stderr.closed


class Protocol:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result or (b'{"name":"WinRM"}', b"", 0, True)
        self.error = error
        self.operation_timeout_sec = 60
        from requests import Session
        self.transport = SimpleNamespace(session=Session(), close_session=lambda: None)

        class Sender:
            def send_message(self, message):
                return b"fixture"

        self._sender = Sender()
        self.transport.send_message = self._sender.send_message

    def open_shell(self, **kwargs):
        self.calls.append(("open", kwargs))
        self.transport.send_message("open")
        return "test-shell"

    def run_command(self, shell, program, arguments):
        self.calls.append(("run", program, arguments))
        self.transport.send_message("run")
        return "test-command"

    def get_command_output_raw(self, shell, command):
        self.calls.append(("read",))
        self.transport.send_message("read")
        if self.error:
            raise self.error
        return self.result

    def cleanup_command(self, shell, command):
        from .test_dependencies_credentials import release_message
        self.calls.append(("cleanup",))
        self.transport.send_message(release_message(shell, command))

    def close_shell(self, shell, close_session=True):
        from .test_dependencies_credentials import release_message
        self.calls.append(("close",))
        self.transport.send_message(release_message(shell))


def install_session(monkeypatch, transport, protocol):
    def session(*, lease=None, bounded=None):
        result = SimpleNamespace(protocol=protocol)
        # A fresh provider sender for each operation; never reuse the old guard.
        protocol.transport.send_message = protocol._sender.send_message
        bounded.attach(result)
        return result
    monkeypatch.setattr(transport, "_sess", session)


def test_winrm_frame_bounds_and_cleanup(monkeypatch):
    protocol = Protocol()
    transport = WinRMTransport("fixture", password="private-password")
    install_session(monkeypatch, transport, protocol)
    guard_calls = []
    command = "$s = Get-Service -Name 'WinRM'"
    result = io.read_command(transport, command, timeout=2, guard=lambda: guard_calls.append(True))
    assert result == '{"name":"WinRM"}'
    assert transport.operation_timeout_s == 60 and transport.read_timeout_s == 90
    assert 0 < protocol.transport.read_timeout_sec <= 2
    run = next(call for call in protocol.calls if call[0] == "run")
    assert base64.b64decode(run[2][-1]).decode("utf-16-le") == command
    assert protocol.calls[-2:] == [("cleanup",), ("close",)] and len(guard_calls) >= 4
    protocol.result = (b"x" * (io.MAX_OUTPUT + 1), b"", 0, True)
    with pytest.raises(io.ReadFailure, match="output_limit"):
        io.read_command(transport, command, timeout=2, guard=lambda: None)
    assert protocol.calls[-2:] == [("cleanup",), ("close",)]


def test_winrm_deadline_and_kill_between_open_and_command(monkeypatch):
    from winrm.exceptions import WinRMOperationTimeoutError

    transport = WinRMTransport("fixture", password="private-password")
    protocol = Protocol(error=WinRMOperationTimeoutError())
    install_session(monkeypatch, transport, protocol)
    clock = [0]
    monkeypatch.setattr(io.time, "monotonic", lambda: clock[0])
    original = protocol.get_command_output_raw
    def expired(*args):
        clock[0] = 2
        return original(*args)
    monkeypatch.setattr(protocol, "get_command_output_raw", expired)
    with pytest.raises(io.ReadFailure, match="timeout"):
        io.read_command(transport, "fixed-read", timeout=1, guard=lambda: None)
    assert protocol.calls[-2:] == [("cleanup",), ("close",)]
    monkeypatch.setattr(io.time, "monotonic", lambda: 0)
    protocol.calls.clear()

    def guard():
        if protocol.calls and protocol.calls[-1][0] != "open":
            raise KillSwitchEngaged("test kill")

    # Revoke after open_shell returns, while preserving its ID for cleanup.
    opened = protocol.open_shell
    def open_then_kill(**kwargs):
        result = opened(**kwargs)
        protocol.calls.append(("created",))
        return result
    monkeypatch.setattr(protocol, "open_shell", open_then_kill)

    with pytest.raises(KillSwitchEngaged):
        io._winrm(transport, "must-not-run", 1, guard)
    assert [c[0] for c in protocol.calls] == ["open", "created", "close"]


def test_ssh_fixed_credentials_bounded_reads_and_guard(monkeypatch):
    import paramiko

    class Channel:
        closed = False
        reads = 0

        def settimeout(self, timeout):
            assert 0 < timeout <= 2

        def exec_command(self, command):
            assert command == "fixed-read"

        def recv_ready(self):
            return self.reads == 0

        def recv(self, limit):
            self.reads += 1
            assert limit == 4096
            return b"facts"

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            return 0

        def close(self):
            self.closed = True

    channel = Channel()
    connection = {}

    class Client:
        closed = False

        def load_system_host_keys(self):
            pytest.fail("dependency probe loaded implicit host trust")

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, host, **kwargs):
            connection.update(kwargs)

        def get_transport(self):
            return self

        def open_session(self, *, timeout):
            assert 0 < timeout <= 2
            return channel

        def close(self):
            self.closed = True

    client = Client()
    monkeypatch.setattr(paramiko, "SSHClient", lambda: client)
    transport = SSHTransport("fixture", password="private-password", allow_insecure_range=True,
                             interactive=True, allow_agent=True)
    guards = []
    assert io.read_command(transport, "fixed-read", timeout=2, guard=lambda: guards.append(True)) == "facts"
    assert connection["auth_timeout"] <= 2 and connection["banner_timeout"] <= 2
    assert connection["allow_agent"] is False and connection["look_for_keys"] is False
    assert client.closed and channel.closed and len(guards) >= 5
    with pytest.raises(io.ReadFailure, match="explicit_ssh_credential_required"):
        io.read_command(SSHTransport("fixture"), "fixed-read", timeout=2, guard=lambda: None)


@pytest.mark.parametrize("mode", ["pin_mismatch", "unknown_host", "changed_host"])
def test_dependency_ssh_cannot_bypass_host_trust(monkeypatch, tmp_path, mode):
    import paramiko
    from cyberthunder.transport.trust import TrustError, key_fingerprint

    # No socket is opened: fake negotiation invokes the real trust policy before auth.
    approved, offered = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    calls, events = [], []

    class Client(paramiko.SSHClient):
        def load_system_host_keys(self, *args):
            pytest.fail("dependency probe loaded implicit host trust")

        def connect(self, hostname, **kwargs):
            calls.append("connect")
            expected = self.get_host_keys().lookup(hostname)
            if expected:
                raise paramiko.BadHostKeyException(hostname, offered, approved)
            self._policy.missing_host_key(self, hostname, offered)
            calls.append("authenticated")

        def close(self):
            calls.append("closed")
            super().close()

    monkeypatch.setattr(paramiko, "SSHClient", Client)
    if mode == "pin_mismatch":
        trust = {"host_key_sha256": key_fingerprint(approved)}
    else:
        path = tmp_path / "known_hosts"
        host = "other.invalid" if mode == "unknown_host" else "fixture"
        path.write_text(f"{host} {approved.get_name()} {approved.get_base64()}\n")
        trust = {"known_hosts": str(path)}
    tr = SSHTransport("fixture", password="private-password", security_mode="fleet",
                      on_security_event=events.append, **trust)
    with pytest.raises(TrustError) as error:
        io.read_command(tr, "must-not-run", timeout=2, guard=lambda: None)
    assert error.value.code == ("transport:unknown_host_key" if mode == "unknown_host" else "discovery:identity_changed")
    assert "authenticated" not in calls and calls[-1] == "closed"
    assert len(events) == 1 and events[0].severity == "high"


@pytest.fixture
def dependency_ssh_probe(monkeypatch):
    calls = []
    clock = [0.0]
    monkeypatch.setattr(io.time, "monotonic", lambda: clock[0])

    class Channel:
        data = b"facts"
        done = True

        def settimeout(self, timeout):
            calls.append(("channel_timeout", timeout))

        def exec_command(self, command):
            calls.append(("exec", command))

        def recv_ready(self):
            return bool(self.data)

        def recv(self, limit):
            calls.append(("recv", limit))
            data, self.data = self.data, b""
            return data

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return self.done

        def recv_exit_status(self):
            return 0

        def close(self):
            calls.append(("channel_closed",))

    channel = Channel()

    class Client:
        def get_transport(self):
            return self

        def open_session(self, *, timeout):
            calls.append(("open", timeout))
            return channel

        def close(self):
            calls.append(("client_closed",))

    transport = SSHTransport("fixture", password="private-password", allow_insecure_range=True)

    def connector(**kwargs):
        calls.append(("connect", kwargs))
        return Client()

    monkeypatch.setattr(transport, "connect_client", connector)
    return SimpleNamespace(transport=transport, calls=calls, clock=clock, channel=channel)


def test_dependency_probe_uses_shared_connector_and_keeps_read_bounds(dependency_ssh_probe):
    probe = dependency_ssh_probe
    checked = []
    guard = lambda: checked.append("caller")
    assert io.read_command(probe.transport, "fixed-read", timeout=10, guard=guard) == "facts"
    assert probe.calls[0][0] == "connect"
    passed = probe.calls[0][1]
    assert passed["timeout"] == 3 and passed["allow_agent"] is False
    before = len(checked)
    passed["guard"]()
    assert len(checked) == before + 1
    assert ("recv", 4096) in probe.calls
    assert probe.calls[-2:] == [("channel_closed",), ("client_closed",)]


@pytest.mark.parametrize("stage", ["connected", "opened", "reading"])
@pytest.mark.parametrize("error_type", [KillSwitchEngaged, PermissionError])
def test_dependency_probe_cancellation_still_closes_resources(dependency_ssh_probe, stage, error_type):
    probe = dependency_ssh_probe
    trigger = {"connected": "connect", "opened": "open", "reading": "recv"}[stage]
    guards_after_recv = 0

    def guard():
        nonlocal guards_after_recv
        if any(call[0] == trigger for call in probe.calls):
            guards_after_recv += 1
            raise error_type("revoked")

    probe.channel.done = stage != "reading"
    with pytest.raises(error_type, match="revoked"):
        io.read_command(probe.transport, "fixed-read", timeout=2, guard=guard)
    assert probe.calls[-1] == ("client_closed",)
    if stage != "connected":
        assert probe.calls[-2] == ("channel_closed",)
    if stage != "reading":
        assert not any(call[0] == "exec" for call in probe.calls)
    assert guards_after_recv == 1


@pytest.mark.parametrize("stage", ["connected", "opened", "reading"])
def test_dependency_probe_deadline_closes_resources(dependency_ssh_probe, stage, monkeypatch):
    probe = dependency_ssh_probe
    trigger = {"connected": "connect", "opened": "open", "reading": "recv"}[stage]

    def guard():
        if any(call[0] == trigger for call in probe.calls):
            probe.clock[0] = 3

    probe.channel.done = stage != "reading"
    monkeypatch.setattr(io.time, "sleep", lambda duration: None)
    with pytest.raises(io.ReadFailure, match="timeout"):
        io.read_command(probe.transport, "fixed-read", timeout=2, guard=guard)
    assert probe.calls[-1] == ("client_closed",)
    if stage != "connected":
        assert probe.calls[-2] == ("channel_closed",)


def test_dependency_probe_output_limit_preserved(dependency_ssh_probe):
    probe = dependency_ssh_probe
    probe.channel.data = b"x" * (io.MAX_OUTPUT + 1)
    with pytest.raises(io.ReadFailure, match="output_limit"):
        io.read_command(probe.transport, "fixed-read", timeout=2, guard=lambda: None)
    assert probe.calls[-2:] == [("channel_closed",), ("client_closed",)]


@pytest.mark.parametrize("finished", [False, True])
def test_dependency_probe_rechecks_transport_authorization_during_reads(dependency_ssh_probe, monkeypatch, finished):
    probe = dependency_ssh_probe

    def authorization():
        if any(call[0] == "recv" for call in probe.calls):
            raise PermissionError("principal revoked")

    monkeypatch.setattr(probe.transport, "_guard", authorization)
    probe.channel.done = finished
    with pytest.raises(PermissionError, match="principal revoked"):
        io.read_command(probe.transport, "fixed-read", timeout=2, guard=lambda: None)
    assert probe.calls[-2:] == [("channel_closed",), ("client_closed",)]


@pytest.mark.parametrize("failure", ["timeout", "exception", "permission", "stderr", "call_limit", "time_limit"])
def test_failed_reads_are_redacted_and_limits_prevent_more_calls(ctx, tmp_path, monkeypatch, failure):
    proposal, _, root, _ = seed(ctx, tmp_path)
    calls, _ = wire(ctx, monkeypatch, root)
    if failure == "call_limit":
        monkeypatch.setattr(io, "MAX_CALLS", 0)
    elif failure == "time_limit":
        monkeypatch.setattr(io, "TOTAL_TIMEOUT", 0)
    elif failure == "stderr":
        monkeypatch.setattr(io, "_fixture", lambda *args: CommandResult("", 1, "", "password=private-value"))
    else:
        error = {"timeout": TimeoutError, "exception": RuntimeError, "permission": PermissionError}[failure]

        def fail(*args, **kwargs):
            raise error("password=private-value")

        monkeypatch.setattr(io, "_fixture", fail)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert "private-value" not in json.dumps(result)
    assert not result["dependencies"]
    if failure.endswith("limit"):
        assert calls == []
    assert any("failed" in s or "bound" in s for s in result["unknowns"])


def test_fixture_replay_cannot_write_log_follow_paths_or_run_regex(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    (tmp_path / "private.txt").write_text("private", encoding="utf-8")
    (root / "commands.json").write_text(json.dumps([
        {"match": "outside", "stdout": {"file": "../private.txt"}}, {"regex": ".*", "stdout": "private"}
    ]), encoding="utf-8")
    fixture = FixtureTransport(root)
    with pytest.raises(io.ReadFailure, match="fixture_invalid"):
        io.read_command(fixture, "outside", timeout=1, guard=lambda: None)
    with pytest.raises(io.ReadFailure, match="fixture_missing"):
        io.read_command(fixture, "regex", timeout=1, guard=lambda: None)
    assert not (root / "missing.log").exists()


def test_packet_bound_preserves_unknown_risk_floor(ctx, tmp_path, monkeypatch):
    names = ["app" + str(n) + "x" * 150 + ".service" for n in range(4)]
    proposal, _, root, _ = seed(ctx, tmp_path, services=names)
    entries = []
    for name in names:
        output = SYSTEMD.replace("sshd.service", name).replace("application.service", " ".join("dep" + str(n) + "x" * 150 + ".service" for n in range(32)))
        entries.append({"match": systemd_command(name), "stdout": output})
    (root / "commands.json").write_text(json.dumps(entries), encoding="utf-8")
    wire(ctx, monkeypatch, root)
    result = dep.collect_dependencies(ctx.engine, proposal.id, actor=ACTOR)
    assert len(json.dumps(result).encode("utf-8")) <= dep.MAX_PACKET_BYTES
    assert not result["dependencies"] and not result["complete"]
    assert any(r["id"].startswith("evidence-limit-") and r["severity"] == "high" for r in result["risks"])
    assert any("packet byte limit" in s for s in result["unknowns"])
