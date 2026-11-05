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

    def open_shell(self, **kwargs):
        self.calls.append(("open", kwargs))
        return "test-shell"

    def run_command(self, shell, program, arguments):
        self.calls.append(("run", program, arguments))
        return "test-command"

    def get_command_output_raw(self, shell, command):
        self.calls.append(("read",))
        if self.error:
            raise self.error
        return self.result

    def cleanup_command(self, shell, command):
        self.calls.append(("cleanup",))

    def close_shell(self, shell):
        self.calls.append(("close",))


def test_winrm_frame_bounds_and_cleanup(monkeypatch):
    protocol = Protocol()
    transport = WinRMTransport("fixture", password="private-password")
    monkeypatch.setattr(transport, "_sess", lambda: SimpleNamespace(protocol=protocol))
    guard_calls = []
    command = "$s = Get-Service -Name 'WinRM'"
    result = io.read_command(transport, command, timeout=2, guard=lambda: guard_calls.append(True))
    assert result == '{"name":"WinRM"}'
    assert transport.operation_timeout_s == 2 and transport.read_timeout_s == 3
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
    monkeypatch.setattr(transport, "_sess", lambda: SimpleNamespace(protocol=protocol))
    clock = iter([0, 0, 2])
    monkeypatch.setattr(io.time, "monotonic", lambda: next(clock))
    with pytest.raises(io.ReadFailure, match="timeout"):
        io._winrm(transport, "fixed-read", 1, lambda: None)
    assert protocol.calls[-2:] == [("cleanup",), ("close",)]
    monkeypatch.setattr(io.time, "monotonic", lambda: 0)
    protocol.calls.clear()

    def guard():
        if protocol.calls:
            raise KillSwitchEngaged("test kill")

    with pytest.raises(KillSwitchEngaged):
        io._winrm(transport, "must-not-run", 1, guard)
    assert [c[0] for c in protocol.calls] == ["open", "close"]


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
            pass

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
    transport = SSHTransport("fixture", password="private-password")
    guards = []
    assert io.read_command(transport, "fixed-read", timeout=2, guard=lambda: guards.append(True)) == "facts"
    assert connection["auth_timeout"] <= 2 and connection["banner_timeout"] <= 2
    assert connection["allow_agent"] is False and connection["look_for_keys"] is False
    assert client.closed and channel.closed and len(guards) >= 5
    with pytest.raises(io.ReadFailure, match="explicit_ssh_credential_required"):
        io.read_command(SSHTransport("fixture"), "fixed-read", timeout=2, guard=lambda: None)


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
