"""Local child tools receive an explicit environment without application credentials."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from cyberthunder.remediation import dependencies_io
from cyberthunder.transport.base import CommandResult, TransportError
from cyberthunder.transport.local import LocalTransport, command_environment


def test_real_child_cannot_inherit_server_credentials_or_startup_hooks(monkeypatch):
    hidden = ("CT_CRED_TEST", "CT_LLM_API_KEY", "SSH_AUTH_SOCK", "KRB5CCNAME",
              "HTTPS_PROXY", "BASH_ENV", "ENV", "PYTHONPATH", "LD_PRELOAD")
    for name in hidden:
        monkeypatch.setenv(name, "synthetic-private-value")
    transport = LocalTransport()
    code = "import json, os; print(json.dumps({k: os.environ[k] for k in " + repr(hidden) + " if k in os.environ}))"
    monkeypatch.setattr(transport, "_argv", lambda _: [sys.executable, "-c", code])
    result = transport.run("fixture-python-child")
    assert result.ok, result.stderr
    assert json.loads(result.stdout) == {}
    assert "PATH" in transport.env
    if os.name == "nt":
        assert "SystemRoot" in transport.env


def test_dependency_collector_uses_the_same_filtered_environment(monkeypatch):
    monkeypatch.setenv("CT_CRED_TEST", "synthetic-private-value")
    transport = LocalTransport()
    captured = []

    def process(argv, timeout, *, cwd, env, guard):
        captured.append(env)
        assert isinstance(env, dict) and "CT_CRED_TEST" not in env
        return CommandResult("", 0, "ActiveState=active")

    monkeypatch.setattr(dependencies_io, "_process", process)
    assert dependencies_io.read_command(transport, "systemctl show example.service", timeout=1, guard=lambda: None)
    assert len(captured) == 1


def test_explicit_empty_environment_stays_empty_and_caller_cannot_change_it():
    explicit = {}
    transport = LocalTransport(env=explicit)
    explicit["CT_CRED_TEST"] = "synthetic-private-value"
    assert transport.env == {}


@pytest.mark.parametrize("source", [
    {"CT_CRED_TEST": "secret"}, {"BASH_ENV": "startup.sh"}, {"LD_PRELOAD": "helper.so"},
    {"PATH": "one", "Path": "two"}, {"PATH": "bad\x00path"}, {"PATH": 1}, [],
])
def test_explicit_unsafe_or_ambiguous_environment_is_refused(source):
    with pytest.raises(TransportError):
        command_environment(source)


def test_local_shells_do_not_enable_startup_profiles_or_cmd_autorun():
    assert LocalTransport(shell="bash")._argv("true") == ["bash", "-c", "true"]
    assert LocalTransport(shell="cmd")._argv("exit 0") == ["cmd", "/d", "/c", "exit 0"]
    assert "-NoProfile" in LocalTransport(shell="powershell")._argv("exit 0")


def test_launch_receives_platform_variables_without_ambient_fallback(monkeypatch):
    transport = LocalTransport(env={"Path": "tools", "TEMP": "scratch", "LANG": "C"})
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    monkeypatch.setattr(subprocess, "run", run)
    assert transport.run("fixture-command").stdout == "ready"
    assert seen == [{"PATH": "tools", "TEMP": "scratch", "LANG": "C"}]
