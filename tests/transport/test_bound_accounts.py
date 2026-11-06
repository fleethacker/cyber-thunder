"""Selected account source and sudo boundaries; all remote clients are inert fakes."""
from __future__ import annotations

import io
import traceback
from types import SimpleNamespace

import paramiko
import pytest

from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import CommandResult, make_transport
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.trust import TrustError
from cyberthunder.transport.winrm import WinRMTransport


def selected(kind="ssh", *, source="environment", sudo=False):
    options = {"credential_bound": True, "credential_source": source, "allow_agent": False,
               "look_for_keys": False, "interactive_auth": False}
    if kind == "ssh":
        options["host_key_sha256"] = "SHA256:" + "A" * 43
    else:
        options["transport"] = "ntlm"
    return Target("selected", "selected", "linux" if kind == "ssh" else "windows", transport=kind,
                  address="localhost", username="selected-user", credential_ref="SELECTED_ACCOUNT",
                  sudo=sudo, options=options)


def test_bound_environment_reference_never_becomes_existing_key_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "SELECTED_ACCOUNT").write_text("private file must not be selected")
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    tr = make_transport(selected(), SimpleNamespace(security_mode="fleet"))
    assert tr._password == "selected-password" and tr._key is None
    assert tr._credential_bound and not tr.sudo_default


def test_missing_bound_environment_never_falls_back_to_file_or_agent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "SELECTED_ACCOUNT").write_text("private file must not be selected")
    monkeypatch.delenv("CT_CRED_SELECTED_ACCOUNT", raising=False)
    monkeypatch.setattr(paramiko, "SSHClient", lambda: pytest.fail("missing credential opened a client"))
    with pytest.raises(TrustError, match="environment credential is unavailable"):
        SSHTransport.from_target(selected(), interactive=True)


def test_bound_key_path_does_not_resolve_an_environment_password(tmp_path, monkeypatch):
    key = tmp_path / "SELECTED_ACCOUNT"
    key.write_text("explicit fixture key; no network")
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "must-not-use")
    item = selected(source="key_file")
    item.credential_ref = None
    item.options["key_file"] = str(key)
    tr = SSHTransport.from_target(item)
    assert tr._key == str(key) and tr._password is None


@pytest.mark.parametrize("kind", ["ssh", "winrm"])
@pytest.mark.parametrize("option", ["allow_agent", "look_for_keys", "interactive_auth"])
@pytest.mark.parametrize("value", [True, "false", None])
def test_bound_account_rejects_ambient_or_ambiguous_auth_flags(kind, option, value, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    item = selected(kind)
    item.options[option] = value
    with pytest.raises(TrustError, match="disabled ambient authentication"):
        make_transport(item)


@pytest.mark.parametrize("source", [None, "unknown", "none", "kubeconfig"])
def test_bound_ssh_cannot_guess_unknown_source(source, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    with pytest.raises(TrustError, match="explicit source"):
        SSHTransport.from_target(selected(source=source))


@pytest.mark.parametrize("source", ["environment", "key_file"])
def test_bound_ssh_rejects_conflicting_sources(source, tmp_path, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    item = selected(source=source)
    item.options["key_file"] = str(tmp_path / "key")
    with pytest.raises(TrustError):
        SSHTransport.from_target(item)


def test_bound_key_source_requires_absolute_path():
    item = selected(source="key_file")
    item.credential_ref = None
    item.options["key_file"] = "relative-key"
    with pytest.raises(TrustError, match="explicit absolute path"):
        SSHTransport.from_target(item)


def test_interactive_invocation_cannot_enable_bound_ssh_ambient_auth(monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda _self, *a, **kw: calls.append(kw))
    tr = SSHTransport.from_target(selected(), interactive=True)
    client = tr.connect_client(allow_agent=True)
    client.close()
    assert tr.interactive is False
    assert calls[0]["allow_agent"] is False and calls[0]["look_for_keys"] is False
    assert calls[0]["password"] == "selected-password" and calls[0]["key_filename"] is None


@pytest.mark.parametrize("operation", ["run", "write_file", "check_output"])
def test_bound_sudo_false_denies_before_connection_or_file_staging(operation, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    checks = []
    tr = SSHTransport.from_target(selected(), guard=lambda: checks.append(True))
    monkeypatch.setattr(tr, "_conn", lambda: pytest.fail("forbidden sudo touched remote client"))
    args = ("/protected", b"data") if operation == "write_file" else ("id",)
    with pytest.raises(TrustError) as error:
        getattr(tr, operation)(*args, sudo=True)
    assert error.value.code == "transport:sudo_forbidden" and checks


def test_bound_read_file_permission_error_cannot_invoke_sudo_fallback(monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    checks = []
    tr = SSHTransport.from_target(selected(), guard=lambda: checks.append(True))

    def denied():
        raise PermissionError("private path and server detail")

    tr._client = SimpleNamespace(open_sftp=denied)
    monkeypatch.setattr(tr, "run", lambda *a, **kw: pytest.fail("forbidden sudo fallback called run"))
    with pytest.raises(TrustError) as error:
        tr.read_file("/protected")
    assert error.value.code == "transport:sudo_forbidden"
    assert "private path" not in str(error.value)
    assert "private path and server detail" not in "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert len(checks) >= 3


@pytest.mark.parametrize("bound,sudo", [(True, True), (False, False)])
def test_authorized_and_legacy_read_fallback_remain_available(bound, sudo, monkeypatch):
    calls = []

    def denied():
        raise PermissionError("SFTP permission denied")

    tr = SSHTransport("localhost", password="p", sudo=sudo, credential_bound=bound)
    tr._client = SimpleNamespace(open_sftp=denied)
    monkeypatch.setattr(tr, "run", lambda command, **kw: calls.append((command, kw)) or CommandResult(command, 0, "read"))
    assert tr.read_file("/protected") == b"read"
    assert calls == [("cat /protected", {"sudo": True})]


@pytest.mark.parametrize("sudo", [False, True])
def test_bound_account_runs_permitted_commands_and_writes(sudo, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    tr = SSHTransport.from_target(selected(sudo=sudo))
    commands, stages = [], []

    class SFTP:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def open(self, path, mode):
            stages.append((path, mode))
            return io.BytesIO()

    def execute(command, **kwargs):
        commands.append(command)
        out = io.BytesIO(b"read")
        out.channel = SimpleNamespace(recv_exit_status=lambda: 0)
        return None, out, io.BytesIO()

    tr._client = SimpleNamespace(exec_command=execute, open_sftp=SFTP)
    assert tr.run("id", sudo=sudo).ok
    tr.write_file("/destination", b"contents", sudo=sudo)
    assert len(stages) == 1 and len(commands) == 2
    assert all(command.startswith("sudo -n ") for command in commands) is sudo


@pytest.mark.parametrize("auth", [None, "kerberos", "basic", "credssp"])
def test_bound_winrm_requires_explicit_ntlm_even_in_fleet(auth, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    item = selected("winrm")
    if auth is None:
        item.options.pop("transport")
    else:
        item.options["transport"] = auth
    with pytest.raises(TrustError, match="explicit NTLM"):
        make_transport(item, SimpleNamespace(security_mode="fleet"))


def test_bound_winrm_env_source_and_missing_secret_never_use_kerberos(tmp_path, monkeypatch, certificates):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "SELECTED_ACCOUNT").write_text("must-not-use")
    item = selected("winrm")
    item.options["ca_trust_path"] = certificates["ca"]
    settings = SimpleNamespace(security_mode="fleet")
    monkeypatch.delenv("CT_CRED_SELECTED_ACCOUNT", raising=False)
    with pytest.raises(TrustError, match="environment credential is unavailable"):
        make_transport(item, settings)
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    tr = make_transport(item, settings)
    assert isinstance(tr, WinRMTransport) and tr.auth == "ntlm" and tr._password == "selected-password"


@pytest.mark.parametrize("change", [{"credential_source": "key_file"}, {"key_file": "/other/key"}])
def test_bound_winrm_rejects_non_environment_sources(change, monkeypatch):
    monkeypatch.setenv("CT_CRED_SELECTED_ACCOUNT", "selected-password")
    item = selected("winrm")
    item.options.update(change)
    with pytest.raises(TrustError, match="explicit NTLM"):
        make_transport(item)
