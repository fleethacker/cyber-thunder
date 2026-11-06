"""Selected SSH keys must cross the native private-file boundary before authentication."""
import io
import json
import os
import time
import traceback
from types import SimpleNamespace

import paramiko
import pytest

from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import TransportError
from cyberthunder.transport.ssh import SSHTransport
from cyberthunder.transport.trust import TrustError, key_fingerprint
from tests.ssh_key_support import (generated_ssh_keys, loopback_network_only,  # noqa: F401
                                   private_key_file, publickey_peer)


WINDOWS = pytest.mark.skipif(os.name != "nt", reason="requires native Windows SID/DACL and file sharing")
POSIX = pytest.mark.skipif(os.name != "posix", reason="requires native POSIX ownership, modes and descriptor traversal")


def selected(path, *, guard=None):
    target = Target("host", "Host", "linux", "ssh", address="127.0.0.1", username="reader", sudo=False,
                    options={"key_file": str(path), "credential_bound": True, "credential_source": "key_file",
                             "allow_agent": False, "look_for_keys": False, "interactive_auth": False,
                             "host_key_sha256": "SHA256:" + "A" * 43})
    return SSHTransport.from_target(target, SimpleNamespace(security_mode="fleet"), guard=guard)


def rejected(path, monkeypatch):
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *args, **kwargs: calls.append(kwargs))
    with pytest.raises(TransportError, match="SSH private key is unavailable or unsafe"):
        selected(path).connect_client()
    assert not calls


def test_selected_key_rejects_hardlink(private_key_file, tmp_path, monkeypatch):
    os.link(private_key_file, tmp_path / "alias")
    rejected(private_key_file, monkeypatch)


@pytest.mark.parametrize("kind", ["missing", "empty", "oversized", "malformed", "directory"])
def test_selected_key_rejects_unavailable_material(private_key_file, kind, monkeypatch):
    if kind == "missing":
        private_key_file.unlink()
    elif kind == "directory":
        private_key_file.unlink()
        private_key_file.mkdir()
    else:
        private_key_file.write_bytes({"empty": b"", "oversized": b"x" * (32 * 1024 + 1),
                                      "malformed": b"private-key-canary-invalid"}[kind])
    rejected(private_key_file, monkeypatch)


@POSIX
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o620, 0o602])
def test_posix_rejects_shared_private_key(private_key_file, monkeypatch, mode):
    private_key_file.chmod(mode)
    rejected(private_key_file, monkeypatch)


@WINDOWS
@pytest.mark.parametrize("rights", ["GR", "GW", "SD", "WD", "WO"])
def test_windows_rejects_foreign_private_key_rights(private_key_file, monkeypatch, rights):
    from tests.windows_acl import protected_aces, set_dacl
    set_dacl(private_key_file, protected_aces() + f"(A;;{rights};;;S-1-1-0)")
    try:
        rejected(private_key_file, monkeypatch)
    finally:
        set_dacl(private_key_file)


@pytest.mark.parametrize("unsafe", [False, True])
def test_real_key_authentication_obeys_private_permissions(private_key_file, publickey_peer,
                                                          generated_ssh_keys, unsafe):
    if unsafe:
        if os.name == "nt":
            from tests.windows_acl import protected_aces, set_dacl
            set_dacl(private_key_file, protected_aces() + "(A;;GW;;;S-1-1-0)")
        else:
            private_key_file.chmod(0o666)
    try:
        with publickey_peer() as peer:
            tr = selected(private_key_file)
            tr.port = peer.port
            tr.host_key_sha256 = key_fingerprint(generated_ssh_keys[1])
            with tr:
                if unsafe:
                    with pytest.raises(TrustError, match="SSH private key is unavailable or unsafe"):
                        tr.run("read")
                    assert not peer.auth and not peer.commands
                else:
                    assert tr.run("read").stdout == "isolated-key-ok\n"
                    assert peer.auth == [("reader", generated_ssh_keys[0].asbytes())]
                    assert tr._client.get_transport().auth_handler.private_key is None
    finally:
        if unsafe and os.name == "nt":
            set_dacl(private_key_file)


def test_wrong_host_pin_prevents_key_authentication(private_key_file, publickey_peer):
    with publickey_peer() as peer, selected(private_key_file) as tr:
        tr.port = peer.port
        with pytest.raises(TrustError, match="provisioned pin"):
            tr.run("never")
        assert not peer.auth and not peer.commands


@pytest.mark.parametrize("algorithm", ["rsa-pem", "rsa-openssh", "ecdsa-pem", "ecdsa-openssh", "ed25519"])
def test_supported_key_formats_use_checked_bytes(tmp_path, algorithm, monkeypatch):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cyberthunder.security.ssh_keys import load_private_key
    if algorithm.startswith("rsa"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm.startswith("ecdsa"):
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = ed25519.Ed25519PrivateKey.generate()
    form = ser.PrivateFormat.TraditionalOpenSSL if algorithm.endswith("pem") else ser.PrivateFormat.OpenSSH
    raw = key.private_bytes(ser.Encoding.PEM, form, ser.NoEncryption())
    path = tmp_path / "selected"
    path.write_bytes(raw)
    path.chmod(0o600)
    parsed = load_private_key(str(path))
    expected = key.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH)
    assert f"{parsed.get_name()} {parsed.get_base64()}".encode() == expected
    assert parsed.can_sign() and parsed.public_blob is None


def test_encrypted_key_has_no_passphrase_or_password_fallback(private_key_file, generated_ssh_keys, monkeypatch):
    generated_ssh_keys[0].write_private_key_file(str(private_key_file), password="disposable-passphrase")
    monkeypatch.setenv("CT_CRED_reader", "disposable-passphrase")
    rejected(private_key_file, monkeypatch)
    with pytest.raises(TransportError, match="cannot be combined"):
        SSHTransport("127.0.0.1", key_filename=str(private_key_file), password="disposable-passphrase")


def test_snapshot_never_reopens_key_or_adjacent_certificate(private_key_file, generated_ssh_keys, monkeypatch):
    from cyberthunder.security import ssh_keys
    read = ssh_keys._read_mounted
    calls = []

    def replace_after_checked_read(*args, **kwargs):
        raw = read(*args, **kwargs)
        generated_ssh_keys[1].write_private_key_file(str(private_key_file))
        return raw

    def forbidden(*args, **kwargs):
        pytest.fail("provider reopened a credential pathname or ambient source")

    monkeypatch.setattr(ssh_keys, "_read_mounted", replace_after_checked_read)
    monkeypatch.setattr(paramiko.SSHClient, "_key_from_filepath", forbidden)
    monkeypatch.setattr(paramiko, "Agent", forbidden)
    monkeypatch.setattr(paramiko.PKey, "load_certificate", forbidden)
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *args, **kwargs: calls.append(kwargs))
    with selected(private_key_file).connect_client(allow_agent=True):
        pass
    assert calls[0]["pkey"].asbytes() == generated_ssh_keys[0].asbytes()
    assert calls[0]["key_filename"] is None and calls[0]["password"] is None
    assert calls[0]["allow_agent"] is False and calls[0]["look_for_keys"] is False


def test_real_snapshot_replacement_uses_checked_key(private_key_file, generated_ssh_keys, publickey_peer, monkeypatch):
    from cyberthunder.security import ssh_keys
    read = ssh_keys._read_mounted

    def replace_after_read(*args, **kwargs):
        raw = read(*args, **kwargs)
        generated_ssh_keys[1].write_private_key_file(str(private_key_file))
        return raw

    monkeypatch.setattr(ssh_keys, "_read_mounted", replace_after_read)
    with publickey_peer() as peer, selected(private_key_file) as tr:
        tr.port = peer.port
        tr.host_key_sha256 = key_fingerprint(generated_ssh_keys[1])
        assert tr.run("snapshot-read").ok
        assert peer.auth == [("reader", generated_ssh_keys[0].asbytes())]


def test_reconnect_checks_file_again(private_key_file, monkeypatch):
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **kw: calls.append(kw["pkey"].asbytes()))
    tr = selected(private_key_file)
    with tr.connect_client():
        pass
    private_key_file.write_bytes(b"invalid-replacement")
    with pytest.raises(TrustError, match="SSH private key is unavailable or unsafe"):
        tr.connect_client()
    assert len(calls) == 1


@pytest.mark.parametrize("mode", ["range", "fleet"])
def test_explicit_unbound_key_cannot_fall_back_to_agent(private_key_file, monkeypatch, mode):
    calls = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **kw: calls.append(kw))
    with SSHTransport("127.0.0.1", security_mode=mode, key_filename=str(private_key_file),
                      host_key_sha256="SHA256:" + "A" * 43, interactive=True, allow_agent=True) as tr:
        tr.connect_client().close()
    assert calls[0]["allow_agent"] is False and calls[0]["look_for_keys"] is False


def test_guard_revocation_during_loading_stops_connection(private_key_file, monkeypatch):
    from cyberthunder.security import ssh_keys
    read = ssh_keys._read_mounted
    revoked = []

    def guarded():
        if revoked:
            raise PermissionError("revoked")

    def revoke(*args, **kwargs):
        raw = read(*args, **kwargs)
        revoked.append(True)
        return raw

    monkeypatch.setattr(ssh_keys, "_read_mounted", revoke)
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *args, **kwargs: pytest.fail("revoked key connected"))
    with pytest.raises(PermissionError, match="revoked"):
        selected(private_key_file, guard=guarded).connect_client()


def test_provider_errors_are_sanitized(private_key_file, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise RuntimeError("private-key-canary-provider " + str(private_key_file))

    monkeypatch.setattr(paramiko.RSAKey, "from_private_key", broken)
    with pytest.raises(TrustError) as error:
        selected(private_key_file).connect_client()
    diagnostic = "".join(traceback.format_exception(error.value)) + caplog.text
    assert error.value.code == "transport:ssh_key_unavailable"
    assert "private-key-canary-provider" not in diagnostic and str(private_key_file) not in diagnostic
    assert error.value.__context__.__context__ is None


@POSIX
@pytest.mark.parametrize("kind", ["leaf", "parent", "fifo", "writable-parent"])
def test_posix_rejects_redirects_and_special_files(private_key_file, tmp_path, monkeypatch, kind):
    path = private_key_file
    if kind == "leaf":
        path = tmp_path / "redirect"
        path.symlink_to(private_key_file)
    elif kind == "parent":
        path = tmp_path / "redirect"
        path.symlink_to(tmp_path, target_is_directory=True)
        path = path / private_key_file.name
    elif kind == "fifo":
        private_key_file.unlink()
        os.mkfifo(private_key_file, 0o600)
    else:
        tmp_path.chmod(0o777)
    rejected(path, monkeypatch)


@POSIX
@pytest.mark.parametrize("attack", ["replace", "mutate", "chmod", "parent-swap"])
def test_posix_race_during_bounded_read_denied(private_key_file, tmp_path, monkeypatch, attack):
    from cyberthunder.security import secret_resolver as resolver
    read = os.read
    sizes = []
    replacement = tmp_path / "replacement"
    replacement.write_bytes(private_key_file.read_bytes())
    replacement.chmod(0o600)

    def race(fd, size):
        raw = read(fd, size)
        sizes.append(size)
        if attack == "replace":
            os.replace(replacement, private_key_file)
        elif attack == "mutate":
            private_key_file.write_bytes(b"x" * len(raw))
        elif attack == "chmod":
            private_key_file.chmod(0o644)
        else:
            tmp_path.rename(tmp_path.with_name(tmp_path.name + "-parked"))
            tmp_path.mkdir(mode=0o700)
        return raw

    monkeypatch.setattr(resolver.os, "read", race)
    open_file, close_file = os.open, os.close
    opened, closed = [], []

    def tracked_open(*args, **kwargs):
        fd = open_file(*args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return close_file(fd)

    monkeypatch.setattr(resolver.os, "open", tracked_open)
    monkeypatch.setattr(resolver.os, "close", tracked_close)
    rejected(private_key_file, monkeypatch)
    assert sizes == [32 * 1024 + 1]
    assert opened and sorted(opened) == sorted(closed)


@POSIX
def test_posix_foreign_owner_denied(private_key_file, monkeypatch):
    original = os.fstat
    inode = private_key_file.stat().st_ino

    def foreign_owner(fd):
        info = original(fd)
        if info.st_ino == inode:
            return SimpleNamespace(**{name: os.geteuid() + 12345 if name == "st_uid" else getattr(info, name)
                                      for name in dir(info) if name.startswith("st_")})
        return info

    monkeypatch.setattr(os, "fstat", foreign_owner)
    rejected(private_key_file, monkeypatch)


@WINDOWS
@pytest.mark.parametrize("attack", ["parent-write", "delete-child", "junction", "unavailable-api", "untrusted-owner"])
def test_windows_native_boundary_denies_unsafe_source(private_key_file, tmp_path, monkeypatch, attack):
    from cyberthunder.security import file_trust as ft
    from tests.windows_acl import protected_aces, set_dacl, user_sid
    path = private_key_file
    if attack in {"parent-write", "delete-child"}:
        mask = "0x2" if attack == "parent-write" else "0x40"
        set_dacl(tmp_path, protected_aces(directory=True) + f"(A;;{mask};;;S-1-1-0)")
    elif attack == "junction":
        import _winapi
        _winapi.CreateJunction(str(tmp_path), str(tmp_path / "redirect"))
        path = tmp_path / "redirect" / private_key_file.name
    elif attack == "untrusted-owner":
        original = ft._Native.trusted_sids
        monkeypatch.setattr(ft._Native, "trusted_sids", lambda self: original(self) - {user_sid()})
    else:
        def unavailable():
            raise OSError("native-private-error")
        monkeypatch.setattr(ft, "_api", unavailable)
    try:
        rejected(path, monkeypatch)
    finally:
        if attack in {"parent-write", "delete-child"}:
            set_dacl(tmp_path)
        elif attack == "junction":
            os.rmdir(tmp_path / "redirect")


@WINDOWS
@pytest.mark.parametrize("attack", ["replace", "mutate", "parent-swap", "dacl"])
def test_windows_pins_source_and_rechecks_dacl(private_key_file, tmp_path, monkeypatch, attack):
    from contextlib import contextmanager
    from cyberthunder.security import file_trust as ft
    from tests.windows_acl import protected_aces, set_dacl
    original = ft.open_protected
    replacement = tmp_path / "replacement"
    replacement.write_bytes(private_key_file.read_bytes())
    sizes = []

    @contextmanager
    def racing(path, **kwargs):
        with original(path, **kwargs) as stream:
            class Wrapped:
                def fileno(self):
                    return stream.fileno()

                def read(self, size):
                    sizes.append(size)
                    raw = stream.read(size)
                    if attack == "dacl":
                        set_dacl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")
                    else:
                        with pytest.raises(PermissionError):
                            if attack == "replace":
                                os.replace(replacement, path)
                            elif attack == "mutate":
                                path.write_bytes(b"replacement")
                            else:
                                tmp_path.rename(tmp_path.with_name(tmp_path.name + "-parked"))
                    return raw
            yield Wrapped()

    monkeypatch.setattr(ft, "open_protected", racing)
    try:
        if attack == "dacl":
            rejected(private_key_file, monkeypatch)
        else:
            from cyberthunder.security.ssh_keys import load_private_key
            assert load_private_key(str(private_key_file)).can_sign()
        assert sizes == [32 * 1024 + 1]
    finally:
        set_dacl(private_key_file)
    # The reader released all handles even after trust failure.
    os.replace(replacement, private_key_file)


def test_account_action_keys_and_sudo_stay_separate(state_dir, tmp_path, generated_ssh_keys, monkeypatch, caplog):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    from cyberthunder.control.principal import Principal, principal_scope, operation_scope
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="fleet",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    target = Target("host", "Host", "linux", "ssh", address="127.0.0.1", username="inventory-admin", sudo=True,
                    options={"host_key_sha256": key_fingerprint(generated_ssh_keys[1]), "key_file": "/ambient/key"})
    ctx.inventory.add(target)
    ctx.inventory.save()
    person = Principal("https://identity.example.test", "alice", "Alice", kind="human",
                       roles=("analyst", "approver"), expires_at=time.time() + 300)
    paths = [tmp_path / "scan_key", tmp_path / "apply_key"]
    for path, key in zip(paths, generated_ssh_keys):
        key.write_private_key_file(str(path))
        path.chmod(0o600)
    policy = {"version": 1, "entries": [{"issuer": person.issuer, "subject": person.subject, "node_actions": [],
        "grants": [{"target_ids": ["host"], "actions": ["read", action],
                    "credential": {"username": username, "credential_ref": None, "sudo": sudo,
                                   "options": {"key_file": str(path)}}}
                   for action, username, sudo, path in zip(("scan", "apply"), ("reader", "changer"),
                                                           (False, True), paths)]}]}
    policy_path = state_dir / "auth" / "access.json"
    policy_path.parent.mkdir(mode=0o700, exist_ok=True)
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o600)
    opened, commands = [], []

    def connect(client, *args, **kwargs):
        opened.append((kwargs["username"], kwargs["pkey"].asbytes(), kwargs["key_filename"], kwargs["allow_agent"]))

    def execute(client, command, **kwargs):
        commands.append(command)
        out = io.BytesIO(b"ok")
        out.channel = SimpleNamespace(recv_exit_status=lambda: 0)
        return None, out, io.BytesIO()

    monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
    monkeypatch.setattr(paramiko.SSHClient, "exec_command", execute)
    with principal_scope(person):
        with operation_scope("scan"), ctx.transport_for(target) as scan:
            assert scan.run("read").ok
            with pytest.raises(PermissionError):
                scan.run("elevate", sudo=True)
            bob = Principal(person.issuer, "bob", "Bob", kind="human", roles=person.roles, expires_at=person.expires_at)
            with principal_scope(bob), pytest.raises(PermissionError):
                scan.run("other-person")
        with operation_scope("scan"), ctx.transport_for(target) as scan:
            paths[0].unlink()
            with pytest.raises(TrustError, match="SSH private key is unavailable or unsafe"):
                scan.run("missing-scan-key")
            generated_ssh_keys[0].write_private_key_file(str(paths[0]))
            paths[0].chmod(0o600)
        with operation_scope("apply"), ctx.transport_for(target) as apply:
            assert apply.run("change", sudo=True).ok
        with operation_scope("scan"), ctx.transport_for(target) as scan:
            policy["entries"][0]["grants"] = policy["entries"][0]["grants"][1:]
            policy_path.write_text(json.dumps(policy))
            with pytest.raises(PermissionError):
                scan.run("revoked")
    assert opened == [("reader", generated_ssh_keys[0].asbytes(), None, False),
                      ("changer", generated_ssh_keys[1].asbytes(), None, False)]
    assert commands[0] == "read" and len(commands) == 2 and "sudo" in commands[1]
    assert ctx.inventory.get("host").username == "inventory-admin"
    emitted = caplog.text + "".join(path.read_bytes().decode("latin1") for path in state_dir.rglob("*") if path.is_file())
    for path in paths:
        assert path.read_text().splitlines()[1] not in emitted
    events = [json.loads(line) for line in ctx.audit.path.read_text().splitlines()]
    assert {row["details"]["username"] for row in events if row["action"] == "credential.use"} == {"reader", "changer"}
