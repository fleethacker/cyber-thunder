"""Independent metadata assessment regressions; mutations stay in disposable fixtures."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from cyberthunder.security import node_hardening as nh
from tests.security.test_node_hardening import codes, private_tree


def test_final_native_metadata_overrun_is_incomplete(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    private_tree(root)
    now = [0.0]
    monkeypatch.setattr(nh.time, "monotonic", lambda: now[0])
    name = "_windows_node" if os.name == "nt" else "_posix_root"
    original = getattr(nh, name)

    @contextmanager
    def slow_final_check(*args, **kwargs):
        with original(*args, **kwargs) as handle:
            yield handle
        now[0] = 11.0  # A native check returned after the cooperative budget.

    monkeypatch.setattr(nh, name, slow_final_check)
    result = nh.assess(root)
    assert result["state_tree"]["status"] == "unknown"
    assert result["state_tree"]["complete"] is False
    assert "time_limit" in codes(result)


@pytest.mark.parametrize("source", ["default", "argument", "environment"])
def test_cli_relative_state_uses_cwd_without_resolving_links(tmp_path, monkeypatch, capsys, source):
    from cyberthunder import cli
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CT_STATE_DIR", raising=False)
    root = tmp_path / "state"
    root.mkdir()
    private_tree(root)

    def forbidden(*args, **kwargs):
        raise AssertionError("relative assessment must not resolve a path or initialize settings")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(cli.Settings, "from_env", forbidden)
    args = ["node-hardening", "--json"]
    if source == "argument":
        args = ["--state-dir", "state", *args]
    elif source == "environment":
        monkeypatch.setenv("CT_STATE_DIR", "state")
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["state_tree"]["status"] == "protected"
    assert not list(root.iterdir())


@pytest.mark.parametrize("path", ["state/../state", "../state", ""])
def test_cli_does_not_erase_parent_components_or_empty_paths(tmp_path, monkeypatch, capsys, path):
    from cyberthunder.cli import main
    monkeypatch.chdir(tmp_path)
    (tmp_path / "state").mkdir()
    private_tree(tmp_path / "state")
    assert main(["--state-dir", path, "node-hardening", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert "absolute_bounded_state_path_required" in codes(result)


@pytest.mark.parametrize("mode,security", [("oidc", "range"), ("mesh", "range"), ("dev", "fleet")])
@pytest.mark.parametrize("command", [["status"], ["proposals", "approve", "fixture"],
                                     ["kill", "release"], ["audit", "tail"], ["discover", "sweep"]])
def test_assessment_exception_does_not_authorize_other_cli_commands(tmp_path, monkeypatch, capsys, mode, security, command):
    from cyberthunder import cli
    monkeypatch.setenv("CT_AUTH_MODE", mode)
    monkeypatch.setenv("CT_SECURITY_MODE", security)

    def forbidden(*args, **kwargs):
        raise AssertionError("blocked CLI initialized application state")

    monkeypatch.setattr(cli, "_ctx", forbidden)
    assert cli.main(["--state-dir", str(tmp_path), *command]) == 2
    assert "authenticated API" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux descriptor lifetime and no-follow races")
@pytest.mark.parametrize("fault", ["depth", "entries", "swap", "rename", "metadata"])
def test_linux_descriptor_traversal_closes_every_handle_on_failure(tmp_path, monkeypatch, fault):
    root = tmp_path / "state"
    (root / "a" / "b").mkdir(parents=True)
    (root / "audit.jsonl").write_bytes(b"PRIVATE-CONTENT")
    private_tree(root)
    opened, peak = set(), [0]
    real_open, real_close, real_scan, real_xattr = os.open, os.close, os.scandir, os.listxattr
    attacked = []

    def open_checked(path, flags, *args, **kwargs):
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        if Path(path).name == "audit.jsonl" and fault == "swap" and not attacked:
            attacked.append(True)
            (root / "audit.jsonl").unlink()
            (root / "audit.jsonl").symlink_to(tmp_path / "PRIVATE-NEVER-OPENED")
        fd = real_open(path, flags, *args, **kwargs)
        opened.add(fd)
        peak[0] = max(peak[0], len(opened))
        return fd

    def close_checked(fd):
        real_close(fd)
        opened.remove(fd)

    def scan_checked(fd):
        assert type(fd) is int and fd in opened
        if fault == "rename" and not attacked:
            attacked.append(True)
            root.rename(tmp_path / "renamed")
            root.mkdir(mode=0o700)
        return real_scan(fd)

    def xattr_checked(fd):
        if fault == "metadata" and os.fstat(fd).st_ino == (root / "audit.jsonl").stat().st_ino:
            attacked.append(True)
            raise PermissionError("PRIVATE-PATH-OR-DIAGNOSTIC")
        return real_xattr(fd)

    monkeypatch.setattr(nh.os, "open", open_checked)
    monkeypatch.setattr(nh.os, "close", close_checked)
    monkeypatch.setattr(nh.os, "scandir", scan_checked)
    monkeypatch.setattr(nh.os, "listxattr", xattr_checked)
    limits = nh.Limits(depth=1) if fault == "depth" else nh.Limits(entries=2) if fault == "entries" else nh.Limits()
    result = nh.assess(root, limits=limits)
    assert result["state_tree"]["status"] != "protected"
    assert result["state_tree"]["complete"] is False
    assert not opened and 0 < peak[0] <= len(root.parts) + 3
    assert "PRIVATE" not in json.dumps(result)
    if fault in {"swap", "rename", "metadata"}:
        assert attacked


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux descriptor filesystem boundary")
def test_linux_different_device_is_not_enumerated(tmp_path, monkeypatch):
    root = tmp_path / "state"
    nested = root / "other-volume"
    nested.mkdir(parents=True)
    (nested / "PRIVATE-NAME").write_bytes(b"PRIVATE-CONTENT")
    private_tree(root)
    inode = nested.stat().st_ino
    real_fstat, real_stat, real_scan = os.fstat, os.stat, os.scandir
    crossed = []

    def device_changed(info):
        if info.st_ino != inode:
            return info
        crossed.append(True)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**{**fields, "st_dev": info.st_dev + 1})

    def scan(fd):
        assert real_fstat(fd).st_ino != inode, "must not enumerate a different filesystem"
        return real_scan(fd)

    # Simulate only the device ID; all opens, FD checks and directory enumeration are native.
    monkeypatch.setattr(nh.os, "fstat", lambda fd: device_changed(real_fstat(fd)))
    monkeypatch.setattr(nh.os, "stat", lambda *args, **kwargs: device_changed(real_stat(*args, **kwargs)))
    monkeypatch.setattr(nh.os, "scandir", scan)
    result = nh.assess(root)
    assert crossed and result["state_tree"]["status"] == "unknown"
    assert "different_filesystem" in codes(result)
    assert result["state_tree"]["entries_observed"] == 2
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.skipif(os.name != "nt", reason="native Windows inherited DACL masks")
def test_windows_unknown_inherit_only_rights_are_not_protected(tmp_path):
    from tests.windows_acl import protected_aces, set_dacl
    root = tmp_path / "state"
    root.mkdir()
    set_dacl(root, protected_aces(directory=True) + "(A;OICIIO;0x200;;;S-1-1-0)")
    result = nh.assess(root)
    assert result["state_tree"]["status"] == "unknown"
    assert result["state_tree"]["complete"] is False


@pytest.mark.skipif(os.name != "nt", reason="native Windows SID, held handles and DACL revocation")
def test_windows_midwalk_acl_change_is_not_protected_and_closes_handles(tmp_path, monkeypatch):
    from cyberthunder.security import file_trust as ft
    from tests.windows_acl import protected_aces, set_dacl, user_sid
    root = tmp_path / "state"
    root.mkdir()
    (root / "PRIVATE-NAME").write_bytes(b"PRIVATE-CONTENT")
    native = ft._api()
    assert user_sid() in native.trusted_sids()
    opened = []
    original_open, original_scan = native.open, os.scandir
    attacked = []

    def open_checked(*args, **kwargs):
        handle = original_open(*args, **kwargs)
        opened.append(handle)
        return handle

    def scan(path):
        if Path(path) == root and not attacked:
            attacked.append(True)
            set_dacl(root, protected_aces(directory=True) + "(A;;GR;;;S-1-1-0)")
        return original_scan(path)

    monkeypatch.setattr(native, "open", open_checked)
    monkeypatch.setattr(nh.os, "scandir", scan)
    result = nh.assess(root)
    assert attacked and opened
    # File handles can be transferred to a Python stream, so check the kernel,
    # not just direct calls to CloseHandle. Every captured handle is now invalid.
    assert all(native.GetFileType(handle) == 0 for handle in opened)
    assert result["state_tree"]["status"] != "protected"
    assert result["state_tree"]["complete"] is False
    assert all(secret not in json.dumps(result) for secret in ["PRIVATE", user_sid(), str(tmp_path)])


@pytest.mark.parametrize("structured", [False, True])
def test_cli_metadata_error_does_not_export_secret_paths_or_contents(tmp_path, monkeypatch, capsys, structured):
    from cyberthunder.cli import main
    root = tmp_path / "PRIVATE-STATE-PATH"
    root.mkdir()
    (root / "PRIVATE-SECRET-NAME").write_bytes(b"PRIVATE-FILE-CONTENT")
    private_tree(root)

    def fail(*args, **kwargs):
        raise OSError(f"PRIVATE-DIAGNOSTIC: {root}")

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata assessment read file contents")

    monkeypatch.setattr(nh.os, "scandir", fail)
    monkeypatch.setattr(nh.os, "read", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    args = ["--state-dir", str(root), "node-hardening"] + (["--json"] if structured else [])
    assert main(args) == 2
    captured = capsys.readouterr()
    assert "unknown" in captured.out and "permissions_unproved" in captured.out
    assert "PRIVATE" not in captured.out + captured.err
    assert not captured.err


@pytest.mark.skipif(os.name != "nt", reason="native Windows drive-relative path syntax")
@pytest.mark.parametrize("path", ["C:state", "\\state"])
def test_windows_cli_does_not_expand_ambiguous_drive_paths(path, capsys):
    from cyberthunder.cli import main
    assert main(["--state-dir", path, "node-hardening", "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert "absolute_bounded_state_path_required" in codes(result)
