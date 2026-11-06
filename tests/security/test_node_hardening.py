"""Metadata-only assessment against disposable native permissions and both stores."""
import builtins
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys

import pytest

from cyberthunder.security import node_hardening as nh
from cyberthunder.store import StateStore


def private_tree(root):
    if os.name == "posix":
        root.chmod(0o700)
        for path in root.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.stat().st_mode, p.stat().st_mtime_ns,
            p.stat().st_ctime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob("*") if p.is_file()}


def codes(report):
    return {row["code"] for row in report["state_tree"]["observations"]}


def test_existing_backend_assessed_without_content_or_database_access(state_dir, monkeypatch):
    store = StateStore(state_dir)
    store.write_json(state_dir / "link.json", {"fixture": "PRIVATE-CONTENT-NOT-FOR-OUTPUT"})
    store.close()
    (state_dir / "audit.jsonl").write_text("PRIVATE-AUDIT-DATA", encoding="utf-8")
    (state_dir / "keys").mkdir()
    (state_dir / "keys" / "PRIVATE-FILENAME.pem").write_bytes(b"private-key-fixture")
    private_tree(state_dir)
    before = snapshot(state_dir)
    def forbidden(*args, **kwargs):
        raise AssertionError("assessment attempted content/database/context access")
    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", forbidden)
        guard.setattr(Path, "read_bytes", forbidden)
        guard.setattr(Path, "read_text", forbidden)
        guard.setattr(sqlite3, "connect", forbidden)
        guard.setattr(StateStore, "__init__", forbidden)
        result = nh.assess(state_dir)
    assert result["state_tree"]["status"] == "protected"
    assert result["state_tree"]["complete"]
    assert snapshot(state_dir) == before
    assert "PRIVATE" not in json.dumps(result) and str(state_dir) not in json.dumps(result)
    assert result["runtime_file_guards"]["whole_state_enforced"] is False
    assert {"node_stig_review", "isso_review_and_authorization"} <= set(result["pending"])


def test_missing_root_does_not_create_any_state(tmp_path):
    root = tmp_path / "absent"
    result = nh.assess(root)
    assert result["state_tree"]["status"] == "unknown"
    assert not result["state_tree"]["complete"] and not root.exists()


@pytest.mark.parametrize("path", ["relative/state", "../state", "/", "/tmp/../secret", "x" * 4097])
def test_ambiguous_or_unbounded_root_is_not_normalized_into_a_pass(path):
    result = nh.assess(path)
    assert result["state_tree"]["status"] == "unknown"
    assert "absolute_bounded_state_path_required" in codes(result)


def test_bounded_tree_reports_incomplete(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    for i in range(5):
        (root / str(i)).write_bytes(b"fixture")
    private_tree(root)
    result = nh.assess(root, limits=nh.Limits(entries=3))
    assert result["state_tree"]["status"] == "unknown"
    assert result["state_tree"]["entries_observed"] == 3
    assert "entry_or_time_limit" in codes(result)


def test_depth_and_time_bounds_are_not_success(tmp_path, monkeypatch):
    root = tmp_path / "state"
    (root / "a" / "b").mkdir(parents=True)
    private_tree(root)
    assert "depth_limit" in codes(nh.assess(root, limits=nh.Limits(depth=1)))
    times = iter([0, 20])
    monkeypatch.setattr(nh.time, "monotonic", lambda: next(times))
    assert "time_limit" in codes(nh.assess(root))


def test_hardlinks_are_not_followed_as_private_state(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    path = root / "audit.jsonl"
    path.write_bytes(b"fixture")
    private_tree(root)
    os.link(path, root / "duplicate")
    assert nh.assess(root)["state_tree"]["status"] != "protected"


@pytest.mark.parametrize("name,category", [("state.db-wal", "sqlite_wal"), ("state.db-shm", "sqlite_shared_memory"),
                                         ("audit.jsonl", "audit"), ("keys/credential", "keys_and_auth")])
def test_sidecars_audit_and_keys_with_foreign_reads_prevent_whole_state_pass(tmp_path, name, category):
    root = tmp_path / "state"
    path = root / name
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fixture-only")
    private_tree(root)
    if os.name == "nt":
        from tests.windows_acl import protected_aces, set_dacl
        set_dacl(path, protected_aces() + "(A;;GR;;;S-1-1-0)")
    else:
        path.chmod(0o644)
    report = nh.assess(root)
    assert report["state_tree"]["status"] != "protected"
    assert any(row["category"] == category and row["status"] != "protected"
               for row in report["state_tree"]["observations"])


def test_live_sqlite_wal_metadata_assessed_without_connecting(state_dir, monkeypatch):
    store = StateStore(state_dir, backend="sqlite")
    try:
        store.write_json(state_dir / "link.json", {"fixture": True})
        private_tree(state_dir)
        assert (state_dir / "state.db-wal").exists()
        def forbidden(*args, **kwargs):
            raise AssertionError("must not open a database")
        monkeypatch.setattr(sqlite3, "connect", forbidden)
        result = nh.assess(state_dir)
        rows = result["state_tree"]["observations"]
        assert {"sqlite_database", "sqlite_wal", "sqlite_shared_memory"} <= {row["category"] for row in rows}
        assert result["state_tree"]["status"] in {"protected", "unknown"}
    finally:
        store.close()


@pytest.mark.parametrize("mode", ["dev", "oidc", "mesh"])
def test_cli_is_metadata_only_even_when_identity_configuration_is_unavailable(tmp_path, monkeypatch, capsys, mode):
    from cyberthunder import cli
    root = tmp_path / "state"
    root.mkdir()
    private_tree(root)
    def forbidden(*args, **kwargs):
        raise AssertionError("node assessment must not initialize application settings/context")
    monkeypatch.setenv("CT_AUTH_MODE", mode)
    monkeypatch.setenv("CT_SECURITY_MODE", "fleet")
    monkeypatch.setattr(cli.Settings, "from_env", forbidden)
    monkeypatch.setattr(cli, "_ctx", forbidden)
    assert cli.main(["--state-dir", str(root), "node-hardening", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["read_only"] and result["state_tree"]["status"] == "protected"
    assert not list(root.iterdir())


def test_cli_failure_exit_and_no_force_or_repairs(tmp_path, capsys):
    from cyberthunder.cli import main
    assert main(["--state-dir", str(tmp_path / "absent"), "node-hardening"]) == 2
    assert "unknown" in capsys.readouterr().out
    with pytest.raises(SystemExit) as error:
        main(["node-hardening", "--force"])
    assert error.value.code == 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux descriptor/permission checks")
@pytest.mark.parametrize("attack", ["symlink", "fifo", "foreign_mode", "parent_mode", "owner"])
def test_linux_unsafe_metadata_is_not_a_pass(tmp_path, monkeypatch, attack):
    root = tmp_path / "state"
    root.mkdir()
    path = root / "audit.jsonl"
    path.write_bytes(b"fixture")
    private_tree(root)
    if attack == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "never-read")
    elif attack == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif attack == "foreign_mode":
        root.chmod(0o755)
    elif attack == "parent_mode":
        tmp_path.chmod(0o777)
    else:
        # Actual stat owner compared with a different caller; no chown or privilege use.
        monkeypatch.setattr(nh.os, "geteuid", lambda: os.stat(root).st_uid + 1)
    assert nh.assess(root)["state_tree"]["status"] == "unsafe"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux xattr/descriptor checks")
def test_linux_acl_unknown_and_midwalk_change_are_not_silently_passed(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    private_tree(root)
    # A real default ACL on this disposable directory. No host ACLs are changed.
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, 0xffffffff)
                                         for tag, perm in [(1, 7), (4, 0), (32, 0)])
    os.setxattr(root, "system.posix_acl_default", acl)
    assert "extended_acl_requires_review" in codes(nh.assess(root))
    os.removexattr(root, "system.posix_acl_default")
    scan = os.scandir
    def changed(fd):
        (root / "new-file").write_bytes(b"fixture")
        (root / "new-file").chmod(0o600)
        return scan(fd)
    monkeypatch.setattr(nh.os, "scandir", changed)
    assert "changed_during_assessment" in codes(nh.assess(root))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux no-follow traversal")
def test_linux_parent_symlink_and_unavailable_permission_metadata(tmp_path, monkeypatch):
    actual = tmp_path / "actual"
    (actual / "state").mkdir(parents=True)
    private_tree(actual)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    assert "redirected_path" in codes(nh.assess(alias / "state"))
    def unavailable(*args, **kwargs):
        raise PermissionError("PRIVATE-PERMISSION-DIAGNOSTIC")
    monkeypatch.setattr(nh.os, "listxattr", unavailable)
    result = nh.assess(actual / "state")
    assert result["state_tree"]["status"] == "unknown"
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.skipif(os.name != "nt", reason="native Windows DACL/handle checks")
@pytest.mark.parametrize("ace", ["(A;;GR;;;S-1-1-0)", "(A;OICIIO;GR;;;S-1-1-0)", "(A;;GW;;;S-1-1-0)"])
def test_windows_directory_read_inheritance_and_mutation_are_not_a_pass(tmp_path, ace):
    from tests.windows_acl import protected_aces, set_dacl
    root = tmp_path / "state"
    root.mkdir()
    set_dacl(root, protected_aces(directory=True) + ace)
    assert nh.assess(root)["state_tree"]["status"] != "protected"


@pytest.mark.skipif(os.name != "nt", reason="native Windows selected-file versus state protection")
def test_windows_protected_file_does_not_certify_the_state_directory(tmp_path):
    from cyberthunder.security import file_trust as ft
    from tests.windows_acl import protected_aces, set_dacl
    root = tmp_path / "state"
    root.mkdir()
    path = root / "policy.json"
    path.write_bytes(b"fixture-only")
    set_dacl(root, protected_aces(directory=True) + "(A;;GR;;;S-1-1-0)")
    with ft.open_protected(path, private=True):
        pass
    result = nh.assess(root)
    assert result["state_tree"]["status"] == "unsafe"
    assert "foreign_directory_access" in codes(result)


@pytest.mark.skipif(os.name != "nt", reason="native Windows DACL/handle checks")
def test_windows_shared_validator_failure_and_junction_are_unknown_or_unsafe(tmp_path, monkeypatch):
    from cyberthunder.security import file_trust as ft
    import _winapi
    root = tmp_path / "state"
    root.mkdir()
    _winapi.CreateJunction(str(tmp_path), str(root / "redirect"))
    assert "redirected_path" in codes(nh.assess(root))
    (root / "redirect").rmdir()
    def unavailable(*args, **kwargs):
        raise ft.FileTrustError("do-not-print-native-diagnostics")
    monkeypatch.setattr(ft, "_api", unavailable)
    result = nh.assess(root)
    assert result["state_tree"]["status"] == "unknown"
    assert "do-not-print" not in json.dumps(result)
