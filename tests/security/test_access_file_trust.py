"""Adversarial local policy-file tests; no external targets or identity services."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.control import access
from cyberthunder.control.access import AccessDenied, AccessPolicy

POSIX = pytest.mark.skipif(os.name != "posix", reason="requires POSIX owner/mode and descriptor-relative filesystem semantics")
WINDOWS = pytest.mark.skipif(os.name != "nt", reason="requires Windows NTFS junction support")


def principal():
    return SimpleNamespace(verified=True, issuer="https://id.example", subject="alice", groups=(),
                           expires_at=time.time() + 60)


def policy_file(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "entries": [{"issuer": "https://id.example", "subject": "alice",
                    "node_actions": ["read"], "grants": [{"actions": sorted(access.ACTIONS - access.NODE_ONLY_ACTIONS),
                                                           "target_ids": ["host-a"], "environments": ["default"]}]}]}),
                    encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    return AccessPolicy(path)


def rejected(policy):
    with pytest.raises(AccessDenied, match="^access policy is unavailable or invalid$"):
        policy.require(principal(), "read")


def changed_stat(info, **updates):
    fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
    return SimpleNamespace(**(fields | updates))


def symlink(link, destination, *, directory=False):
    try:
        link.symlink_to(destination, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable on this filesystem (errno={exc.errno}, winerror={getattr(exc, 'winerror', None)})")


def test_trusted_file_content_digest_and_scope_predicate_preserved(tmp_path):
    policy = policy_file(tmp_path / "trusted" / "access.json")
    assert policy.require(principal(), "read") is None
    entries, digest = policy._load()
    assert entries and digest == hashlib.sha256(policy.path.read_bytes()).hexdigest()
    target = SimpleNamespace(id="host-a", environment="default", in_scope=False)
    # Risk acceptance records a decision under the fixture's exact account/target/
    # environment grant; it does not scan or change the out-of-scope target.
    # A maintenance override can authorize execution scheduling, so remains blocked.
    restricted = {"scan", "discover", "propose", "approve", "plan", "apply", "rollback", "verify",
                  "maintenance.override"}
    for action in access.ACTIONS - access.NODE_ONLY_ACTIONS:
        assert policy.allows(principal(), action, target) is (action not in restricted)
    for flag in (None, 0, 1, "false"):
        target.in_scope = flag
        assert not policy.allows(principal(), "read", target)


@pytest.mark.parametrize("node_action", ["read", "read.all"])
def test_global_history_requires_its_exact_node_action(tmp_path, node_action):
    policy = policy_file(tmp_path / "access.json")
    document = json.loads(policy.path.read_text())
    document["entries"][0].update(node_actions=[node_action], grants=[])
    policy.path.write_text(json.dumps(document))
    assert policy.allows(principal(), node_action)
    other = "read.all" if node_action == "read" else "read"
    assert not policy.allows(principal(), other)
    target = SimpleNamespace(id="host-a", environment="A", in_scope=True)
    for action in ("read", "read.all", "export"):
        assert not policy.allows(principal(), action, target)
    assert not policy.allows(principal(), "export")


@pytest.mark.parametrize("actions", [["read.all"], ["read", "read.all"]])
def test_read_all_in_resource_grant_invalidates_policy(tmp_path, actions):
    policy = policy_file(tmp_path / "access.json")
    document = json.loads(policy.path.read_text())
    document["entries"][0]["grants"].append({"actions": actions, "environments": ["*"]})
    policy.path.write_text(json.dumps(document))
    rejected(policy)


def test_read_all_does_not_expand_targeted_read_or_export(tmp_path):
    policy = policy_file(tmp_path / "access.json")
    document = json.loads(policy.path.read_text())
    document["entries"][0].update(node_actions=["read.all"], grants=[
        {"actions": ["read", "export"], "target_ids": ["host-a"], "environments": ["A"]}])
    policy.path.write_text(json.dumps(document))
    assert policy.allows(principal(), "read.all")
    a = SimpleNamespace(id="host-a", environment="A", in_scope=True)
    b = SimpleNamespace(id="host-b", environment="B", in_scope=True)
    moved = SimpleNamespace(id="host-a", environment="B", in_scope=True)
    for action in ("read", "export"):
        assert policy.allows(principal(), action, a)
        assert not policy.allows(principal(), action, b)
        assert not policy.allows(principal(), action, moved)
    assert not policy.allows(principal(), "read.all", a)
    assert policy.visible_targets(principal(), [a, b, moved]) == [a]


@pytest.mark.parametrize("kind", ["relative", "traversal"])
def test_noncanonical_policy_path_is_rejected_before_open(tmp_path, monkeypatch, kind):
    policy_file(tmp_path / "access.json")
    monkeypatch.chdir(tmp_path)
    path = Path("access.json") if kind == "relative" else tmp_path / "child" / ".." / "access.json"
    monkeypatch.setattr(access.os, "open", lambda *a, **kw: pytest.fail("unsafe path was opened"))
    rejected(AccessPolicy(path))


@pytest.mark.parametrize("kind", ["file", "parent", "grandparent"])
def test_symlink_at_any_component_is_rejected_before_open(tmp_path, monkeypatch, kind):
    original = tmp_path / "original"
    policy_file(original / "nested" / "access.json")
    alias = tmp_path / "alias"
    if kind == "file":
        symlink(alias, original / "nested" / "access.json")
        path = alias
    else:
        symlink(alias, original if kind == "grandparent" else original / "nested", directory=True)
        path = alias / "nested" / "access.json" if kind == "grandparent" else alias / "access.json"
    monkeypatch.setattr(access.os, "open", lambda *a, **kw: pytest.fail("redirected path was opened"))
    rejected(AccessPolicy(path))


@pytest.mark.parametrize("component", ["file", "parent", "grandparent"])
@pytest.mark.parametrize("attribute", ["st_file_attributes", "st_reparse_tag"])
def test_reparse_metadata_rejected_even_without_symlink_mode(tmp_path, monkeypatch, component, attribute):
    policy = policy_file(tmp_path / "guarded" / "nested" / "access.json")
    suspect = {"file": policy.path, "parent": policy.path.parent, "grandparent": policy.path.parent.parent}[component]
    lstat = Path.lstat

    def redirected(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        return changed_stat(info, **{attribute: 0x400 if attribute == "st_file_attributes" else 0xA0000003}) if path == suspect else info

    monkeypatch.setattr(Path, "lstat", redirected)
    monkeypatch.setattr(access.os, "open", lambda *a, **kw: pytest.fail("reparse path was opened"))
    rejected(policy)


@WINDOWS
def test_actual_windows_junction_parent_denied(tmp_path, monkeypatch):
    import _winapi

    original = tmp_path / "original"
    policy_file(original / "access.json")
    alias = tmp_path / "junction"
    try:
        _winapi.CreateJunction(str(original), str(alias))
    except OSError as exc:
        pytest.skip(f"Windows junction creation unavailable (winerror={exc.winerror})")
    monkeypatch.setattr(access.os, "open", lambda *a, **kw: pytest.fail("junction path was opened"))
    rejected(AccessPolicy(alias / "access.json"))


def test_hardlinked_policy_file_denied(tmp_path):
    policy = policy_file(tmp_path / "access.json")
    os.link(policy.path, tmp_path / "alias.json")
    assert policy.path.stat().st_nlink == 2
    rejected(policy)


def test_hardlink_created_during_decision_denied(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "access.json")
    parse = access._parse

    def link_during_parse(raw):
        result = parse(raw)
        os.link(policy.path, tmp_path / "alias.json")
        return result

    monkeypatch.setattr(access, "_parse", link_during_parse)
    rejected(policy)


def test_parent_replacement_with_same_policy_file_denied(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "guarded" / "access.json")
    parse = access._parse

    def replace_parent(raw):
        result = parse(raw)
        parked = tmp_path / "parked"
        policy.path.parent.rename(parked)
        policy.path.parent.mkdir(mode=0o700)
        (parked / "access.json").rename(policy.path)
        return result

    monkeypatch.setattr(access, "_parse", replace_parent)
    rejected(policy)


@pytest.mark.parametrize("field,value", [("st_mode", stat.S_IFREG | 0o444), ("st_nlink", 2), ("st_uid", 123456)])
def test_descriptor_security_metadata_mismatch_denied(tmp_path, monkeypatch, field, value):
    policy = policy_file(tmp_path / "access.json")
    fstat = os.fstat

    def mismatch(fd):
        info = fstat(fd)
        return changed_stat(info, **{field: value}) if stat.S_ISREG(info.st_mode) else info

    monkeypatch.setattr(access.os, "fstat", mismatch)
    rejected(policy)


@POSIX
@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666, 0o1666])
def test_posix_policy_write_permissions_denied(tmp_path, mode):
    policy = policy_file(tmp_path / "access.json")
    policy.path.chmod(mode)
    rejected(policy)


@POSIX
@pytest.mark.parametrize("mode", [0o770, 0o707])
def test_posix_writable_parent_denied(tmp_path, mode):
    policy = policy_file(tmp_path / "guarded" / "access.json")
    policy.path.parent.chmod(mode)
    rejected(policy)


@POSIX
@pytest.mark.parametrize("component", ["file", "parent"])
def test_posix_untrusted_owner_denied(tmp_path, monkeypatch, component):
    policy = policy_file(tmp_path / "guarded" / "access.json")
    suspect = policy.path if component == "file" else policy.path.parent
    lstat = Path.lstat

    def foreign_owner(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        return changed_stat(info, st_uid=os.geteuid() + 12345) if path == suspect else info

    monkeypatch.setattr(Path, "lstat", foreign_owner)
    rejected(policy)


@POSIX
def test_posix_permission_change_during_parse_denied(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "access.json")
    parse = access._parse

    def make_writable(raw):
        result = parse(raw)
        policy.path.chmod(0o666)
        return result

    monkeypatch.setattr(access, "_parse", make_writable)
    rejected(policy)


@POSIX
def test_posix_root_sticky_directory_exception_never_applies_to_file(tmp_path):
    info = (tmp_path / "..").stat()
    sticky = changed_stat(info, st_uid=0, st_mode=stat.S_IFDIR | 0o1777)
    access._check_node(sticky, directory=True)
    with pytest.raises(ValueError):
        access._check_node(changed_stat(sticky, st_mode=stat.S_IFREG | 0o1666, st_nlink=1, st_size=10))


@POSIX
def test_posix_parent_swap_to_symlink_before_open_denied_and_fds_closed(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "guarded" / "access.json")
    alternate = tmp_path / "alternate"
    policy_file(alternate / "access.json")
    open_file, close_file = os.open, os.close
    opened, closed, attacked = [], [], []

    def swapping_open(path, flags, *args, **kwargs):
        if str(path) == "guarded" and not attacked:
            attacked.append(True)
            policy.path.parent.rename(tmp_path / "parked")
            policy.path.parent.symlink_to(alternate, target_is_directory=True)
        fd = open_file(path, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        return close_file(fd)

    monkeypatch.setattr(access.os, "open", swapping_open)
    monkeypatch.setattr(access.os, "close", close)
    rejected(policy)
    assert attacked and opened and sorted(opened) == sorted(closed)


def test_errors_suppress_filesystem_details(tmp_path, monkeypatch):
    policy = policy_file(tmp_path / "access.json")

    def denied(*args, **kwargs):
        raise PermissionError("private pathname and account")

    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(AccessDenied) as error:
        policy.require(principal(), "read")
    assert error.value.__suppress_context__ and error.value.__cause__ is None
    assert str(error.value) == "access policy is unavailable or invalid"
