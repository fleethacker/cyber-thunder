"""Authorization boundaries, malformed documents and policy replacement races."""
import copy
import json
import os
import time
from dataclasses import dataclass, field, replace
from types import SimpleNamespace

import pytest

from cyberthunder.control import access
from cyberthunder.control.access import AccessDenied, AccessPolicy


@dataclass(frozen=True)
class Principal:
    issuer: str = "https://id.example"
    subject: str = "alice"
    groups: tuple = ()
    roles: tuple = ()
    scopes: tuple = ()
    verified: bool = True
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    display_name: str = "Alice"


def target(tid="host-a", environment="A", **kwargs):
    return SimpleNamespace(id=tid, environment=environment, in_scope=True, **kwargs)


def entry(**changes):
    row = {"issuer": "https://id.example", "subject": "alice", "node_actions": [],
           "grants": [{"actions": ["read", "scan"], "environments": ["A"]}]}
    row.update(changes)
    return row


def write(path, entries=None):
    path.write_text(json.dumps({"version": 1, "entries": entries if entries is not None else [entry()]}),
                    encoding="utf-8")
    return AccessPolicy(path)


def test_per_environment_actions_and_explicit_visibility(tmp_path):
    row = entry(grants=[{"actions": ["read", "scan"], "environments": ["A"]},
                        {"actions": ["approve"], "target_ids": ["host-b"], "environments": ["B"]}])
    policy = write(tmp_path / "access.json", [row])
    principal = Principal(roles=("admin",), scopes=("*", "C", "PRINCIPAL_SCOPE"))
    a, b, c = target(), target("host-b", "B"), target("host-c", "C")
    assert policy.allows(principal, "scan", a)
    assert policy.allows(principal, "approve", b)
    assert not policy.allows(principal, "scan", b)
    assert not policy.allows(principal, "approve", a)
    for action in access.ACTIONS:
        assert not policy.allows(principal, action, c)
    assert not policy.allows(principal, "admin", a)
    assert policy.visible_targets(principal, [a, b, c]) == [a]


def test_node_and_resource_permissions_never_imply_each_other(tmp_path):
    policy = write(tmp_path / "access.json", [entry(node_actions=["admin", "audit"])])
    assert policy.require(Principal(), "admin") is None
    assert policy.allows(Principal(), "audit")
    assert not policy.allows(Principal(), "admin", target())
    assert not policy.allows(Principal(), "scan")
    assert not policy.allows(Principal(), "read")


def test_exact_issuer_subject_and_trusted_group_namespaces(tmp_path):
    group = entry(subject="operators", grants=[{"actions": ["apply"], "target_ids": ["host-a"]}])
    group["group"] = group.pop("subject")
    policy = write(tmp_path / "access.json", [group])
    assert policy.allows(Principal(subject="bob", groups=("operators",)), "apply", target())
    assert not policy.allows(Principal(subject="operators"), "apply", target())
    assert not policy.allows(Principal(groups=("Operators",)), "apply", target())
    assert not policy.allows(Principal(groups=("operators-admin",)), "apply", target())
    assert not policy.allows(Principal(issuer="https://other.example", groups=("operators",)), "apply", target())
    policy = write(tmp_path / "access.json")
    assert not policy.allows(Principal(subject="bob", display_name="alice", groups=("alice",)), "scan", target())
    assert not policy.allows(Principal(issuer="https://id.example/"), "scan", target())
    assert not policy.allows(Principal(subject="Alice"), "scan", target())


@pytest.mark.parametrize("changes", [
    {"verified": False}, {"verified": 1}, {"expires_at": None}, {"expires_at": True},
    {"expires_at": 0}, {"expires_at": float("nan")}, {"expires_at": float("inf")},
    {"expires_at": 10 ** 1000},
    {"groups": "alice"}, {"groups": ("a", "a")}, {"groups": ("*",)},
    {"subject": "alice "}, {"issuer": ""},
])
def test_invalid_or_unverified_principal_denied(tmp_path, changes):
    policy = write(tmp_path / "access.json")
    assert not policy.allows(replace(Principal(), **changes), "scan", target())


@pytest.mark.parametrize("action", ["*", "scan.*", "Scan", "scan ", "delete-everything", "", None, []])
def test_unknown_actions_fail_closed(tmp_path, action):
    policy = write(tmp_path / "access.json", [entry(node_actions=["admin"])])
    assert not policy.allows(Principal(roles=("admin",)), action, target())
    assert not policy.allows(Principal(), action)


def test_id_and_environment_selectors_are_intersected_and_rechecked(tmp_path):
    policy = write(tmp_path / "access.json", [entry(grants=[
        {"actions": ["scan"], "target_ids": ["host-a"], "environments": ["A"]}])])
    a = target()
    assert policy.allows(Principal(), "scan", a)
    a.environment = "B"
    assert not policy.allows(Principal(), "scan", a)
    assert not policy.allows(Principal(), "scan", target("host-a-backup"))
    assert not policy.allows(Principal(), "scan", target("host-b"))
    a.environment, a.in_scope = "A", False
    assert not policy.allows(Principal(), "scan", a)


def test_missing_environment_is_default_but_empty_environment_is_invalid(tmp_path):
    policy = write(tmp_path / "access.json", [entry(grants=[
        {"actions": ["scan"], "environments": ["default"]}])])
    plain = SimpleNamespace(id="host-a", in_scope=True)
    assert policy.allows(Principal(), "scan", plain)
    for environment in (None, "", "default ", "DEFAULT"):
        plain.environment = environment
        assert not policy.allows(Principal(), "scan", plain)


def test_wildcards_only_expand_the_explicit_resource_dimension(tmp_path):
    policy = write(tmp_path / "access.json", [entry(grants=[
        {"actions": ["scan"], "target_ids": ["*"], "environments": ["A"]}])])
    assert policy.allows(Principal(), "scan", target("anything", "A"))
    assert not policy.allows(Principal(), "scan", target("anything", "AB"))
    assert not policy.allows(Principal(), "read", target())
    assert not policy.allows(Principal(subject="bob"), "scan", target())
    assert not policy.allows(Principal(), "scan")
    assert not policy.allows(Principal(), "scan", target("*", "A"))


def test_revocation_and_corruption_never_reuse_last_good_policy(tmp_path):
    path = tmp_path / "access.json"
    policy = write(path)
    assert policy.allows(Principal(), "scan", target())
    # Same byte length and restored mtime must not defeat refresh.
    previous = path.stat()
    path.write_text(path.read_text().replace('"alice"', '"carol"'), encoding="utf-8")
    os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
    assert not policy.allows(Principal(), "scan", target())
    write(path)
    assert policy.allows(Principal(), "scan", target())
    path.write_text('{"version":1,"entries":[', encoding="utf-8")
    assert not policy.allows(Principal(), "scan", target())
    with pytest.raises(AccessDenied):
        policy.require(Principal(), "scan", target())
    write(path)
    assert policy.allows(Principal(), "scan", target())
    path.unlink()
    assert not policy.allows(Principal(), "scan", target())
    write(path, [])
    assert not policy.allows(Principal(), "scan", target())


def test_atomic_replacement_observed_and_mid_decision_replacement_denied(tmp_path, monkeypatch):
    path, replacement = tmp_path / "access.json", tmp_path / "next.json"
    policy = write(path)
    write(replacement, [])
    parse = access._parse

    def replace_during_parse(raw):
        result = parse(raw)
        os.replace(replacement, path)
        return result

    with monkeypatch.context() as m:
        m.setattr(access, "_parse", replace_during_parse)
        assert not policy.allows(Principal(), "scan", target())
    if os.name == "nt":
        # The native reader prevents replacement while its handle is held.
        assert replacement.exists() and policy.allows(Principal(), "scan", target())
        os.replace(replacement, path)
    assert not policy.allows(Principal(), "scan", target())
    write(replacement)
    os.replace(replacement, path)
    assert policy.allows(Principal(), "scan", target())


def test_in_place_edit_during_read_is_denied(tmp_path, monkeypatch):
    path = tmp_path / "access.json"
    policy = write(path)
    fstat = access.os.fstat
    calls = 0

    def mutate_after_open(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_text("{}", encoding="utf-8")
        return fstat(fd)

    monkeypatch.setattr(access.os, "fstat", mutate_after_open)
    assert not policy.allows(Principal(), "scan", target())


def test_unreadable_policy_is_a_sanitized_denial(tmp_path, monkeypatch):
    policy = write(tmp_path / "access.json")
    assert policy.allows(Principal(), "scan", target())

    def denied(*args, **kwargs):
        raise PermissionError("private filesystem detail")

    if os.name == "nt":
        from cyberthunder.security import file_trust
        monkeypatch.setattr(file_trust._Native, "open", denied)
    else:
        monkeypatch.setattr(access.os, "open", denied)
    with pytest.raises(AccessDenied) as error:
        policy.require(Principal(), "scan", target())
    assert "private" not in str(error.value)


@pytest.mark.parametrize("raw", [
    b'{"version":1,"version":1,"entries":[]}',
    b'{"version":1,"entries":[],"extra":"private-value"}',
    b'{"version":NaN,"entries":[]}', b'{"version":true,"entries":[]}',
    b'{"version":2,"entries":[]}', b'{"version":1}', b'[]', b'null', b'',
    b'\xff', b'\xef\xbb\xbf{"version":1,"entries":[]}',
    b'[' * 20 + b']' * 20,
])
def test_invalid_json_document_denies_without_echoing_contents(tmp_path, raw):
    path = tmp_path / "access.json"
    path.write_bytes(raw)
    with pytest.raises(AccessDenied) as error:
        AccessPolicy(path).require(Principal(), "scan", target())
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("change", [
    lambda r: r.pop("issuer"), lambda r: r.pop("subject"), lambda r: r.pop("node_actions"),
    lambda r: r.pop("grants"), lambda r: r.update(group="operators"),
    lambda r: r.update(extra=True), lambda r: r.update(subject="alice*"),
    lambda r: r.update(subject="\ud800"),
    lambda r: r.update(issuer="*"), lambda r: r.update(node_actions=["*"]),
    lambda r: r.update(node_actions=["read", "read"]), lambda r: r.update(grants={}),
    lambda r: r["grants"][0].pop("actions"), lambda r: r["grants"][0].pop("environments"),
    lambda r: r["grants"][0].update(actions=[]), lambda r: r["grants"][0].update(actions=["sacn"]),
    lambda r: r["grants"][0].update(environments=[]),
    lambda r: r["grants"][0].update(environments=["A", "A"]),
    lambda r: r["grants"][0].update(environments=["A*"]),
    lambda r: r["grants"][0].update(environments=["*", "A"]),
    lambda r: r["grants"][0].update(target_ids="host-a"),
    lambda r: r["grants"][0].update(unknown=True),
    lambda r: r["grants"][0].update(credential=None),
])
def test_missing_unknown_and_confusing_fields_invalidate_entire_policy(tmp_path, change):
    bad = entry(subject="unrelated")
    change(bad)
    policy = write(tmp_path / "access.json", [entry(), bad])
    assert not policy.allows(Principal(), "scan", target())


def test_duplicate_selectors_and_reordered_duplicate_grants_are_invalid(tmp_path):
    path = tmp_path / "access.json"
    policy = write(path, [entry(), entry()])
    assert not policy.allows(Principal(), "scan", target())
    row = entry()
    duplicate = copy.deepcopy(row["grants"][0])
    duplicate["actions"].reverse()
    row["grants"].append(duplicate)
    write(path, [row])
    assert not policy.allows(Principal(), "scan", target())


def test_bounded_bytes_entries_grants_and_selector_lists(tmp_path):
    path = tmp_path / "access.json"
    policy = AccessPolicy(path)
    path.write_bytes(b" " * (access.MAX_POLICY_BYTES + 1))
    assert not policy.allows(Principal(), "scan", target())
    write(path, [entry(subject=f"user-{n}") for n in range(access.MAX_ENTRIES + 1)])
    assert not policy.allows(Principal(), "scan", target())
    write(path, [entry(grants=[{"actions": ["scan"], "target_ids": [str(n)]} for n in range(65)])])
    assert not policy.allows(Principal(), "scan", target())
    write(path, [entry(grants=[{"actions": ["scan"], "target_ids": [str(n) for n in range(129)]}])])
    assert not policy.allows(Principal(), "scan", target())


def test_total_grant_limit_is_enforced_below_byte_limit(tmp_path):
    rows = [entry(subject=f"user-{n}", grants=[{"actions": ["scan"], "target_ids": [str(i)]}
                                             for i in range(64)]) for n in range(33)]
    rows[0]["subject"] = "alice"
    policy = write(tmp_path / "access.json", rows)
    assert policy.path.stat().st_size < access.MAX_POLICY_BYTES
    assert not policy.allows(Principal(), "scan", target("0"))


def test_directory_or_symlink_policy_denied(tmp_path):
    assert not AccessPolicy(tmp_path).allows(Principal(), "scan", target())
    actual = tmp_path / "real.json"
    write(actual)
    link = tmp_path / "access.json"
    try:
        link.symlink_to(actual)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    assert not AccessPolicy(link).allows(Principal(), "scan", target())


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO")
def test_fifo_is_rejected_without_opening_or_waiting(tmp_path):
    path = tmp_path / "access.json"
    os.mkfifo(path)
    assert not AccessPolicy(path).allows(Principal(), "scan", target())
