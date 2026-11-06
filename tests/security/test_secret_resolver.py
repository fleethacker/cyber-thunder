"""Disposable account-scoped canaries; never read an existing credential store."""
from dataclasses import replace
import base64
import json
import os
import pickle
from pathlib import Path
import time
import traceback
from types import SimpleNamespace
from urllib.parse import quote
import uuid

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import Principal, current_principal, principal_scope
from cyberthunder.inventory.targets import Target
from cyberthunder.security.credentials import bind_target
from cyberthunder.security import secret_resolver as sr


@pytest.fixture
def account(state_dir, monkeypatch):
    # An unmocked provider call is a test failure before any vault API is loaded.
    from cyberthunder.security import _wincred
    monkeypatch.setattr(_wincred, "_api", lambda: pytest.fail("real credential store access is forbidden"))
    monkeypatch.delenv("CT_CREDENTIAL_SOURCES", raising=False)
    state_dir.chmod(0o700)
    folder = state_dir / "secrets"
    folder.mkdir(mode=0o700)
    path = folder / "password"
    canary = "fixture-" + uuid.uuid4().hex + "-value"
    path.write_text(canary, encoding="utf-8")
    path.chmod(0o600)
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="fleet",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    target = Target("owned", "Owned", "linux", transport="ssh", address="127.0.0.1", sudo=False,
                    options={"host_key_sha256": "SHA256:" + "A" * 43})
    ctx.inventory.add(target)
    ctx.inventory.save()
    person = Principal("https://identity.fixture.test", "reader", "Same display name", kind="human",
                       roles=("analyst",), expires_at=time.time() + 600)
    policy = {"version": 1, "entries": [{"issuer": person.issuer, "subject": person.subject,
        "node_actions": [], "grants": [{"target_ids": [target.id], "actions": ["scan"],
            "credential": {"username": "remote-reader", "credential_ref": "SCOPED", "sudo": False, "options": {}}}]}]}
    auth = state_dir / "auth"
    auth.mkdir(mode=0o700)
    policy_path = auth / "access.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    policy_path.chmod(0o600)
    binding = ctx.access.credential(person, "scan", target)
    generation = target.authorization_id
    events = []

    def guard():
        if current_principal() != person:
            raise PermissionError("another session")
        ctx.authorize("scan", target=target)
        if ctx.inventory.get(target.id).authorization_id != generation:
            raise PermissionError("target generation changed")
        ctx.killswitch.guard("target.access", person.actor)
        if ctx.access.credential(person, "scan", target).evidence() != binding.evidence():
            raise PermissionError("binding changed")

    def audit(event):
        events.append(event)
        ctx.audit.append(event.action, person.actor, event.to_dict(), subject=target.id)

    source = sr.MountedSecret(str(folder), "password")
    resolver = sr.SecretResolver({"SCOPED": source}, security_mode="fleet", auth_mode="oidc")
    with principal_scope(person):
        use = resolver.bind(binding, principal=person, target=target, purpose="scan", guard=guard, on_event=audit)
    return SimpleNamespace(ctx=ctx, target=target, person=person, binding=binding, guard=guard, audit=audit,
        resolver=resolver, source=source, use=use, events=events, path=path, canary=canary,
        policy=policy, policy_path=policy_path, selected=bind_target(target, binding))


def no_canary(value, canary):
    for form in (canary, base64.b64encode(canary.encode()).decode(), quote(canary), canary.encode().hex()):
        assert form not in value


def test_mounted_lease_is_redacted_nonserializable_and_bounded(account):
    a = account
    with principal_scope(a.person), a.use.lease() as lease:
        secret = lease.secret
        assert secret.reveal() == a.canary
        for value in (secret, lease):
            no_canary(str(value) + repr(value), a.canary)
            no_canary(json.dumps(value, default=str), a.canary)
            for serialize in (json.dumps, pickle.dumps):
                with pytest.raises(TypeError):
                    serialize(value)
    assert not secret._buffer
    with pytest.raises(sr.SecretResolutionError):
        secret.reveal()
    with pytest.raises(sr.SecretResolutionError):
        lease.__enter__()
    with pytest.raises(sr.SecretResolutionError):
        lease.secret
    assert [e.action for e in a.events] == ["credential.resolve"]
    assert a.events[0].backend == "mounted" and a.events[0].purpose == "scan"
    no_canary(json.dumps([e.to_dict() for e in a.events]) + a.ctx.audit.path.read_text(), a.canary)
    assert str(a.path) not in a.ctx.audit.path.read_text()
    assert "SCOPED" not in a.ctx.audit.path.read_text()


def test_direct_resolve_and_interrupted_acquisition_close_value(account):
    a = account
    captured = []
    def interrupted(event):
        captured.append(event)
        raise KeyboardInterrupt()
    with principal_scope(a.person):
        lease = a.resolver.resolve(a.binding, principal=a.person, target=a.target, purpose="scan",
                                   guard=a.guard, on_event=interrupted)
        with pytest.raises(KeyboardInterrupt), lease:
            pytest.fail("interrupted acquisition continued")
    assert captured and lease._closed and lease._secret is None


def test_next_lease_reads_rotated_file_and_never_reuses_secret(account):
    a = account
    with principal_scope(a.person):
        with a.use.lease() as first:
            assert first.secret.reveal() == a.canary
        rotated = "rotated-" + uuid.uuid4().hex
        a.path.write_text(rotated, encoding="utf-8")
        with a.use.lease() as second:
            assert second.secret.reveal() == rotated
    assert a.events[0].lease_id != a.events[1].lease_id
    assert a.events[0].reference_fingerprint == a.events[1].reference_fingerprint
    no_canary(a.ctx.audit.path.read_text(), rotated)


@pytest.mark.parametrize("change", ["revoked", "other_subject", "expired", "scope", "generation", "binding"])
def test_fresh_authorization_blocks_before_backend_read(account, monkeypatch, change):
    a = account
    person = a.person
    if change == "revoked":
        a.policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
    elif change == "other_subject":
        person = replace(person, subject="other-account")
    elif change == "expired":
        monkeypatch.setattr(sr, "time", SimpleNamespace(time=lambda: a.person.expires_at + 1, monotonic=time.monotonic))
    elif change in {"scope", "generation"}:
        target = a.ctx.inventory.get(a.target.id)
        if change == "scope":
            target.in_scope = False
        else:
            target.authorization_id = uuid.uuid4().hex
        a.ctx.inventory.save()
    else:
        a.policy["entries"][0]["grants"][0]["credential"]["credential_ref"] = "DIFFERENT"
        a.policy_path.write_text(json.dumps(a.policy), encoding="utf-8")
    monkeypatch.setattr(sr, "_read_mounted", lambda *_: pytest.fail("unauthorized secret lookup"))
    with principal_scope(person), pytest.raises(sr.SecretResolutionError):
        with a.use.lease():
            pytest.fail("unauthorized lease")


def test_revocation_during_resolution_and_audit_prevents_value_access(account, monkeypatch):
    a = account
    original = sr._read_mounted
    def revoke(source):
        result = original(source)
        a.policy_path.write_text('{"version":1,"entries":[]}', encoding="utf-8")
        return result
    monkeypatch.setattr(sr, "_read_mounted", revoke)
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        with a.use.lease():
            pytest.fail("revocation was ignored")
    assert [event.action for event in a.events] == ["credential.failed"]


@pytest.mark.parametrize("where", ["provider", "audit", "guard"])
def test_provider_and_callback_errors_do_not_escape_with_canary(account, monkeypatch, where):
    a = account
    def broken(*args):
        raise RuntimeError(a.canary)
    use = a.use
    if where == "provider":
        monkeypatch.setattr(sr, "_read_mounted", broken)
    elif where == "audit":
        use = replace(use, on_event=broken)
    else:
        use = replace(use, guard=broken)
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError) as error:
        with use.lease():
            pytest.fail("broken dependency accepted")
    assert error.value.__context__ is None and error.value.__cause__ is None
    no_canary(str(error.value) + repr(error.value) + "".join(traceback.format_exception(error.value)), a.canary)


def test_expiry_is_enforced_inside_a_live_lease(account, monkeypatch):
    a = account
    clock = [time.monotonic()]
    monkeypatch.setattr(sr, "time", SimpleNamespace(time=time.time, monotonic=lambda: clock[0]))
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        with a.use.lease() as lease:
            secret = lease.secret
            clock[0] += 31
            with pytest.raises(sr.SecretResolutionError):
                secret.reveal()
            # Catching expiry inside the context must not retain the old value
            # or allow a later callback/clock change to resurrect the lease.
            assert not secret._buffer and lease._closed
    assert not secret._buffer


@pytest.mark.parametrize("boundary", ["acquire", "reveal"])
@pytest.mark.parametrize("expiry", ["lease", "principal"])
def test_guard_cannot_release_a_value_after_expiry(account, monkeypatch, boundary, expiry):
    a = account
    wall, monotonic = [time.time()], [time.monotonic()]
    slow = [boundary == "acquire"]
    monkeypatch.setattr(sr, "time", SimpleNamespace(time=lambda: wall[0], monotonic=lambda: monotonic[0]))

    def guard():
        a.guard()
        if slow[0]:
            if expiry == "lease":
                monotonic[0] += 61
            else:
                wall[0] = a.person.expires_at + 1

    use = replace(a.use, guard=guard)
    reads = []
    original = sr._read_mounted

    def read(source):
        reads.append(True)
        return original(source)

    monkeypatch.setattr(sr, "_read_mounted", read)
    with principal_scope(a.person):
        lease = use.lease()
        try:
            if boundary == "acquire":
                with pytest.raises(sr.SecretResolutionError):
                    lease.__enter__()
                assert not reads, "expired acquisition reached the credential provider"
            else:
                lease.__enter__()
                secret = lease.secret
                slow[0] = True
                with pytest.raises(sr.SecretResolutionError):
                    secret.reveal()
                assert not secret._buffer
            assert lease._closed and lease._secret is None
        finally:
            lease.close()


@pytest.mark.parametrize("change", ["subject", "purpose", "target", "generation", "reference", "username"])
def test_binding_or_selected_target_cannot_be_substituted(account, change):
    a = account
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        if change == "subject":
            a.resolver.bind(a.binding, principal=replace(a.person, subject="other"), target=a.target,
                            purpose="scan", guard=a.guard, on_event=a.audit)
        elif change == "purpose":
            a.resolver.bind(a.binding, principal=a.person, target=a.target,
                            purpose="apply", guard=a.guard, on_event=a.audit)
        else:
            updates = {"target": {"address": "different.fixture.test"},
                       "generation": {"authorization_id": uuid.uuid4().hex},
                       "reference": {"credential_ref": "OTHER"}, "username": {"username": "other"}}[change]
            a.use.matches_target(replace(a.selected, **updates))


@pytest.mark.parametrize("profile", [("fleet", "oidc"), ("fleet", "mesh"), ("range", "oidc")])
def test_environment_backend_is_explicit_development_only(profile):
    with pytest.raises(ValueError, match="development"):
        sr.SecretResolver({"alias": sr.EnvironmentSecret("VALUE")}, security_mode=profile[0], auth_mode=profile[1])


def test_environment_never_uses_bare_variable_or_unknown_alias(account, monkeypatch):
    a = account
    resolver = sr.SecretResolver({"SCOPED": sr.EnvironmentSecret("NAMED")}, security_mode="range", auth_mode="dev")
    monkeypatch.setenv("NAMED", a.canary)
    monkeypatch.delenv("CT_CRED_NAMED", raising=False)
    with principal_scope(a.person):
        use = resolver.bind(a.binding, principal=a.person, target=a.target, purpose="scan", guard=a.guard, on_event=a.audit)
        with pytest.raises(sr.SecretResolutionError), use.lease():
            pytest.fail("bare environment value used")
        monkeypatch.setenv("CT_CRED_NAMED", a.canary)
        with use.lease() as lease:
            assert lease.secret.reveal() == a.canary
        with pytest.raises(sr.SecretResolutionError):
            resolver.bind(replace(a.binding, credential_ref="UNKNOWN"), principal=a.person, target=a.target,
                          purpose="scan", guard=a.guard, on_event=a.audit)


@pytest.mark.parametrize("name", ["../escape", "*", "env:VALUE", "keyring:guess", "", "a" * 65])
def test_registry_rejects_implicit_schemes_and_unbounded_aliases(name):
    with pytest.raises(ValueError):
        sr.SecretResolver({name: sr.EnvironmentSecret("VALUE")}, security_mode="range", auth_mode="dev")


@pytest.mark.parametrize("attack", ["hardlink", "symlink", "parent_symlink", "empty", "oversize"])
def test_unsafe_mounted_paths_fail_closed(account, attack):
    a = account
    if attack == "hardlink":
        os.link(a.path, a.path.with_name("another"))
    elif attack == "symlink":
        other = a.path.with_name("real")
        a.path.rename(other)
        a.path.symlink_to(other)
    elif attack == "parent_symlink":
        other = a.path.parent.with_name("real-directory")
        a.path.parent.rename(other)
        a.path.parent.symlink_to(other, target_is_directory=True)
    else:
        a.path.write_bytes(b"" if attack == "empty" else b"x" * (sr.MAX_SECRET_BYTES + 1))
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        with a.use.lease():
            pytest.fail("unsafe mount accepted")


@pytest.mark.skipif(os.name != "nt", reason="native Windows private-file DACL enforcement")
def test_windows_world_readable_secret_fails_closed(account):
    from tests.windows_acl import set_dacl, protected_aces
    a = account
    try:
        set_dacl(a.path, protected_aces() + "(A;;GR;;;S-1-1-0)")
        with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
            with a.use.lease():
                pytest.fail("publicly readable private value accepted")
    finally:
        set_dacl(a.path)
