"""Protected configuration through real AppContext/factory, with disposable secrets only."""
from dataclasses import replace
import json
import os
import traceback

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.security import secret_resolver as sr
from cyberthunder.transport.base import make_transport, TransportError
from cyberthunder.transport.trust import key_fingerprint, TrustError
from tests.security.test_secret_resolver import account, no_canary
from tests.security.test_secret_transport_integration import winrm_case
from tests.transport.conftest import certificates, ssh_keys, ssh_peer


@pytest.fixture
def registry(account):
    a = account
    a.registry_path = a.ctx.store.root / "credential-sources.json"
    a.document = {"version": 1, "sources": {"SCOPED": {
        "provider": "mounted", "root": a.source.root, "key": a.source.key}}}
    a.registry_path.write_text(json.dumps(a.document), encoding="utf-8")
    a.registry_path.chmod(0o600)
    a.ctx.settings.credential_sources = str(a.registry_path)
    return a


def rows(a):
    if not a.ctx.audit.path.exists():
        return []
    return [json.loads(line) for line in a.ctx.audit.path.read_text().splitlines()
            if json.loads(line)["action"].startswith("credential.")]


def open_transport(a):
    with principal_scope(a.person), operation_scope("scan"):
        return a.ctx.transport_for(a.ctx.inventory.get(a.target.id))


def test_setting_and_startup_validate_explicit_registry_without_reading_providers(registry, monkeypatch):
    a = registry
    monkeypatch.setenv("CT_CREDENTIAL_SOURCES", str(a.registry_path))
    monkeypatch.setenv("CT_AUTH_MODE", "oidc")
    monkeypatch.setenv("CT_SECURITY_MODE", "fleet")
    settings = Settings.from_env(state_dir=a.ctx.store.root, llm_backend="template", explain_precompute=False)
    original = sr._read_mounted
    def only_registry(source, **kwargs):
        assert source.key == a.registry_path.name, "startup must not read password providers"
        return original(source, **kwargs)
    monkeypatch.setattr(sr, "_read_mounted", only_registry)
    assert AppContext(settings).settings.credential_sources == str(a.registry_path)
    monkeypatch.setenv("CT_CREDENTIAL_SOURCES", "")
    assert Settings.from_env().credential_sources == ""
    with pytest.raises(sr.SecretResolutionError):
        AppContext(Settings.from_env())
    unused = a.ctx.store.root / "not-created"
    with pytest.raises(sr.SecretResolutionError):
        AppContext(replace(settings, state_dir=unused, credential_sources=""))
    assert not unused.exists()


@pytest.mark.parametrize("invalid", ["missing", "relative", "empty", "directory", "hardlink", "symlink", "public_write"])
def test_explicit_unsafe_registry_fails_at_startup_and_use(registry, invalid):
    a = registry
    original = open_transport(a)
    try:
        if invalid == "missing":
            a.registry_path.unlink()
        elif invalid == "relative":
            a.ctx.settings.credential_sources = a.registry_path.name
        elif invalid == "empty":
            a.ctx.settings.credential_sources = ""
        elif invalid == "directory":
            a.registry_path.unlink()
            a.registry_path.mkdir()
        elif invalid == "hardlink":
            os.link(a.registry_path, a.registry_path.with_suffix(".other"))
        elif invalid == "symlink":
            other = a.registry_path.with_suffix(".other")
            a.registry_path.rename(other)
            a.registry_path.symlink_to(other)
        elif os.name == "nt":
            from tests.windows_acl import set_dacl, protected_aces
            set_dacl(a.registry_path, protected_aces() + "(A;;GW;;;S-1-1-0)")
        else:
            a.registry_path.chmod(0o622)
        with pytest.raises(sr.SecretResolutionError):
            AppContext(a.ctx.settings)
        with principal_scope(a.person), operation_scope("scan"), pytest.raises(PermissionError):
            original.run("must-not-reach-network")
    finally:
        if invalid == "public_write" and os.name == "nt":
            set_dacl(a.registry_path)
        original.close()


@pytest.mark.parametrize("invalid", ["version", "boolean_version", "top_extra", "unknown_provider", "env_provider",
    "provider_extra", "missing_key", "null_layout", "relative_root", "escaping_key", "invalid_alias",
    "duplicate_alias", "duplicate_provider", "too_many", "too_large", "constant", "utf8", "malformed"])
def test_registry_schema_is_strict_bounded_and_errors_are_sanitized(registry, invalid):
    a = registry
    d = a.document
    source = d["sources"]["SCOPED"]
    if invalid == "version": d["version"] = 2
    elif invalid == "boolean_version": d["version"] = True
    elif invalid == "top_extra": d[a.canary] = "unsupported"
    elif invalid == "unknown_provider": source["provider"] = a.canary
    elif invalid == "env_provider": source.update(provider="env", name="SCOPED")
    elif invalid == "provider_extra": source["password"] = a.canary
    elif invalid == "missing_key": del source["key"]
    elif invalid == "null_layout": source["layout"] = None
    elif invalid == "relative_root": source["root"] = "relative"
    elif invalid == "escaping_key": source["key"] = "../password"
    elif invalid == "invalid_alias": d["sources"] = {"vault:guess": source}
    elif invalid == "too_many": d["sources"] = {f"alias{i}": source for i in range(sr.MAX_REGISTRY_ENTRIES + 1)}
    raw = json.dumps(d).encode()
    if invalid == "duplicate_alias":
        row = json.dumps(source)
        raw = ('{"version":1,"sources":{"SCOPED":' + row + ',"SCOPED":' + row + '}}').encode()
    elif invalid == "duplicate_provider":
        raw = raw.replace(b'"provider": "mounted"', b'"provider":"wincred","provider":"mounted"')
    elif invalid == "too_large": raw = b" " * (sr.MAX_REGISTRY_BYTES + 1)
    elif invalid == "constant": raw = raw.replace(b'"version": 1', b'"version": NaN')
    elif invalid == "utf8": raw = b"\xff"
    elif invalid == "malformed": raw = a.canary.encode()
    a.registry_path.write_bytes(raw)
    with pytest.raises(sr.SecretResolutionError) as error:
        AppContext(a.ctx.settings)
    assert error.value.__context__ is None
    no_canary("".join(traceback.format_exception(error.value)), a.canary)


@pytest.mark.parametrize("change", ["mapping", "remove_alias", "unset", "auth_mode", "security_mode"])
def test_existing_transport_rechecks_registry_on_every_operation(registry, change, monkeypatch):
    a = registry
    tr = open_transport(a)
    monkeypatch.setattr(tr, "connect_client", lambda: pytest.fail("changed mapping reached connection"))
    if change == "mapping": a.document["sources"]["SCOPED"]["key"] = "different"
    elif change == "remove_alias": a.document["sources"] = {"OTHER": a.document["sources"]["SCOPED"]}
    elif change == "unset": a.ctx.settings.credential_sources = None
    elif change == "auth_mode": a.ctx.settings.auth_mode = "dev"
    else: a.ctx.settings.security_mode = "range"
    a.registry_path.write_text(json.dumps(a.document))
    with principal_scope(a.person):
        for operation, args in (("run", ("command",)), ("read_file", ("path",)), ("write_file", ("path", b"data"))):
            with pytest.raises(PermissionError):
                getattr(tr, operation)(*args)
    tr.close()


def test_reformatting_preserves_fingerprint_but_mapping_change_requires_fresh_use(registry):
    a = registry
    original = open_transport(a)
    with principal_scope(a.person):
        a.registry_path.write_text(json.dumps(a.document, indent=4))
        original._guard()
    a.document["sources"]["SCOPED"]["key"] = "rotated-reference"
    a.registry_path.write_text(json.dumps(a.document))
    with principal_scope(a.person), pytest.raises(PermissionError):
        original._guard()
    replacement = open_transport(a)
    assert replacement._credential_use.source.key == "rotated-reference"
    original.close()
    replacement.close()


def test_missing_alias_never_uses_environment_and_dev_cannot_activate_registry(registry, monkeypatch):
    a = registry
    monkeypatch.setenv("CT_CRED_SCOPED", a.canary)
    a.document["sources"] = {"OTHER": a.document["sources"]["SCOPED"]}
    a.registry_path.write_text(json.dumps(a.document))
    with pytest.raises(sr.SecretResolutionError):
        open_transport(a)
    a.ctx.settings.auth_mode = "dev"
    with pytest.raises(sr.SecretResolutionError):
        AppContext(a.ctx.settings)
    assert not rows(a)


@pytest.mark.parametrize("backend", ["mounted", "wincred"])
def test_context_factory_real_ssh_and_durable_backend_attribution(registry, ssh_keys, ssh_peer, backend, monkeypatch):
    a = registry
    monkeypatch.setenv("CT_CRED_SCOPED", "wrong-environment-canary")
    with ssh_peer(ssh_keys[0]) as peer:
        target = replace(a.target, port=peer.port, options={"host_key_sha256": key_fingerprint(ssh_keys[0])})
        a.ctx.inventory.add(target)
        a.ctx.inventory.save()
        if backend == "wincred":
            from cyberthunder.security import _wincred
            from tests.security.test_wincred_resolver import FakeNative
            binding = a.ctx.access.credential(a.person, "scan", target)
            name = sr.windows_target_name(binding, a.person, target)
            native = FakeNative(name, binding.username, a.canary)
            monkeypatch.setattr(_wincred, "_api", lambda: native)
            a.document["sources"]["SCOPED"] = {"provider": "wincred", "target_name": name}
            a.registry_path.write_text(json.dumps(a.document))
        with principal_scope(a.person), operation_scope("scan"), a.ctx.transport_for(target) as tr:
            assert tr.run("fixture-read").stdout == "loopback-ok\n"
            assert tr._password is None
        assert peer.auth == [(a.binding.username, a.canary)] and not peer.failures
    audit = rows(a)
    assert [r["action"] for r in audit] == ["credential.use", "credential.resolve"]
    assert audit[0]["details"]["credential_source"] == backend
    assert audit[1]["details"]["backend"] == backend
    assert all(r["principal"]["verified"] and r["principal"]["sub"] == a.person.subject for r in audit)
    no_canary(json.dumps(audit), a.canary)
    for reference in (str(a.registry_path), a.source.root, "SCOPED"):
        assert reference not in json.dumps(audit)


def test_context_winrm_forwarding_and_per_message_mapping_revocation(registry, winrm_case, monkeypatch):
    a, _, made, leases, Session = winrm_case
    original = Session.send
    def revoke(session, message):
        a.document["sources"]["SCOPED"]["key"] = "different"
        a.registry_path.write_text(json.dumps(a.document))
        return original(session, message)
    monkeypatch.setattr(Session, "send", revoke)
    with principal_scope(a.person), operation_scope("scan"), a.ctx.transport_for(a.ctx.inventory.get(a.target.id)) as tr:
        with pytest.raises(TransportError):
            tr.run("safe-command")
    assert len(made) == 1 and len(made[0].messages) == 1 and made[0].closed and leases[0]._closed
    assert rows(a)[0]["details"]["credential_source"] == "mounted"


def test_failed_provider_is_durable_and_event_sink_rejects_spoofed_metadata(registry):
    a = registry
    tr = open_transport(a)
    use = tr._credential_use
    a.path.unlink()
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError):
        with use.lease():
            pytest.fail("missing provider resolved")
    audit = rows(a)
    assert audit[-1]["action"] == "credential.failed" and audit[-1]["outcome"] == "blocked"
    assert audit[-1]["principal"]["sub"] == a.person.subject
    details = audit[-1]["details"]
    event = sr.CredentialEvent("credential.failed", **details)
    for updates in ({"backend": a.canary}, {"purpose": a.canary}, {"target": a.canary},
                    {"reason": a.canary}, {"lease_id": a.canary}, {"reference_fingerprint": a.canary}):
        with principal_scope(a.person), pytest.raises(PermissionError):
            use.on_event(replace(event, **updates))
    with principal_scope(replace(a.person, subject="other")), pytest.raises(PermissionError):
        use.on_event(event)
    assert rows(a) == audit
    no_canary(a.ctx.audit.path.read_text(), a.canary)
    tr.close()


def test_unconfigured_fleet_cannot_claim_credential_use_for_refused_environment(account, monkeypatch):
    monkeypatch.setenv("CT_CRED_SCOPED", account.canary)
    with pytest.raises(TrustError) as error:
        open_transport(account)
    assert error.value.code == "transport:credential_resolver_required"
    assert not rows(account)


def test_factory_rejects_credential_use_for_unrelated_transport(account):
    with pytest.raises(TransportError):
        make_transport(replace(account.target, transport="local"), account.ctx.settings, credential_use=account.use)


def test_context_audit_failure_closes_lease_before_authentication(registry, monkeypatch):
    import paramiko
    a = registry
    tr = open_transport(a)
    captured = []
    original = sr.CredentialUse.lease
    def lease(use):
        result = original(use)
        captured.append(result)
        return result
    monkeypatch.setattr(sr.CredentialUse, "lease", lease)
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *_a, **_k: pytest.fail("unaudited authentication"))
    def unavailable(*_args, **_kwargs):
        raise RuntimeError(a.canary)
    monkeypatch.setattr(a.ctx.audit, "append", unavailable)
    with principal_scope(a.person), pytest.raises(sr.SecretResolutionError) as error:
        tr.run("safe-command")
    assert captured[0]._closed and captured[0]._secret is None and tr._client is None
    assert error.value.__context__ is None
    no_canary("".join(traceback.format_exception(error.value)), a.canary)
    tr.close()
