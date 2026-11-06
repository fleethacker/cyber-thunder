"""Per-account binding, source isolation and secret-free audit provenance."""
import copy
import hashlib
import json
import time
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberthunder.control.access import AccessDenied, AccessPolicy
from cyberthunder.inventory.targets import Target
from cyberthunder.security.credentials import CredentialBinding, CredentialError, bind_target


def principal(subject="alice", groups=()):
    return SimpleNamespace(verified=True, issuer="https://id.example", subject=subject,
                           groups=groups, expires_at=time.time() + 3600, roles=("admin",), scopes=("*",))


def credential(**changes):
    result = {"username": "alice_scan", "credential_ref": "ALICE_SCAN", "sudo": False, "options": {}}
    result.update(changes)
    return result


def target(**changes):
    fields = {"id": "host-a", "name": "Host A", "asset_type": "linux", "transport": "ssh",
              "address": "192.0.2.10", "username": "shared-root", "credential_ref": "SHARED",
              "sudo": True, "options": {"key_file": "/shared/key", "password": "inventory-secret",
                                         "allow_agent": True, "look_for_keys": True,
                                         "critical_services": ["sshd"], "known_hosts": "/trust/hosts"}}
    fields.update(changes)
    t = Target(**fields)
    t.environment = "A"
    return t


def entry(binding=None, *, subject="alice", group=None, actions=None):
    grant = {"actions": actions or ["scan"], "target_ids": ["host-a"], "environments": ["A"]}
    if binding is not None:
        grant["credential"] = binding
    return {"issuer": "https://id.example", "group" if group else "subject": group or subject,
            "node_actions": [], "grants": [grant]}


def policy(tmp_path, entries):
    path = tmp_path / "access.json"
    path.write_text(json.dumps({"version": 1, "entries": entries}), encoding="utf-8")
    return AccessPolicy(path)


def test_accounts_differ_by_principal_and_inventory_is_never_mutated(tmp_path):
    p = policy(tmp_path, [entry(credential()), entry(credential(username="bob_ops", credential_ref="BOB",
                                                               sudo=True), subject="bob")])
    t = target()
    original = copy.deepcopy(t.to_dict())
    alice_binding = p.credential(principal(), "scan", t)
    alice = bind_target(t, alice_binding)
    bob = bind_target(t, p.credential(principal("bob"), "scan", t))
    assert (alice.username, alice.credential_ref, alice.sudo) == ("alice_scan", "ALICE_SCAN", False)
    assert (bob.username, bob.credential_ref, bob.sudo) == ("bob_ops", "BOB", True)
    assert alice is not t and bob is not t and alice.options is not t.options
    assert "key_file" not in alice.options and "password" not in alice.options
    assert alice.options["known_hosts"] == "/trust/hosts"
    assert alice.options["credential_bound"] is True
    assert alice.options["credential_source"] == "environment"
    for key in ("allow_agent", "look_for_keys", "interactive_auth"):
        assert alice.options[key] is False
    alice.options["critical_services"].append("other")
    assert bob.options["critical_services"] == ["sshd"]
    assert t.to_dict() == original
    assert alice.environment == "A"


def test_binding_and_options_are_immutable(tmp_path):
    b = policy(tmp_path, [entry(credential())]).credential(principal(), "scan", target())
    with pytest.raises(FrozenInstanceError):
        b.sudo = True
    with pytest.raises(TypeError):
        b.options["key_file"] = "/other"
    with pytest.raises(FrozenInstanceError):
        b.provenance.subject = "bob"
    original = {"key_file": "/selected/key"}
    direct = CredentialBinding("alice", None, False, original)
    original["key_file"] = "/shared/key"
    assert direct.options["key_file"] == "/selected/key"


def test_acl_alone_does_not_authorize_inventory_or_ambient_credentials(tmp_path):
    p = policy(tmp_path, [entry()])
    t = target()
    assert p.allows(principal(), "scan", t)
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", t)
    with pytest.raises(CredentialError):
        bind_target(t, CredentialBinding("alice", "ALICE_SCAN", False))


def test_binding_does_not_cross_action_target_subject_or_issuer(tmp_path):
    p = policy(tmp_path, [entry(credential())])
    t = target()
    for who, action, resource in [(principal(), "apply", t), (principal("bob"), "scan", t),
                                  (principal("alice"), "scan", target(id="host-b"))]:
        with pytest.raises(AccessDenied):
            p.credential(who, action, resource)
    foreign = principal()
    foreign.issuer = "https://other.example"
    with pytest.raises(AccessDenied):
        p.credential(foreign, "scan", t)


def test_acl_and_credential_cannot_be_joined_across_different_actions(tmp_path):
    rows = [entry(actions=["scan"]), entry(credential(), group="operators", actions=["apply"])]
    p = policy(tmp_path, rows)
    assert p.allows(principal(groups=("operators",)), "scan", target())
    with pytest.raises(AccessDenied):
        p.credential(principal(groups=("operators",)), "scan", target())


def test_group_binding_only_matches_trusted_group_not_same_named_subject(tmp_path):
    p = policy(tmp_path, [entry(credential(), group="operators")])
    assert p.credential(principal(groups=("operators",)), "scan", target()).username == "alice_scan"
    with pytest.raises(AccessDenied):
        p.credential(principal("operators"), "scan", target())


@pytest.mark.parametrize("change", [{"username": "other"}, {"credential_ref": "OTHER"}, {"sudo": True},
                                     {"credential_ref": None, "options": {"key_file": "/selected/key"}}])
def test_distinct_matching_bindings_deny_without_subject_over_group_precedence(tmp_path, change):
    p = policy(tmp_path, [entry(credential()), entry(credential(**change), group="operators")])
    who = principal(groups=("operators",))
    assert p.allows(who, "scan", target())
    with pytest.raises(AccessDenied):
        p.credential(who, "scan", target())


def test_identical_matching_bindings_are_unambiguous_and_both_selectors_audited(tmp_path):
    p = policy(tmp_path, [entry(credential()), entry(credential(), group="operators")])
    b = p.credential(principal(groups=("operators",)), "scan", target())
    assert len(b.evidence()["selectors"]) == 2


@pytest.mark.parametrize("field,value", [("id", "host-b"), ("environment", "B"),
    ("address", "192.0.2.11"), ("port", 2222), ("transport", "local"),
    ("asset_type", "containers"), ("simulated", True), ("in_scope", False)])
def test_binding_cannot_be_replayed_to_changed_resource(tmp_path, field, value):
    p = policy(tmp_path, [entry(credential())])
    t = target()
    b = p.credential(principal(), "scan", t)
    setattr(t, field, value)
    with pytest.raises(CredentialError):
        bind_target(t, b)


def test_target_move_during_credential_selection_cannot_reuse_old_grant(tmp_path, monkeypatch):
    p = policy(tmp_path, [entry(credential())])
    t = target()
    matching = p._matching

    def move_after_matching(*args):
        result = matching(*args)
        t.environment = "C"
        return result

    monkeypatch.setattr(p, "_matching", move_after_matching)
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", t)


def test_policy_revocation_and_account_rebinding_rechecked_each_action(tmp_path):
    p = policy(tmp_path, [entry(credential())])
    old = p.credential(principal(), "scan", target())
    policy(tmp_path, [entry(credential(username="alice_new", credential_ref="ALICE_NEW"))])
    new = p.credential(principal(), "scan", target())
    assert new.username == "alice_new"
    assert new.provenance.policy_sha256 != old.provenance.policy_sha256
    policy(tmp_path, [entry()])
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target())
    p.path.write_text("{", encoding="utf-8")
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target())
    p.path.unlink()
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target())


@pytest.mark.parametrize("transport", ["local", "file", "fixture"])
@pytest.mark.parametrize("simulated", [False, True])
def test_runtime_host_access_is_denied_even_when_simulated_flag_is_set(tmp_path, transport, simulated):
    p = policy(tmp_path, [entry(credential())])
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target(transport=transport, simulated=simulated))


def test_simulated_transport_skips_os_account_but_never_acl(tmp_path):
    p = policy(tmp_path, [entry()])
    t = target(transport="simulated", simulated=True)
    b = p.credential(principal(), "scan", t)
    bound = bind_target(t, b)
    assert bound.username is None and bound.credential_ref is None and bound.sudo is False
    assert "key_file" not in bound.options and "password" not in bound.options
    with pytest.raises(AccessDenied):
        p.credential(principal("bob"), "scan", t)
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target(simulated=True))


@pytest.mark.parametrize("key_path", ["/accounts/alice/id_ed25519", "C:/accounts/alice/id_ed25519"])
@pytest.mark.parametrize("use_option", [True, False])
def test_ssh_key_paths_are_explicit_and_not_resolved(tmp_path, monkeypatch, key_path, use_option):
    c = credential(credential_ref=None if use_option else key_path,
                   options={"key_file": key_path} if use_option else {})
    p = policy(tmp_path, [entry(c)])

    def no_path_lookup(*args, **kwargs):
        raise AssertionError("helper must not open or resolve key material")

    t = target()
    with monkeypatch.context() as m:
        m.setattr(Path, "exists", no_path_lookup)
        b = p.credential(principal(), "scan", t)
        bound = bind_target(t, b)
    assert bound.credential_ref is None and bound.options["key_file"] == key_path
    assert bound.options["credential_source"] == "key_file"


def test_environment_source_is_explicit_even_if_reference_names_existing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ALICE_SCAN").write_text("not-a-private-key", encoding="utf-8")
    monkeypatch.setenv("CT_CRED_ALICE_SCAN", "never-read-this-secret")
    p = policy(tmp_path, [entry(credential())])
    t = target()
    b = p.credential(principal(), "scan", t)
    bound = bind_target(t, b)
    assert bound.credential_ref == "ALICE_SCAN" and "key_file" not in bound.options
    assert bound.options["credential_source"] == "environment"
    assert "never-read-this-secret" not in repr(b) + json.dumps(b.evidence())


def test_winrm_pins_explicit_account_and_removes_kerberos_fallback(tmp_path):
    p = policy(tmp_path, [entry(credential(username="DOMAIN\\alice", options={"transport": "ntlm"}))])
    t = target(asset_type="windows", transport="winrm", port=5986,
               options={"transport": "kerberos", "ccache": "/shared/ccache", "password": "old",
                        "ssl": True, "cert_validation": "validate", "ca_trust_path": "/trust/ca.pem"})
    bound = bind_target(t, p.credential(principal(), "scan", t))
    assert bound.options["transport"] == "ntlm"
    assert "ccache" not in bound.options and "password" not in bound.options
    assert bound.username == "DOMAIN\\alice" and bound.credential_ref == "ALICE_SCAN"
    assert bound.options["ssl"] is True and bound.options["cert_validation"] == "validate"


def test_kubeconfig_pins_context_and_drops_inventory_credentials_and_executable(tmp_path):
    c = credential(username=None, credential_ref=None,
                   options={"kubeconfig": "/accounts/alice/kubeconfig", "context": "alice-A"})
    p = policy(tmp_path, [entry(c)])
    t = target(asset_type="kubernetes", transport="kubeconfig", options={
        "kubeconfig": "/shared/kubeconfig", "context": "cluster-admin", "token": "old-token",
        "exec": {"command": "ambient-login"}, "kubectl": "/untrusted/kubectl",
        "env": {"KUBECONFIG": "/ambient/config"}, "allowed_registries": ["registry.example"]})
    bound = bind_target(t, p.credential(principal(), "scan", t))
    assert bound.options["kubeconfig"] == "/accounts/alice/kubeconfig"
    assert bound.options["context"] == "alice-A"
    assert bound.options["allowed_registries"] == ["registry.example"]
    assert not {"token", "exec", "env", "kubectl"} & bound.options.keys()
    assert bound.username is None and bound.credential_ref is None


@pytest.mark.parametrize("transport,c", [
    ("ssh", credential(credential_ref=None)),
    ("ssh", credential(username=None)),
    ("ssh", credential(options={"key_file": "/accounts/key"})),
    ("ssh", credential(options={"context": "wrong"})),
    ("winrm", credential(credential_ref=None)),
    ("winrm", credential(credential_ref="/accounts/key")),
    ("winrm", credential(sudo=True)),
    ("kubeconfig", credential(username=None, credential_ref=None, options={"kubeconfig": "/config"})),
    ("kubeconfig", credential(options={"kubeconfig": "/config", "context": "admin"})),
    ("simulated", credential()),
])
def test_missing_conflicting_or_wrong_transport_credentials_deny(tmp_path, transport, c):
    p = policy(tmp_path, [entry(c)])
    with pytest.raises(AccessDenied):
        p.credential(principal(), "scan", target(transport=transport))


@pytest.mark.parametrize("c", [
    {"username": "alice"}, credential(sudo=1), credential(username=""),
    credential(options={"password": "never-serialize-this"}),
    credential(options={"allow_agent": True}), credential(options={"transport": "kerberos"}),
    credential(options={"transport": "basic"}), credential(options={"key_file": "~/.ssh/id_rsa"}),
    credential(options={"key_file": "relative/key"}), credential(options={"key_file": "%HOME%/key"}),
    credential(options={"context": []}), credential(options=None),
    credential(credential_ref="-----BEGIN PRIVATE KEY-----\nprivate-material"),
    credential(credential_ref=".."), dict(credential(), password="never-serialize-this"),
])
def test_credential_schema_rejects_raw_secrets_and_unknown_auth_fields(tmp_path, c):
    p = policy(tmp_path, [entry(c)])
    with pytest.raises(AccessDenied) as error:
        p.credential(principal(), "scan", target())
    assert "never-serialize-this" not in str(error.value)
    assert "private-material" not in str(error.value)


@pytest.mark.parametrize("c", [
    credential(username=None), credential(credential_ref=None),
    credential(options={"key_file": "/second/source"}),
    credential(options={"kubeconfig": "/config", "context": "alice"}),
    credential(credential_ref=None, options={"context": "alice"}),
])
def test_structurally_conflicting_binding_invalidates_unrelated_grants(tmp_path, c):
    p = policy(tmp_path, [entry(credential()), entry(c, subject="bob")])
    assert not p.allows(principal(), "scan", target())


def test_audit_provenance_identifies_account_and_resource_without_paths_or_secrets(tmp_path):
    c = credential(credential_ref=None, options={"key_file": "/private/account/key"})
    p = policy(tmp_path, [entry(c)])
    b = p.credential(principal(), "scan", target())
    evidence = b.evidence()
    assert evidence["issuer"] == "https://id.example" and evidence["subject"] == "alice"
    assert evidence["username"] == "alice_scan" and evidence["sudo"] is False
    assert evidence["action"] == "scan"
    assert evidence["target"]["id"] == "host-a" and evidence["target"]["environment"] == "A"
    assert evidence["policy_sha256"] == hashlib.sha256(p.path.read_bytes()).hexdigest()
    assert evidence["selectors"] == [{"issuer": "https://id.example", "subject": "alice"}]
    assert evidence["credential_source"] == "key_file"
    assert len(evidence["credential_fingerprint"]) == 64
    assert "/private" not in json.dumps(evidence)
    evidence["target"]["id"] = "changed"
    assert b.evidence()["target"]["id"] == "host-a"
