"""Adversarial kubeconfigs and real local file changes; no cluster connections."""
import base64
import copy
import json
import os
import stat
import time
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cyberthunder.control.access import AccessPolicy
from cyberthunder.inventory.targets import Target
from cyberthunder.security import kube_credentials as kc
from cyberthunder.security.credentials import BindingProvenance, CredentialBinding
from cyberthunder.security.kube_credentials import (
    KubeCredentialError, guard_kubeconfig, kube_subprocess_env, validate_kubeconfig, validate_kubectl_args,
)


TOKEN = "test-only-token.DoNotLog"


@pytest.fixture(scope="module")
def cert_material():
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-test-ca")])

    def cert(key, name, ca):
        return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    return {"ca": cert(ca_key, "isolated-test-ca", True),
            "client": cert(client_key, "alice", False),
            "key": client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()),
            "wrong_key": ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())}


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def document(material):
    return {"apiVersion": "v1", "kind": "Config", "current-context": "alice-A", "preferences": {},
            "contexts": [{"name": "alice-A", "context": {"cluster": "A", "user": "alice", "namespace": "work"}}],
            "clusters": [{"name": "A", "cluster": {"server": "https://127.0.0.1:6443",
                                                    "certificate-authority-data": b64(material["ca"])}}],
            "users": [{"name": "alice", "user": {"token": TOKEN}}]}


def write(path, value, private=True):
    path.write_bytes(value if isinstance(value, bytes) else yaml.safe_dump(value, sort_keys=False).encode())
    path.chmod(0o600 if private else 0o644)
    return path


def account(path, context="alice-A"):
    provenance = BindingProvenance("https://id.example", "alice", "scan",
                                  ("cluster-a", "A", "kubernetes", "kubeconfig", None, None, False, True),
                                  "1" * 64, (("https://id.example", "subject", "alice"),))
    return CredentialBinding(None, None, False, {"kubeconfig": str(path), "context": context}, provenance)


def validate(tmp_path, material, change=None):
    doc = document(material)
    if change:
        change(doc)
    path = write(tmp_path / "selected.yaml", doc)
    return validate_kubeconfig(account(path))


def assert_sanitized(operation):
    with pytest.raises(KubeCredentialError) as error:
        operation()
    assert TOKEN not in str(error.value) + repr(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None


def test_valid_static_token_has_only_safe_selection_and_evidence(tmp_path, cert_material):
    bound = validate(tmp_path, cert_material)
    assert (bound.context, bound.cluster, bound.user) == ("alice-A", "A", "alice")
    assert bound.server == "https://127.0.0.1:6443" and bound.auth_kind == "token"
    assert bound.kubectl_args() == ("--kubeconfig", bound.path, "--context", "alice-A",
                                    "--cluster", "A", "--user", "alice")
    evidence = bound.evidence()
    assert evidence["issuer"] == "https://id.example" and evidence["subject"] == "alice"
    assert evidence["files"][0]["role"] == "kubeconfig"
    assert TOKEN not in repr(bound) + json.dumps(evidence)
    assert bound.path not in repr(bound) + json.dumps(evidence)
    assert b64(cert_material["ca"]) not in repr(bound) + json.dumps(evidence)
    assert guard_kubeconfig(bound) is None
    with pytest.raises(FrozenInstanceError):
        bound.context = "admin"


def test_actual_access_policy_selection_integrates_without_identity_import(tmp_path, cert_material):
    config = write(tmp_path / "selected.yaml", document(cert_material))
    row = {"issuer": "https://id.example", "subject": "alice", "node_actions": [], "grants": [{
        "actions": ["scan"], "target_ids": ["cluster-a"], "credential": {
            "username": None, "credential_ref": None, "sudo": False,
            "options": {"kubeconfig": str(config), "context": "alice-A"}}}]}
    path = write(tmp_path / "access.json", json.dumps({"version": 1, "entries": [row]}).encode())
    principal = SimpleNamespace(verified=True, issuer="https://id.example", subject="alice", groups=(),
                                expires_at=time.time() + 3600)
    target = Target("cluster-a", "A", "kubernetes", transport="kubeconfig", sudo=False)
    selected = AccessPolicy(path).credential(principal, "scan", target)
    assert validate_kubeconfig(selected).provenance == selected.provenance


@pytest.mark.parametrize("field,value", [
    ("exec", {"command": "credential-program", "args": [TOKEN]}),
    ("auth-provider", {"name": "external", "config": {"access-token": TOKEN}}),
    ("tokenFile", "/var/run/secrets/token"), ("token-file", "/var/run/secrets/token"),
    ("as", "admin"), ("as-uid", "0"), ("as-groups", ["system:masters"]),
    ("as-user-extra", {"groups": ["system:masters"]}), ("username", "admin"),
    ("password", TOKEN), ("extensions", []), ("credential-provider", {}),
    ("authProvider", {}), ("unknown", TOKEN),
])
def test_auth_plugin_impersonation_and_unknown_credential_fields_rejected(tmp_path, cert_material, field, value):
    assert_sanitized(lambda: validate(tmp_path, cert_material, lambda d: d["users"][0]["user"].update({field: value})))


@pytest.mark.parametrize("field,value", [
    ("insecure-skip-tls-verify", True), ("insecure-skip-tls-verify", False),
    ("proxy-url", "https://proxy.example"), ("tls-server-name", "other.example"),
    ("extensions", []), ("certificate-authority", "relative/ca.pem"),
])
def test_cluster_trust_overrides_are_rejected(tmp_path, cert_material, field, value):
    assert_sanitized(lambda: validate(tmp_path, cert_material, lambda d: d["clusters"][0]["cluster"].update({field: value})))


@pytest.mark.parametrize("server", ["http://127.0.0.1:6443", "https://", "https://host:0", "https://host:65536",
    "https://user:secret@host", "https://host?token=" + TOKEN, "https://host#fragment", "https://host\\other",
    "https://host?", "https://host#",
    "https://host\nother", "https://user%40host", "file:///tmp/config"])
def test_invalid_server_never_reaches_subprocess(tmp_path, cert_material, server):
    assert_sanitized(lambda: validate(tmp_path, cert_material, lambda d: d["clusters"][0]["cluster"].update(server=server)))


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("apiVersion"), lambda d: d.update(apiVersion="v2"),
    lambda d: d.update(kind="List"), lambda d: d.update(extensions=[]),
    lambda d: d.update(preferences={"colors": True}), lambda d: d.update(**{"current-context": "admin"}),
    lambda d: d["contexts"].append(copy.deepcopy(d["contexts"][0])),
    lambda d: d["clusters"].append({"name": "other", "cluster": {"server": "https://other"}}),
    lambda d: d["users"].append({"name": "admin", "user": {"exec": {"command": "ambient-login"}}}),
    lambda d: d["contexts"][0]["context"].update(user="other"),
    lambda d: d["contexts"][0]["context"].update(cluster="other"),
    lambda d: d["contexts"][0]["context"].update(namespace="../other"),
    lambda d: d["contexts"][0]["context"].update(extensions=[]),
    lambda d: d["users"][0].update(extra="bad"),
    lambda d: d["users"][0].update(user={}),
    lambda d: d["users"][0]["user"].update(token=""),
    lambda d: d["users"][0]["user"].update(token=True),
    lambda d: d["users"][0]["user"].update(token="has whitespace"),
    lambda d: d["clusters"][0]["cluster"].pop("certificate-authority-data"),
    lambda d: d["clusters"][0]["cluster"].update(**{"certificate-authority-data": "not-base64"}),
])
def test_strict_single_selection_schema(tmp_path, cert_material, mutate):
    assert_sanitized(lambda: validate(tmp_path, cert_material, mutate))


@pytest.mark.parametrize("raw", [
    b"apiVersion: v1\napiVersion: v1\n", b"users: [{name: alice, name: admin}]",
    b"contexts: &shared [a]\nusers: *shared", b"a: &unused {user: admin}",
    b"a: !!python/object/apply:os.system ['never-execute']", b"apiVersion: !!str v1",
    b"a: [" * 20 + b"]" * 20, b"---\napiVersion: v1\n---\napiVersion: v1\n", b"\xff",
    b"a: 'unterminated-private-token", b"[", b"null", b"[]",
])
def test_real_malicious_yaml_is_rejected_without_parser_details(tmp_path, raw):
    path = write(tmp_path / "malicious.yaml", raw)
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


def test_duplicate_json_key_and_unused_yaml_anchor_in_otherwise_valid_config(tmp_path, cert_material):
    doc = document(cert_material)
    duplicated = json.dumps(doc).replace('"token":', '"token": "different-account", "token":')
    path = write(tmp_path / "selected.yaml", duplicated.encode())
    assert_sanitized(lambda: validate_kubeconfig(account(path)))
    anchored = yaml.safe_dump(doc, sort_keys=False).replace("contexts:\n", "contexts: &selected\n")
    write(path, anchored.encode())
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


def test_yaml_event_and_file_byte_limits(tmp_path):
    path = write(tmp_path / "large.yaml", b"a: [" + b"x," * 4100 + b"]")
    assert path.stat().st_size < kc.MAX_CONFIG_BYTES
    assert_sanitized(lambda: validate_kubeconfig(account(path)))
    write(path, b" " * (kc.MAX_CONFIG_BYTES + 1))
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


@pytest.mark.parametrize("embedded", [False, True])
def test_certificate_and_key_sources_are_explicit_and_matching(tmp_path, cert_material, embedded):
    doc = document(cert_material)
    if embedded:
        user = {"client-certificate-data": b64(cert_material["client"]), "client-key-data": b64(cert_material["key"])}
    else:
        user = {"client-certificate": str(write(tmp_path / "client.pem", cert_material["client"], False)),
                "client-key": str(write(tmp_path / "client.key", cert_material["key"]))}
    doc["users"][0]["user"] = user
    path = write(tmp_path / "selected.yaml", doc)
    bound = validate_kubeconfig(account(path))
    assert bound.auth_kind == "client_certificate"
    assert len(bound.files) == (1 if embedded else 3)
    assert cert_material["key"].decode() not in repr(bound) + json.dumps(bound.evidence())
    guard_kubeconfig(bound)


def test_external_ca_is_bound_and_changed_ca_revokes_guard(tmp_path, cert_material):
    doc = document(cert_material)
    ca = write(tmp_path / "ca.pem", cert_material["ca"], False)
    cluster = doc["clusters"][0]["cluster"]
    cluster.pop("certificate-authority-data")
    cluster["certificate-authority"] = str(ca)
    path = write(tmp_path / "selected.yaml", doc)
    bound = validate_kubeconfig(account(path))
    assert {f.role for f in bound.files} == {"kubeconfig", "ca"}
    write(ca, cert_material["client"], False)
    assert_sanitized(lambda: guard_kubeconfig(bound))


def test_guard_covers_all_four_external_material_files(tmp_path, cert_material):
    doc = document(cert_material)
    ca = write(tmp_path / "ca.pem", cert_material["ca"], False)
    cert = write(tmp_path / "client.pem", cert_material["client"], False)
    key = write(tmp_path / "client.key", cert_material["key"])
    doc["clusters"][0]["cluster"] = {"server": "https://127.0.0.1:6443", "certificate-authority": str(ca)}
    doc["users"][0]["user"] = {"client-certificate": str(cert), "client-key": str(key)}
    path = write(tmp_path / "selected.yaml", doc)
    bound = validate_kubeconfig(account(path))
    assert len(bound.files) == 4
    write(key, cert_material["wrong_key"])
    assert_sanitized(lambda: guard_kubeconfig(bound))


@pytest.mark.parametrize("invalid", ["mismatch", "token_and_key", "relative", "missing", "encrypted", "trailing", "public_key"])
def test_ambiguous_or_nonstatic_certificate_sources_deny(tmp_path, cert_material, invalid):
    doc = document(cert_material)
    user = {"client-certificate-data": b64(cert_material["client"]), "client-key-data": b64(cert_material["key"])}
    if invalid == "mismatch":
        user["client-key-data"] = b64(cert_material["wrong_key"])
    elif invalid == "token_and_key":
        user["token"] = TOKEN
    elif invalid == "relative":
        user.pop("client-key-data")
        user["client-key"] = "relative/key"
    elif invalid == "missing":
        user.pop("client-key-data")
    elif invalid == "encrypted":
        key = serialization.load_pem_private_key(cert_material["key"], password=None)
        user["client-key-data"] = b64(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.BestAvailableEncryption(b"test-password")))
    elif invalid == "trailing":
        user["client-key-data"] = b64(cert_material["key"] + b"exec: plugin")
    else:
        user["client-key-data"] = b64(cert_material["client"])
    doc["users"][0]["user"] = user
    path = write(tmp_path / "selected.yaml", doc)
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


@pytest.mark.parametrize("kind", ["leaf", "private", "trailing", "empty"])
def test_ca_must_contain_only_public_ca_certificates(tmp_path, cert_material, kind):
    content = {"leaf": cert_material["client"], "private": cert_material["key"],
               "trailing": cert_material["ca"] + cert_material["key"], "empty": b""}[kind]
    assert_sanitized(lambda: validate(tmp_path, cert_material,
        lambda d: d["clusters"][0]["cluster"].update(**{"certificate-authority-data": b64(content)})))


@pytest.mark.parametrize("change", ["same_mtime", "replacement", "missing", "malformed"])
def test_file_changes_cannot_reuse_a_previous_guard(tmp_path, cert_material, change):
    bound = validate(tmp_path, cert_material)
    path = Path(bound.path)
    old = path.stat()
    if change == "same_mtime":
        path.write_bytes(path.read_bytes().replace(TOKEN.encode(), TOKEN.lower().encode()))
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
    elif change == "replacement":
        replacement = write(tmp_path / "replacement.yaml", path.read_bytes())
        os.replace(replacement, path)
    elif change == "missing":
        path.unlink()
    else:
        write(path, b"invalid: [")
    assert_sanitized(lambda: guard_kubeconfig(bound))


def test_edit_during_validation_is_detected_before_binding_return(tmp_path, cert_material, monkeypatch):
    doc = document(cert_material)
    path = write(tmp_path / "selected.yaml", doc)
    parse = kc._document

    def mutate_after_parse(raw):
        result = parse(raw)
        doc["users"][0]["user"]["exec"] = {"command": "never-execute"}
        write(path, doc)
        return result

    monkeypatch.setattr(kc, "_document", mutate_after_parse)
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


def test_guard_does_not_claim_to_pin_the_path_for_later_external_open(tmp_path, cert_material):
    bound = validate(tmp_path, cert_material)
    guard_kubeconfig(bound)
    path = Path(bound.path)
    write(path, b"changed after guard")
    assert path.read_bytes() == b"changed after guard"
    assert_sanitized(lambda: guard_kubeconfig(bound))


def test_validator_writes_no_temp_files_and_never_uses_environment_defaults(tmp_path, cert_material, monkeypatch):
    path = write(tmp_path / "selected.yaml", document(cert_material))
    monkeypatch.setenv("KUBECONFIG", "/ambient/never-read")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "ambient.example")
    before = set(tmp_path.iterdir())
    validate_kubeconfig(account(path))
    assert set(tmp_path.iterdir()) == before
    with pytest.raises(KubeCredentialError):
        validate_kubeconfig(CredentialBinding(None, None, False, {"kubeconfig": str(path), "context": "alice-A"}))
    with pytest.raises(KubeCredentialError):
        validate_kubeconfig(account(path, context="other"))


@pytest.mark.parametrize("in_parent", [False, True])
def test_real_symlinks_in_file_or_parent_chain_are_denied(tmp_path, cert_material, in_parent):
    real = tmp_path / "real"
    real.mkdir()
    path = write(real / "selected.yaml", document(cert_material))
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real if in_parent else path, target_is_directory=in_parent)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert_sanitized(lambda: validate_kubeconfig(account(alias / "selected.yaml" if in_parent else alias)))


def test_hardlinked_credential_files_are_denied(tmp_path, cert_material):
    path = write(tmp_path / "selected.yaml", document(cert_material))
    try:
        os.link(path, tmp_path / "alias")
    except OSError:
        pytest.skip("hardlink creation unavailable")
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


@pytest.mark.skipif(os.name != "posix", reason="real POSIX file permissions")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666])
def test_real_posix_config_permission_failure(tmp_path, cert_material, mode):
    path = write(tmp_path / "selected.yaml", document(cert_material))
    path.chmod(mode)
    assert_sanitized(lambda: validate_kubeconfig(account(path)))


@pytest.mark.parametrize("owner,mode,private,allowed", [
    (1000, 0o600, True, True), (0, 0o600, True, True), (1001, 0o600, True, False),
    (1000, 0o640, True, False), (1000, 0o644, False, True), (1000, 0o664, False, False),
])
def test_posix_owner_and_mode_rules_on_all_hosts(monkeypatch, owner, mode, private, allowed):
    monkeypatch.setattr(kc, "os", SimpleNamespace(name="posix"))
    info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=owner, st_nlink=1)
    if allowed:
        kc._protection(info, private=private, owner=1000)
    else:
        with pytest.raises(ValueError):
            kc._protection(info, private=private, owner=1000)


def test_windows_reparse_flag_rejected_without_claiming_dacl_validation(monkeypatch):
    monkeypatch.setattr(kc, "os", SimpleNamespace(name="nt"))
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1, st_file_attributes=0x400)
    with pytest.raises(ValueError):
        kc._protection(info, private=True, owner=None)


@pytest.mark.parametrize("args", [
    ["get", "pods", "-A", "-o", "json"], ["version", "-o", "json"],
    ["get", "--raw", "/api/v1/nodes/test-node/proxy/configz"],
    ["get", "--raw=/readyz"], ["apply", "-f", "-"], ["replace", "--filename=-"],
    ["patch", "deployment", "app", "-n", "work", "--type=strategic", "-p", '{"spec":{"replicas":1}}'],
    ["delete", "networkpolicy", "default-deny", "-n", "work", "--ignore-not-found"],
    ["rollout", "status", "deployment/app", "-n", "work", "--timeout=180s"],
    ["api-resources", "--namespaced=true"], ["auth", "can-i", "get", "pods"],
])
def test_known_application_commands_are_accepted(args):
    assert validate_kubectl_args(args) == tuple(args)


@pytest.mark.parametrize("flag", [
    "--server", "-s", "--kubeconfig", "--context", "--cluster", "--user", "--token",
    "--username", "--password", "--as", "--as-uid", "--as-group", "--as-groups", "--as-user-extra",
    "--client-certificate", "--client-key", "--certificate-authority", "--insecure-skip-tls-verify",
    "--tls-server-name", "--proxy-url", "--kuberc", "--cache-dir", "--profile", "--profile-output",
    "--v", "-v", "--vmodule", "--log-file", "--unknown-future-credential-flag",
])
@pytest.mark.parametrize("equals", [True, False])
def test_appended_connection_identity_proxy_and_logging_flags_never_override_binding(flag, equals):
    tail = [flag + "=" + TOKEN] if equals else [flag, TOKEN]
    assert_sanitized(lambda: validate_kubectl_args(["get", "pods", *tail]))


@pytest.mark.parametrize("args", [
    ["get", "pods", "-shttps://evil"], ["get", "pods", "-As"], ["get", "pods", "--", "--token", TOKEN],
    ["get", "pods", "--output"], ["get", "pods", "--output=go-template-file=/private/file"],
    ["get", "pods", "--namespace", "--server=evil"],
    ["get", "--raw", "https://evil"], ["get", "--raw", "//evil"], ["get", "--raw", "/%2f%2fevil"],
    ["get", "--raw", "/../other"], ["apply", "-f", "https://remote/manifest"],
    ["apply", "-k", "/local/kustomize"], ["apply", "-f", "/local/config"], ["apply", "view-last-applied"],
    ["plugin", "list"], ["unknown-plugin"], ["create", "unknown-plugin"], ["config", "view", "--raw"],
    ["kuberc", "view"], ["proxy"], ["exec", "pod", "--", "env"], ["run", "pod"],
    ["rollout", "unknown-plugin"], ["auth", "unknown-plugin"], ["get\npods"], [],
])
def test_plugins_command_aliases_and_unreviewed_argument_forms_deny(args):
    assert_sanitized(lambda: validate_kubectl_args(args))


def test_arguments_are_bounded_and_not_a_command_string():
    for value in ("get pods", ["get"] * 129, ["get", "a" * 32769], ["get", None]):
        assert_sanitized(lambda: validate_kubectl_args(value))


def test_subprocess_environment_drops_ambient_auth_proxy_preferences_and_loader_hooks():
    source = {"PATH": "/trusted/bin", "SystemRoot": "C:/Windows", "TEMP": "C:/Temp", "LANG": "C.UTF-8",
              "KUBECONFIG": "/ambient/config", "KUBECTL_KUBERC": "true", "KUBERC": "/ambient/preferences",
              "KUBECTL_PLUGINS_PATH": "/plugins", "KUBERNETES_SERVICE_HOST": "ambient.example",
              "HTTPS_PROXY": "https://proxy", "http_proxy": "http://proxy", "ALL_PROXY": "socks5://proxy",
              "NO_PROXY": "*", "CT_CRED_ALICE": TOKEN, "AWS_SECRET_ACCESS_KEY": TOKEN,
              "SSL_CERT_FILE": "/ambient/ca", "HOME": "/ambient/home", "USERPROFILE": "C:/ambient",
              "LD_PRELOAD": "/untrusted.so", "GODEBUG": "x509sha1=1"}
    safe = kube_subprocess_env(source)
    assert safe == {"PATH": "/trusted/bin", "SystemRoot": "C:/Windows", "TEMP": "C:/Temp", "LANG": "C.UTF-8",
                    "KUBECTL_KUBERC": "false", "KUBERC": "off"}
    assert source["KUBECTL_KUBERC"] == "true"
    assert TOKEN not in repr(safe)
    assert_sanitized(lambda: kube_subprocess_env({"PATH": "a", "path": "b"}))
    assert_sanitized(lambda: kube_subprocess_env({"PATH": "a\x00" + TOKEN}))
