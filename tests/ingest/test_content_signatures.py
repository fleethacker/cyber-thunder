"""Real Ed25519 attestations, local media and application authorization boundaries."""
import copy
import csv
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import zipfile

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyberthunder.control.access import AccessPolicy
from cyberthunder.control.principal import Principal, principal_scope
from cyberthunder.ingest.content import signatures as sig
from cyberthunder.ingest.content.fetch import check_file
from cyberthunder.ingest.content.service import fetch_manifest
from tests.ingest.content_helpers import make_ctx, stig_zip, scap_zip, loopback_client

STIG = "U_MS_Windows_11_V2R11_STIG.zip"
SCAP = "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip"


@pytest.fixture
def key_directory(tmp_path):
    if os.name != "nt":
        yield tmp_path
        return
    # Ancestors of the usual temporary directory may grant another local account
    # write access. Exercise the real ACL checker without changing those ACLs.
    anchor = Path(tmp_path.anchor)
    with tempfile.TemporaryDirectory(prefix="ct-content-keys-", dir=anchor) as directory:
        root = Path(directory)
        assert root.is_absolute() and root.parent == anchor and root.name.startswith("ct-content-keys-")
        sid = next(csv.reader([subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True).strip()]))[1]
        subprocess.run(["icacls", str(root), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F",
                        "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"], check=True, capture_output=True)
        yield root


@pytest.fixture
def signing(key_directory, monkeypatch):
    key = Ed25519PrivateKey.generate()
    private, public = key_directory / "operator.pem", key_directory / "operator.pub"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(b"fixture-passphrase")))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    private.chmod(0o600)
    public.chmod(0o644)
    monkeypatch.setenv("CT_CRED_CONTENT_TEST", "fixture-passphrase")
    config = sig.ContentSignatureConfig({"operator-1": public}, "range-a", private, "operator-1", "CONTENT_TEST")
    return config, key


@pytest.fixture
def verified(state_dir, signing):
    ctx = make_ctx(state_dir)
    ctx.settings.auth_mode = "oidc"
    ctx.content_signature_config = signing[0]
    principal = Principal("https://id.example", "human-1", "Operator", kind="human",
                          roles=("analyst", "admin", "auditor"), expires_at=time.time() + 600)
    policy = state_dir / "auth" / "access.json"
    policy.parent.mkdir(exist_ok=True)
    policy.write_text(json.dumps({"version": 1, "entries": [{"issuer": principal.issuer,
        "subject": principal.subject, "node_actions": ["import", "admin", "export"], "grants": []}]}))
    ctx.access = AccessPolicy(policy)
    return ctx, principal


def row(path, kind="manual_stig"):
    return {"filename": path.name, "disk_name": path.name, "url": "https://dl.dod.cyber.mil/" + path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size,
            "kind": kind, "product_key": "MS_Windows_11", "version": [2, 11], "version_label": "V2R11"}


def bundle(tmp_path, config, *, two=False, signed=True):
    media = tmp_path / "media"
    media.mkdir()
    rows = [row(stig_zip(media / STIG))]
    if two:
        rows.append(row(scap_zip(media / SCAP), "scap_benchmark"))
    doc = {"generated_at": "2026-11-05T00:00:00Z", "manifest": None, "files": rows, "failed": []}
    sig.atomic_document(media / "manifest.lock.json", sig.sign_document(doc, "lock", config) if signed else doc)
    return media, doc


def altered_envelope(doc, config, key, *, payload_change=None, header_change=None, canonical=True):
    envelope = sig.sign_document(doc, "lock", config)
    header = sig.parse(sig._unb64(envelope["protected"], 1024))
    payload = sig.parse(sig._unb64(envelope["payload"], sig.MAX_ENVELOPE))
    if header_change:
        header_change(header)
    if payload_change:
        payload_change(payload)
    envelope["protected"] = sig._b64(sig.canonical(header))
    raw = sig.canonical(payload) if canonical else json.dumps(payload, indent=2).encode()
    envelope["payload"] = sig._b64(raw)
    envelope["signature"] = sig._b64(key.sign((envelope["protected"] + "." + envelope["payload"]).encode()))
    return envelope


def test_standard_jws_interoperation_and_stable_file_read(signing):
    config, key = signing
    doc = {"items": [{"filename": STIG, "url": "https://dl.dod.cyber.mil/" + STIG}]}
    envelope = sig.sign_document(doc, "request", config)
    compact = ".".join(envelope[k] for k in ("protected", "payload", "signature"))
    decoded = jwt.api_jws.PyJWS().decode_complete(compact, key.public_key(), algorithms=["EdDSA"])
    assert sig.parse(decoded["payload"])["document"] == doc
    raw = json.dumps(envelope).encode()
    verified, evidence = sig.verify_document(raw, "request", config)
    assert verified == doc and evidence["operator_attested"] and not evidence["disa_signature"]


def test_signed_bundle_imports_both_kinds_before_publication(verified, tmp_path):
    ctx, human = verified
    media, _ = bundle(tmp_path, ctx.content_signature_config, two=True)
    with principal_scope(human):
        result = ctx.ingest.content.import_dir(media, human.actor)
    assert len(result["imported"]) == 2 and not result["refused"]
    assert result["authenticity"]["status"] == "operator_attested"
    records = ctx.ingest.held_content()["files"]
    assert all(r["authenticity"]["operator_attested"] for r in records)
    scap = next(r for r in records if r["kind"] == "scap_benchmark")
    assert Path(scap["ingest"]["datastream_path"]).is_file()
    assert all(not r["authenticity"]["disa_signature"] for r in records)


def test_signed_input_names_cannot_collide_with_working_copies(verified, tmp_path):
    ctx, human = verified
    media, doc = bundle(tmp_path, ctx.content_signature_config)
    other = media / ("import-" + STIG)
    other.write_bytes((media / STIG).read_bytes())
    doc["files"].append(row(other))
    sig.atomic_document(media / "manifest.lock.json", sig.sign_document(doc, "lock", ctx.content_signature_config))
    with principal_scope(human):
        result = ctx.ingest.content.import_dir(media, human.actor)
    assert len(result["imported"]) == 2 and not result["missing"] and not result["refused"]
    assert {r["filename"] for r in ctx.ingest.content.store.records()} == {STIG, other.name}


@pytest.mark.parametrize("fault", ["bytes", "size", "missing", "extra", "swapped"])
def test_whole_signed_bundle_checked_before_any_import(verified, tmp_path, monkeypatch, fault):
    ctx, human = verified
    media, doc = bundle(tmp_path, ctx.content_signature_config, two=True)
    if fault == "bytes":
        (media / SCAP).write_bytes((media / SCAP).read_bytes() + b"tampered")
    elif fault == "size":
        doc["files"][1]["bytes"] += 1
        sig.atomic_document(media / "manifest.lock.json", sig.sign_document(doc, "lock", ctx.content_signature_config))
    elif fault == "missing":
        (media / SCAP).unlink()
    elif fault == "extra":
        (media / "unlisted.xml").write_bytes(b"unlisted")
    else:
        (media / STIG).write_bytes((media / SCAP).read_bytes())
    monkeypatch.setattr(ctx.ingest, "ingest_stig", lambda *a, **k: pytest.fail("must verify before parsing"))
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="cannot override integrity")
    assert not ctx.ingest.content.store.records()
    assert not ctx.ingest.content.store.scap_dir.exists()


@pytest.mark.parametrize("change", [
    lambda h: h.update(alg="none"), lambda h: h.update(alg="HS256"),
    lambda h: h.update(kid="../operator.pem"), lambda h: h.update(kid=""),
    lambda h: h.update(jwk={"kty": "OKP"}), lambda h: h.update(crit=["extra"]),
    lambda h: h.update(typ="application/jwt"),
])
def test_valid_signature_cannot_override_header_profile(signing, tmp_path, change):
    config, key = signing
    _, doc = bundle(tmp_path, config)
    envelope = altered_envelope(doc, config, key, header_change=change)
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(json.dumps(envelope).encode(), "lock", config)


@pytest.mark.parametrize("fault", ["scope", "kind", "version", "duplicate_path", "case_alias", "traversal", "noncanonical",
                                   "missing_hash", "bad_size", "unknown_metadata", "document_type", "kind_type", "manifest_type",
                                   "partial_path"])
def test_signed_payload_schema_and_scope_fail_closed(signing, tmp_path, fault):
    config, key = signing
    _, doc = bundle(tmp_path, config)
    def mutate(payload):
        if fault in {"scope", "kind", "version"}:
            payload[fault] = {"scope": "other-enclave", "kind": "request", "version": True}[fault]
        elif fault in {"duplicate_path", "case_alias"}:
            extra = copy.deepcopy(payload["document"]["files"][0])
            if fault == "case_alias":
                extra["filename"] = extra["filename"].lower()
                extra["disk_name"] = extra["filename"]
            payload["document"]["files"].append(extra)
        elif fault == "traversal":
            payload["document"]["files"][0]["disk_name"] = "../escape.zip"
        elif fault == "missing_hash":
            del payload["document"]["files"][0]["sha256"]
        elif fault == "bad_size":
            payload["document"]["files"][0]["bytes"] = True
        elif fault == "unknown_metadata":
            payload["document"]["files"][0]["trusted"] = True
        elif fault == "document_type":
            payload["document"] = [payload["document"]]
        elif fault == "kind_type":
            payload["document"]["files"][0]["kind"] = []
        elif fault == "manifest_type":
            payload["document"]["manifest"] = {"sha256": "a" * 64, "node": {}}
        elif fault == "partial_path":
            payload["document"]["files"][0].update(filename="ignored.part", disk_name="ignored.part")
    envelope = altered_envelope(doc, config, key, payload_change=mutate, canonical=fault != "noncanonical")
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(json.dumps(envelope).encode(), "lock", config)


def test_invalid_signature_and_duplicate_json_cannot_be_overridden(verified, signing, tmp_path):
    ctx, human = verified
    media, _ = bundle(tmp_path, signing[0])
    path = media / "manifest.lock.json"
    envelope = json.loads(path.read_bytes())
    signature = bytearray(sig._unb64(envelope["signature"], 128))
    signature[0] ^= 1
    envelope["signature"] = sig._b64(bytes(signature))
    sig.atomic_document(path, envelope)
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="test refusal")
    duplicate = b'{"protected":"x","protected":"y","payload":"x","signature":"x"}'
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(duplicate, "lock", signing[0])
    assert not ctx.ingest.content.store.records()


@pytest.mark.parametrize("unknown", [False, True])
def test_unsigned_or_unknown_signer_needs_current_authorized_human(verified, tmp_path, unknown):
    ctx, human = verified
    media, _ = bundle(tmp_path, ctx.content_signature_config, signed=unknown)
    if unknown:
        ctx.content_signature_config = replace(ctx.content_signature_config, trusted_keys={})
    with pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="approved exception")
    with principal_scope(replace(human, kind="workload")), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, replace(human, kind="workload").actor, override_reason="approved exception")
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, "typed operator", override_reason="approved exception")
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor)
    with principal_scope(human):
        result = ctx.ingest.content.import_dir(media, human.actor, override_reason="reviewed media provenance")
    assert result["authenticity"]["status"] == "human_override"
    assert result["imported"][0]["authenticity"]["operator_attested"] is False
    records = [r for r in ctx.audit.records() if r["action"] == "content.authenticity"]
    assert any(r["actor"] == human.actor and r["details"].get("override_reason") == "reviewed media provenance" for r in records)


def test_override_rechecks_policy_and_session_before_publish(verified, tmp_path, monkeypatch):
    ctx, human = verified
    media, _ = bundle(tmp_path, ctx.content_signature_config, signed=False)
    live = [True]
    def guard():
        if not live[0]:
            raise PermissionError("session ended")
    original = ctx.ingest.content._import_directory_contents
    def expire(*args):
        live[0] = False
        return original(*args)
    monkeypatch.setattr(ctx.ingest.content, "_import_directory_contents", expire)
    with principal_scope(human, validity=guard), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="reviewed media")
    assert not ctx.ingest.content.store.records()


def test_development_status_is_explicit_and_fleet_does_not_accept_unsigned(ctx, tmp_path, signing):
    media, _ = bundle(tmp_path, signing[0], signed=False)
    result = ctx.ingest.content.import_dir(media, "it2.smith")
    assert result["authenticity"]["status"] == "unsigned_dev"
    assert result["imported"][0]["authenticity"]["operator_attested"] is False
    ctx.settings.security_mode = "fleet"
    with pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, "it2.smith", override_reason="typed name cannot authorize")


def test_unsigned_upload_and_legacy_entry_rejected_before_parsing(verified, tmp_path, monkeypatch):
    ctx, human = verified
    path = stig_zip(tmp_path / STIG)
    monkeypatch.setattr(ctx.ingest, "ingest_stig", lambda *a, **kw: pytest.fail("must authorize before parser"))
    with principal_scope(human):
        with pytest.raises(sig.AuthenticityError):
            ctx.ingest.content.import_upload(path.read_bytes(), STIG, human.actor)
        with pytest.raises(sig.AuthenticityError):
            ctx.ingest.content.import_stig(path, human.actor)


def test_protected_key_and_wrong_passphrase_errors_are_safe(signing, monkeypatch):
    config, _ = signing
    doc = {"items": []}
    monkeypatch.setenv("CT_CRED_CONTENT_TEST", "private-test-canary")
    with pytest.raises(sig.AuthenticityError) as failure:
        sig.sign_document(doc, "request", config)
    assert "private-test-canary" not in str(failure.value) and str(config.signing_key) not in str(failure.value)
    monkeypatch.setenv("CT_CRED_CONTENT_TEST", "fixture-passphrase")
    if os.name == "nt":
        subprocess.run(["icacls", str(config.signing_key), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    else:
        config.signing_key.chmod(0o644)
    with pytest.raises(sig.AuthenticityError):
        sig.sign_document(doc, "request", config)


def test_hardlinked_media_and_oversized_document_refused(signing, tmp_path):
    original = tmp_path / "data.json"
    original.write_bytes(b'{"items": []}')
    os.link(original, tmp_path / "alias.json")
    with pytest.raises(sig.AuthenticityError):
        sig.read_document_file(original)
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(b" " * (sig.MAX_ENVELOPE + 1), "request", signing[0])
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(b'{"items":[],"items":[]}', "request", signing[0])


def test_duplicate_zip_paths_refused_before_extraction(tmp_path):
    path = tmp_path / STIG
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("first/x.xml", b"unused")
        archive.writestr("FIRST/X.xml", b"unused")
    with pytest.raises(ValueError, match="duplicate"):
        check_file(path, "manual_stig")


def test_signed_request_fetch_and_import_round_trip(verified, signing, tmp_path, file_server):
    ctx, human = verified
    path = stig_zip(tmp_path / STIG)
    file_server.add(STIG, path.read_bytes())
    item = row(path)
    item = {k: v for k, v in item.items() if k not in {"disk_name", "sha256", "bytes"}}
    item["url"] = file_server.url(STIG)
    request = {"items": [item], "node": "range-node", "generated_at": "2026-11-05T00:00:00Z"}
    manifest = tmp_path / "request.json"
    sig.atomic_document(manifest, sig.sign_document(request, "request", signing[0]))
    media = tmp_path / "connected"
    result = fetch_manifest(manifest, media, loopback_client(), signature_config=signing[0], require_signed=True)
    assert result["authenticity"]["status"] == "operator_signed"
    with principal_scope(human):
        imported = ctx.ingest.content.import_dir(media, human.actor)
    assert len(imported["imported"]) == 1 and imported["authenticity"]["operator_attested"]
    (media / "manifest.json").write_text('{"items":[]}')
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="not a scope bypass")


def test_untrusted_request_is_rejected_without_network(signing, tmp_path, file_server):
    path = tmp_path / "request.json"
    path.write_text(json.dumps({"items": [{"filename": STIG, "url": file_server.url(STIG)}]}))
    with pytest.raises(sig.AuthenticityError):
        fetch_manifest(path, tmp_path / "out", loopback_client(), signature_config=signing[0])
    assert not file_server.requests


def test_trust_removal_before_publication_is_rechecked(verified, tmp_path, monkeypatch):
    ctx, human = verified
    media, _ = bundle(tmp_path, ctx.content_signature_config)
    original = ctx.ingest.content._import_directory_contents
    def revoke(*args):
        ctx.content_signature_config = replace(ctx.content_signature_config, trusted_keys={})
        return original(*args)
    monkeypatch.setattr(ctx.ingest.content, "_import_directory_contents", revoke)
    monkeypatch.setattr("cyberthunder.ingest.content.fetch.check_file",
                        lambda *a, **kw: pytest.fail("revocation must be checked before the archive parser"))
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor)
    assert not ctx.ingest.content.store.records()


def test_role_permission_does_not_replace_override_node_policy(verified, tmp_path):
    ctx, human = verified
    media, _ = bundle(tmp_path, ctx.content_signature_config, signed=False)
    policy = ctx.access.path
    doc = json.loads(policy.read_bytes())
    doc["entries"][0]["node_actions"] = ["import"]
    policy.write_text(json.dumps(doc))
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.content.import_dir(media, human.actor, override_reason="role alone is insufficient")
    assert not ctx.ingest.content.store.records()


@pytest.mark.parametrize("endpoint", ["import-dir", "content/upload", "stig"])
def test_api_override_uses_authenticated_context(verified, tmp_path, monkeypatch, endpoint):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app
    from tests.ingest.content_helpers import guard_network
    ctx, human = verified
    guard_network(monkeypatch)
    # Identity validation is injected here; content attestations use real crypto above.
    class IdentityValidator:
        def validate(self, _):
            return {"iss": human.issuer, "sub": human.subject, "name": human.display_name,
                    "ct_kind": human.kind, "ct_roles": list(human.roles), "exp": human.expires_at}
    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *a: IdentityValidator())
    media, _ = bundle(tmp_path, ctx.content_signature_config, signed=False)
    def send(client, reason=None, authenticated=True):
        headers = {"Authorization": "Bearer fixture-human"} if authenticated else {"X-Actor": human.actor}
        options = {"headers": headers}
        if endpoint == "content/upload":
            options["files"] = {"file": (STIG, (media / STIG).read_bytes(), "application/zip")}
            if reason is not None:
                options["data"] = {"override_reason": reason}
        else:
            options["json"] = {"path": str(media if endpoint == "import-dir" else media / STIG)}
            if reason is not None:
                options["json"]["override_reason"] = reason
        return client.post("/api/v1/ingest/" + endpoint, **options)
    with TestClient(create_app(ctx)) as client:
        assert send(client, "typed header cannot authorize", False).status_code == 401
        denied = send(client)
        assert denied.status_code == 400, denied.text
        assert not ctx.ingest.content.store.records()
        accepted = send(client, "reviewed courier provenance")
        assert accepted.status_code in {200, 201}, accepted.text
        assert accepted.json()["authenticity"]["status"] == "human_override"
    audit = [r for r in ctx.audit.records() if r["action"] == "content.authenticity"]
    assert any(r["details"].get("override_by") == human.actor for r in audit)


def test_manifest_export_is_signed_portable_file_for_each_backend(verified):
    ctx, human = verified
    with principal_scope(human):
        result = ctx.ingest.content.write_manifest(human.actor)
    path = Path(result["path"])
    assert path.is_file() and result["authenticity"]["operator_attested"]
    doc, evidence = sig.verify_document(path.read_bytes(), "request", ctx.content_signature_config)
    assert doc["generated_by"] == human.actor and evidence["operator_attested"]


def test_trusted_public_key_must_not_be_writable_by_others(signing):
    config, _ = signing
    envelope = sig.sign_document({"items": []}, "request", config)
    public = config.trusted_keys["operator-1"]
    if os.name == "nt":
        subprocess.run(["icacls", str(public), "/grant", "*S-1-1-0:(W)"], check=True, capture_output=True)
    else:
        public.chmod(0o666)
    with pytest.raises(sig.AuthenticityError):
        sig.verify_document(json.dumps(envelope).encode(), "request", config)


def config_document(config):
    return {"version": 1, "scope": config.scope,
            "trusted_keys": {kid: str(path) for kid, path in config.trusted_keys.items()},
            "signing_key": str(config.signing_key), "signing_key_id": config.signing_key_id,
            "signing_password_ref": config.signing_password_ref}


def test_protected_runtime_configuration_loader(signing, key_directory):
    config, _ = signing
    path = key_directory / "trust.json"
    path.write_text(json.dumps(config_document(config)))
    loaded = sig.load_config(path)
    envelope = sig.sign_document({"items": []}, "request", loaded)
    assert sig.verify_document(json.dumps(envelope).encode(), "request", loaded)[1]["operator_attested"]
    assert "fixture-passphrase" not in path.read_text()
    assert "operator.pem" not in repr(loaded)


def test_application_loads_configured_content_trust(signing, key_directory, state_dir, monkeypatch):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    config, _ = signing
    path = key_directory / "application-trust.json"
    path.write_text(json.dumps(config_document(config)))
    monkeypatch.setenv("CT_CONTENT_TRUST_CONFIG", str(path))
    settings = Settings.from_env(state_dir=state_dir, explain_precompute=False, llm_backend="template")
    ctx = AppContext(settings)
    assert settings.content_trust_config == str(path)
    envelope = sig.sign_document({"items": []}, "request", sig.config_for(ctx))
    assert sig.verify_document(json.dumps(envelope).encode(), "request", config)[1]["operator_attested"]


def test_no_config_does_not_invent_offline_content_trust(state_dir, monkeypatch):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    monkeypatch.delenv("CT_CONTENT_TRUST_CONFIG", raising=False)
    ctx = AppContext(Settings(state_dir=state_dir, explain_precompute=False, llm_backend="template"))
    config = sig.config_for(ctx)
    assert not config.trusted_keys and config.signing_key is None


def test_cli_retains_runtime_trust_configuration(verified, monkeypatch):
    from argparse import Namespace
    from cyberthunder.ingest.cli import _service
    ctx, _ = verified
    config = ctx.content_signature_config
    monkeypatch.setattr("cyberthunder.context.AppContext", lambda *a, **kw: ctx)
    assert _service(Namespace(state_dir=str(ctx.store.root))).ctx.content_signature_config is config


@pytest.mark.parametrize("fault", ["duplicate", "relative", "inline_password", "unknown", "wrong_key_type",
                                  "writable", "boolean_version", "oversized"])
def test_runtime_trust_config_fails_closed(signing, key_directory, fault):
    config, _ = signing
    path = key_directory / "trust.json"
    doc = config_document(config)
    if fault == "relative":
        doc["trusted_keys"]["operator-1"] = "relative-key.pem"
    elif fault == "inline_password":
        doc["signing_password"] = "secret-canary"
    elif fault == "unknown":
        doc["key_url"] = "https://example.invalid/key"
    elif fault == "boolean_version":
        doc["version"] = True
    elif fault == "wrong_key_type":
        from cryptography.hazmat.primitives.asymmetric import ec
        config.trusted_keys["operator-1"].write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    raw = json.dumps(doc)
    if fault == "duplicate":
        raw = raw.replace('"trusted_keys": {', '"trusted_keys": {"operator-1":"ignored",')
    if fault == "oversized":
        raw += " " * 65536
    path.write_text(raw)
    if fault == "writable":
        if os.name == "nt":
            subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(W)"], check=True, capture_output=True)
        else:
            path.chmod(0o666)
    with pytest.raises(sig.AuthenticityError) as failure:
        sig.load_config(path)
    assert "secret-canary" not in str(failure.value) and str(path) not in str(failure.value)
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    state = key_directory / "uncreated-state"
    with pytest.raises(sig.AuthenticityError):
        AppContext(Settings(state_dir=state, content_trust_config=str(path),
                            explain_precompute=False, llm_backend="template"))
    assert not state.exists()
