"""Adversarial checks at the final content acceptance and publication seams."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.ingest import delta as dl
from cyberthunder.ingest.content import signatures as sig, uploads
from cyberthunder.ingest.content.fetch import entry_from_item
from cyberthunder.ingest.content.service import fetch_manifest
from tests.ingest.content_helpers import DATASTREAM, loopback_client, make_ctx
from tests.ingest.test_content_signatures import (
    SCAP, STIG, key_directory, signing, verified, row, scap_zip, stig_zip,
)


@pytest.mark.parametrize("as_bytes", [False, True])
def test_direct_ingest_rejects_unsigned_before_parser(verified, tmp_path, monkeypatch, as_bytes):
    ctx, human = verified
    path = stig_zip(tmp_path / STIG)
    monkeypatch.setattr(dl, "load_benchmark", lambda *a: pytest.fail("unsigned bytes reached parser"))
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        ctx.ingest.ingest_stig(path.read_bytes() if as_bytes else path, filename=STIG,
                               actor=human.actor, receipt_source="trusted_https_source")
    assert not dl.list_deltas(ctx.store)


@pytest.mark.parametrize("status", ["trusted_https_source", "operator_attested"])
def test_receipt_rejects_caller_claimed_provenance(verified, status):
    ctx, human = verified
    digest = hashlib.sha256(b"caller bytes").hexdigest()
    evidence = {"status": status, "operator_attested": status == "operator_attested", "disa_signature": False}
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        with sig.receipt(ctx, human.actor, [(digest, 12)], evidence, recheck=lambda: evidence):
            sig.acceptance(ctx, human.actor, digest, 12)


def test_direct_upload_rejects_unsigned_before_parser(verified, tmp_path, monkeypatch):
    ctx, human = verified
    data = stig_zip(tmp_path / STIG).read_bytes()
    monkeypatch.setattr(uploads, "_validate", lambda *a: pytest.fail("unsigned bytes reached parser"))
    with principal_scope(human), pytest.raises(sig.AuthenticityError):
        uploads.import_content(ctx.ingest.content, data, STIG, human.actor)


def test_publication_uses_stable_authorized_snapshot(verified, tmp_path, monkeypatch):
    ctx, human = verified
    path = scap_zip(tmp_path / SCAP)
    original = path.read_bytes()
    item = row(path, "scap_benchmark")
    doc = {"files": [item]}
    envelope = sig.sign_document(doc, "lock", ctx.content_signature_config)
    _, evidence = sig.verify_document(sig.canonical(envelope), "lock", ctx.content_signature_config)
    event = ctx.ingest.content._auth_event
    def change_source(*args, **kwargs):
        event(*args, **kwargs)
        path.write_bytes(b"replaced after hash check")
    monkeypatch.setattr(ctx.ingest.content, "_auth_event", change_source)
    with principal_scope(human), sig.receipt(ctx, human.actor, [(item["sha256"], item["bytes"])], evidence):
        record = ctx.ingest.content._accept(path, entry_from_item(item), source="imported", actor=human.actor,
                                           sha256=item["sha256"], size=item["bytes"], etag=None)
    assert (ctx.ingest.content.store.files_dir / record["disk_name"]).read_bytes() == original


@pytest.mark.parametrize("fault", ["session", "trust", "kill"])
def test_revoke_after_initial_acceptance_preserves_held_content(verified, tmp_path, monkeypatch, fault):
    from dataclasses import replace
    ctx, human = verified
    path = scap_zip(tmp_path / SCAP)
    item = row(path, "scap_benchmark")
    envelope = sig.sign_document({"files": [item]}, "lock", ctx.content_signature_config)
    _, evidence = sig.verify_document(sig.canonical(envelope), "lock", ctx.content_signature_config)
    dest = ctx.ingest.content.store.files_dir / SCAP
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"previous held content")
    active = [True]
    def guard():
        if not active[0]:
            raise PermissionError("session revoked")
    event = ctx.ingest.content._auth_event
    def revoke(*args, **kwargs):
        event(*args, **kwargs)
        if fault == "session":
            active[0] = False
        elif fault == "trust":
            ctx.content_signature_config = replace(ctx.content_signature_config, trusted_keys={})
        else:
            ctx.killswitch.engage(human.actor, "fixture revocation")
    monkeypatch.setattr(ctx.ingest.content, "_auth_event", revoke)
    with principal_scope(human, validity=guard), pytest.raises((PermissionError, ValueError, RuntimeError)):
        with sig.receipt(ctx, human.actor, [(item["sha256"], item["bytes"])], evidence):
            ctx.ingest.content._accept(path, entry_from_item(item), source="imported", actor=human.actor,
                                       sha256=item["sha256"], size=item["bytes"], etag=None)
    assert dest.read_bytes() == b"previous held content"
    assert not ctx.ingest.content.store.records()


def test_direct_ingest_rechecks_session_after_parsing(verified, tmp_path, monkeypatch):
    ctx, human = verified
    path = stig_zip(tmp_path / STIG)
    active = [True]
    def guard():
        if not active[0]:
            raise PermissionError("session revoked")
    load = dl.load_benchmark
    def revoke(*args):
        result = load(*args)
        active[0] = False
        return result
    monkeypatch.setattr(dl, "load_benchmark", revoke)
    with principal_scope(human, validity=guard), pytest.raises(PermissionError):
        ctx.ingest.content.import_stig(path, human.actor, override_reason="reviewed media")
    assert not dl.list_deltas(ctx.store)


def test_signed_courier_fetch_does_not_attest_injected_partial(signing, tmp_path, file_server):
    config, _ = signing
    prefix = b"trusted preamble"
    data = prefix + stig_zip(tmp_path / STIG).read_bytes()
    file_server.add(STIG, data, etag='"fixture"')
    request = {"items": [{"filename": STIG, "url": file_server.url(STIG)}]}
    manifest, dest = tmp_path / "request.json", tmp_path / "fetched"
    sig.atomic_document(manifest, sig.sign_document(request, "request", config))
    def inject(event):
        if event["state"] == "starting":
            part = dest / (STIG + ".part")
            part.write_bytes(b"X" * len(prefix))
            part.with_name(part.name + ".json").write_text(json.dumps({"url": file_server.url(STIG), "etag": '"fixture"'}))
    fetched = fetch_manifest(manifest, dest, loopback_client(), signature_config=config, progress=inject)
    assert not fetched["failed"]
    assert (dest / STIG).read_bytes() == data
    assert not any("Range" in r["headers"] for r in file_server.requests)


def test_session_revoked_during_scap_extraction_does_not_publish(verified, tmp_path, monkeypatch):
    ctx, human = verified
    path = scap_zip(tmp_path / SCAP)
    item = row(path, "scap_benchmark")
    envelope = sig.sign_document({"files": [item]}, "lock", ctx.content_signature_config)
    _, evidence = sig.verify_document(sig.canonical(envelope), "lock", ctx.content_signature_config)
    active = [True]
    def guard():
        if not active[0]:
            raise PermissionError("session revoked")
    extract = ctx.ingest.content._extract_datastream
    def revoke(*args, **kwargs):
        result = extract(*args, **kwargs)
        active[0] = False
        return result
    monkeypatch.setattr(ctx.ingest.content, "_extract_datastream", revoke)
    with principal_scope(human, validity=guard), pytest.raises(PermissionError):
        with sig.receipt(ctx, human.actor, [(item["sha256"], item["bytes"])], evidence):
            ctx.ingest.content._accept(path, entry_from_item(item), source="imported", actor=human.actor,
                                       sha256=item["sha256"], size=item["bytes"], etag=None)
    assert not list(ctx.ingest.content.store.scap_dir.rglob("*.xml"))
    assert not ctx.ingest.content.store.records()


def test_signed_receipt_cannot_authorize_another_digest(verified, tmp_path):
    ctx, human = verified
    item = row(stig_zip(tmp_path / STIG))
    raw = sig.canonical(sig.sign_document({"files": [item]}, "lock", ctx.content_signature_config))
    _, evidence = sig.verify_document(raw, "lock", ctx.content_signature_config)
    other = hashlib.sha256(b"other bytes").hexdigest()
    with principal_scope(human), sig.receipt(ctx, human.actor, [(other, 11)], evidence):
        with pytest.raises(sig.AuthenticityError):
            sig.acceptance(ctx, human.actor, other, 11)


def test_key_rotation_invalidates_retained_receipt_and_records_exact_key(verified, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ctx, human = verified
    config = ctx.content_signature_config
    item = row(stig_zip(tmp_path / STIG))
    envelope = sig.sign_document({"files": [item]}, "lock", config)
    _, evidence = sig.verify_document(sig.canonical(envelope), "lock", config)
    replacement = Ed25519PrivateKey.generate()
    config.trusted_keys["operator-1"].write_bytes(replacement.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with principal_scope(human), sig.receipt(ctx, human.actor, [(item["sha256"], item["bytes"])], evidence):
        with pytest.raises(sig.AuthenticityError):
            sig.acceptance(ctx, human.actor, item["sha256"], item["bytes"])
    envelope["signature"] = sig._b64(replacement.sign((envelope["protected"] + "." + envelope["payload"]).encode()))
    _, rotated = sig.verify_document(sig.canonical(envelope), "lock", config)
    assert rotated["signer"] == evidence["signer"]
    assert rotated["key_sha256"] != evidence["key_sha256"]
    assert rotated["key_sha256"] == hashlib.sha256(replacement.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def test_direct_ingest_does_not_reread_caller_path_after_acceptance(ctx, tmp_path, monkeypatch):
    path = stig_zip(tmp_path / STIG)
    original = path.read_bytes()
    accept = sig.acceptance
    def replace_input(*args):
        result = accept(*args)
        path.write_bytes(b"caller replaced the original path")
        return result
    monkeypatch.setattr(sig, "acceptance", replace_input)
    result = ctx.ingest.ingest_stig(path, actor="IT2 Smith")
    assert result["authenticity"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["authenticity"]["bytes"] == len(original)
    assert result["counts"]["added"] > 0


def test_competing_publishers_keep_file_record_and_datastream_consistent(verified, tmp_path):
    ctx, human = verified
    second = make_ctx(ctx.store.root)
    second.settings.auth_mode = "oidc"
    second.access = ctx.access
    second.content_signature_config = ctx.content_signature_config
    barrier = threading.Barrier(2)
    def publish(number, owner):
        directory = tmp_path / str(number)
        directory.mkdir()
        xml = DATASTREAM.replace(b"collection_test", b"collection_" + str(number).encode())
        path = scap_zip(directory / SCAP, xml)
        item = row(path, "scap_benchmark")
        raw = sig.canonical(sig.sign_document({"files": [item]}, "lock", owner.content_signature_config))
        _, evidence = sig.verify_document(raw, "lock", owner.content_signature_config)
        barrier.wait(timeout=10)
        with principal_scope(human), sig.receipt(owner, human.actor, [(item["sha256"], item["bytes"])], evidence):
            record = owner.ingest.content._accept(path, entry_from_item(item), source="imported", actor=human.actor,
                                                  sha256=item["sha256"], size=item["bytes"], etag=None)
        return record["sha256"], xml
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(publish, n, owner) for n, owner in enumerate((ctx, second))]
        from cyberthunder.ingest.content.publication import PublicationError
        expected, refused = {}, 0
        for future in futures:
            try:
                sha, xml = future.result(timeout=30)
                expected[sha] = xml
            except PublicationError as exc:
                assert "previously accepted release" in str(exc)
                refused += 1
        assert len(expected) == refused == 1
    records = ctx.ingest.content.store.records()
    assert len(records) == 1
    record = records[0]
    saved = ctx.ingest.content.store.files_dir / record["disk_name"]
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == record["sha256"]
    from pathlib import Path
    assert Path(record["ingest"]["datastream_path"]).read_bytes() == expected[record["sha256"]]
