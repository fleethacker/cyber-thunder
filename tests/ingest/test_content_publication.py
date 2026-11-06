"""Publication acceptance, process termination and competing writers on disposable state."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from cyberthunder.control.principal import principal_scope
from cyberthunder.ingest import delta
from cyberthunder.ingest.content import publication as pub, signatures as sig
from cyberthunder.ingest.content.index import Entry
from tests.ingest.test_content_signatures import key_directory, signing, verified
from tests.ingest.test_content_uploads import benchmark, archive, datastream


def candidate(tmp, release=11, *, declared=None, data=None, name=None):
    declared = release if declared is None else declared
    name = name or f"U_MS_Windows_11_V2R{declared}_STIG.xml"
    path = tmp / name
    path.write_bytes(data or benchmark(release=str(release)))
    return path, Entry(filename=name, url="", host="", title="Disposable fixture", kind="manual_stig",
                       product_key="MS_Windows_11", version=(2, declared), version_label=f"V2R{declared}")


def accept(verified, candidate, *, intent=None, source="imported"):
    ctx, human = verified
    path, entry = candidate
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    row = {"filename": entry.filename, "disk_name": entry.filename, "url": "https://dl.dod.cyber.mil/fixture",
           "sha256": sha, "bytes": path.stat().st_size, "kind": entry.kind,
           "product_key": entry.product_key, "version": list(entry.version) if entry.version else None, "version_label": entry.version_label}
    envelope = sig.sign_document({"files": [row]}, "lock", ctx.content_signature_config)
    _, evidence = sig.verify_document(sig.canonical(envelope), "lock", ctx.content_signature_config)
    with principal_scope(human), sig.receipt(ctx, human.actor, [(sha, row["bytes"])], evidence):
        return ctx.ingest.content._accept(path, entry, source=source, actor=human.actor, sha256=sha,
            size=row["bytes"], etag=None, publication_intent=intent)


def review(verified, item):
    with pytest.raises(pub.PublicationReviewRequired) as failure:
        accept(verified, item)
    return failure.value.review


def intent(value, request="fixture-request-000001"):
    return {**{k: value[k] for k in ("mode", "expected_generation", "review_sha256", "candidate_sha256")},
            "request_id": request, "reason": "Explicitly review this disposable release"}


def test_verified_empty_node_upgrade_and_exact_replay(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    assert first["active"] and first["authenticity"]["operator_attested"]
    before = ctx.ingest.content.store.generation()
    again = accept(verified, candidate(tmp_path))
    assert again["generation"] == first["generation"] and again["already_held"]
    assert ctx.ingest.content.store.generation() == before
    second = accept(verified, candidate(tmp_path, 12))
    assert second["active"] and Path(first["ingest"]["catalog_path"]).is_file()
    assert len(delta.list_deltas(ctx.store)) == 2
    assert second["ingest"]["report"]["old_release"] == first["ingest"]["report"]["new_release"]


def test_signed_downgrade_requires_separate_one_use_intent_and_keeps_floor(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path, 11)
    value = review(verified, item)
    assert value["mode"] == "downgrade"
    assert ctx.ingest.content.store.generation() == first["generation"]
    consent = intent(value)
    lowered = accept(verified, item, intent=consent)
    assert lowered["active"] and lowered["generation"] != first["generation"]
    assert next(iter(pub.index(ctx.store)["floors"].values()))["release"] == [2, 12]
    again = accept(verified, item, intent=consent)
    assert again["generation"] == lowered["generation"]
    with pytest.raises(pub.PublicationError, match="consumed"):
        accept(verified, candidate(tmp_path, 10), intent=consent)
    assert review(verified, candidate(tmp_path, 10))["mode"] == "downgrade"


@pytest.mark.parametrize("field", ["mode", "expected_generation", "candidate_sha256", "review_sha256"])
def test_intent_exact_binding(verified, tmp_path, field):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path, 11)
    consent = intent(review(verified, item))
    consent[field] = "legacy_baseline" if field == "mode" else "0" * 64
    with pytest.raises(pub.PublicationReviewRequired):
        accept(verified, item, intent=consent)
    assert ctx.ingest.content.store.generation() == first["generation"]


def test_mapping_of_identity_and_session_change_requires_new_review(verified, tmp_path):
    from dataclasses import replace
    ctx, human = verified
    accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path, 11)
    consent = intent(review(verified, item))
    with pytest.raises(pub.PublicationReviewRequired):
        accept((ctx, replace(human, session_id="new-session")), item, intent=consent)


def test_same_release_changed_bytes_and_filename_mismatch_are_refused(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    with pytest.raises(pub.PublicationError, match="previously accepted release"):
        accept(verified, candidate(tmp_path, data=benchmark().replace(b"Check the setting", b"Different check")))
    with pytest.raises(pub.PublicationError, match="Filename release"):
        accept(verified, candidate(tmp_path, 10, declared=12))
    assert ctx.ingest.content.store.generation() == first["generation"]


def test_legacy_baseline_is_explicit_and_never_repairs_corruption(verified, tmp_path):
    ctx, _ = verified
    legacy = delta.catalog_dir(ctx.store) / "Microsoft_Windows_11_STIG.xml"
    legacy.write_bytes(benchmark(release="20"))
    item = candidate(tmp_path, 11)
    value = review(verified, item)
    assert value["mode"] == "legacy_baseline"
    committed = accept(verified, item, intent=intent(value))
    assert committed["active"] and legacy.read_bytes() == benchmark(release="20")
    ctx.store.delete_json(ctx.ingest.content.store.index_path)
    with pytest.raises(pub.PublicationError, match="ledger missing"):
        accept(verified, item, intent=intent(value))


@pytest.mark.parametrize("phase", ["prepared", "audited", "before_commit"])
def test_precommit_failure_keeps_previous_snapshot(verified, tmp_path, monkeypatch, phase):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    def fail(at):
        if at == phase:
            raise OSError("fixture interruption")
    monkeypatch.setattr(pub, "checkpoint", fail)
    with pytest.raises(OSError, match="fixture interruption"):
        accept(verified, candidate(tmp_path, 12))
    assert ctx.ingest.content.store.generation() == first["generation"]
    assert len(delta.list_deltas(ctx.store)) == 1
    assert delta.catalog_path(ctx.store, "Microsoft_Windows_11_STIG") == Path(first["ingest"]["catalog_path"])


def test_required_audit_failure_blocks_activation(verified, tmp_path, monkeypatch):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    original = ctx.audit.append
    def fail(action, *args, **kwargs):
        if action == "content.publication_intent":
            raise OSError("required audit unavailable")
        return original(action, *args, **kwargs)
    monkeypatch.setattr(ctx.audit, "append", fail)
    with pytest.raises(OSError, match="required audit"):
        accept(verified, candidate(tmp_path, 12))
    assert ctx.ingest.content.store.generation() == first["generation"]


def test_postcommit_failure_is_reported_as_committed_pending(verified, tmp_path, monkeypatch):
    ctx, _ = verified
    def fail(at):
        if at == "committed":
            raise OSError("bookkeeping unavailable")
    monkeypatch.setattr(pub, "checkpoint", fail)
    result = accept(verified, candidate(tmp_path))
    assert result["commit_status"] == "committed_with_bookkeeping_pending" and result["active"]
    assert ctx.ingest.content.store.generation() == result["generation"]
    assert len(delta.list_deltas(ctx.store)) == 1


def test_pinned_reader_remains_consistent_across_commit(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    item = candidate(tmp_path, 12)
    with pub.read_scope(ctx.store):
        with ThreadPoolExecutor() as executor:
            second = executor.submit(accept, verified, item).result()
        assert ctx.ingest.content.store.generation() == first["generation"]
        assert len(delta.list_deltas(ctx.store)) == 1
    assert ctx.ingest.content.store.generation() == second["generation"]


def test_missing_artifact_fails_closed_without_fallback(verified, tmp_path):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    Path(first["ingest"]["catalog_path"]).unlink()
    with pytest.raises(pub.PublicationError, match="unavailable"):
        ctx.ingest.content.store.records()


def test_pull_cannot_supply_exceptional_intent(verified, tmp_path):
    accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path, 11)
    consent = intent(review(verified, item))
    with pytest.raises(pub.PublicationError, match="pulls cannot consent"):
        accept(verified, item, intent=consent, source="pulled")


def worker_control(verified, tmp_path):
    from dataclasses import asdict, fields
    ctx, human = verified
    config = {f.name: getattr(ctx.content_signature_config, f.name) for f in fields(ctx.content_signature_config)}
    config["trusted_keys"] = {key: str(value) for key, value in config["trusted_keys"].items()}
    config["signing_key"] = str(config["signing_key"])
    control = tmp_path / "worker-control.json"
    control.write_text(json.dumps({"state": str(ctx.store.root), "backend": ctx.store.backend_name,
                                  "signature": config, "principal": asdict(human)}), encoding="utf-8")
    return control


def command(control, release, phase="none", mode="directory"):
    return [sys.executable, "-m", "tests.ingest.publication_worker", str(control), str(release), phase, mode]


@pytest.mark.parametrize("phase", ["prepared", "audited", "before_commit", "committed"])
def test_process_termination_reopens_only_committed_generation(verified, tmp_path, phase):
    from cyberthunder.store import StateStore
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    control = worker_control(verified, tmp_path)
    process = subprocess.run(command(control, 12, phase), capture_output=True, text=True, timeout=40)
    assert process.returncode == 73, process.stderr
    fresh = StateStore(ctx.store.root, backend=ctx.store.backend_name)
    try:
        doc = pub.index(fresh)
        committed = phase == "committed"
        assert (doc["generation"] != first["generation"]) == committed
        assert len(delta.list_deltas(fresh)) == (2 if committed else 1)
        assert Path(first["ingest"]["catalog_path"]).read_bytes() == benchmark()
        if committed:
            assert doc["publications"][doc["generation"]]["commit_status"] == "committed_with_bookkeeping_pending"
    finally:
        fresh.close()
    resumed = subprocess.run(command(control, 12), capture_output=True, text=True, timeout=40)
    assert resumed.returncode == 0, resumed.stderr
    assert len(delta.list_deltas(ctx.store)) == 2


@pytest.mark.parametrize("releases", [(12, 12, 12), (12, 13, 14)])
def test_cross_process_writers_share_one_commit_and_monotonic_floor(verified, tmp_path, releases):
    ctx, _ = verified
    accept(verified, candidate(tmp_path))
    control = worker_control(verified, tmp_path)
    processes = [subprocess.Popen(command(control, release, mode=mode), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for release, mode in zip(releases, ("directory", "direct", "upload"))]
    try:
        deadline = time.monotonic() + 120
        while any(process.poll() is None for process in processes):
            assert time.monotonic() < deadline, "fixture writers did not finish"
            with pub.read_scope(ctx.store) as snapshot:
                assert ctx.ingest.content.store.generation() == snapshot["generation"]
                active = {row["generation"] for row in ctx.ingest.content.store.records() if row["active"]}
                assert active == set(snapshot["active"].values())
                assert len(delta.list_deltas(ctx.store)) == len(snapshot["publications"])
            time.sleep(0.02)
        for process in processes:
            output, errors = process.communicate(timeout=50)
            assert process.returncode == 0, errors
            assert json.loads(output)["status"] in {"committed", "review_required"}
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
    doc = pub.index(ctx.store)
    assert next(iter(doc["floors"].values()))["release"] == [2, max(releases)]
    reports = delta.list_deltas(ctx.store)
    if len(set(releases)) == 1:
        assert len(reports) == 2
    assert len({report["id"] for report in reports}) == len(reports)


def test_dev_content_is_never_certified_by_later_verified_import(verified, tmp_path):
    ctx, human = verified
    ctx.settings.auth_mode = "dev"
    item = candidate(tmp_path)
    ctx.ingest.ingest_stig(item[0], actor="fixture-development")
    assert not pub.index(ctx.store)["floors"]
    ctx.settings.auth_mode = "oidc"
    with pytest.raises(pub.PublicationReviewRequired) as failure:
        accept(verified, item)
    assert failure.value.review["mode"] == "legacy_baseline"
    result = accept(verified, item, intent=intent(failure.value.review))
    old = next(row for row in ctx.ingest.content.store.records() if row["generation"] != result["generation"])
    assert old["authenticity"]["status"] == "unsigned_dev" and not old["active"]


def test_corrupt_floor_and_mixed_backend_are_not_empty_node_bootstrap(verified, tmp_path):
    from cyberthunder.store import StateStore
    ctx, _ = verified
    accept(verified, candidate(tmp_path))
    other = StateStore(ctx.store.root, backend="sqlite" if ctx.store.backend_name == "json" else "json")
    try:
        with pytest.raises(pub.PublicationError, match="backend changed"):
            pub.index(other)
    finally:
        other.close()
    doc = ctx.store.read_json(ctx.ingest.content.store.index_path)
    doc["floors"] = {}
    ctx.store.write_json(ctx.ingest.content.store.index_path, doc)
    with pytest.raises(pub.PublicationError, match="floor is inconsistent"):
        accept(verified, candidate(tmp_path, 12))


@pytest.mark.parametrize("endpoint", ["import-dir", "content/upload"])
def test_api_review_roundtrip_preserves_contract_and_separates_authenticity(verified, tmp_path, monkeypatch, endpoint):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app
    from tests.ingest.content_helpers import guard_network
    ctx, human = verified
    guard_network(monkeypatch)
    class Validator:
        def validate(self, token):
            return {"iss": human.issuer, "sub": human.subject, "name": human.display_name,
                    "ct_kind": human.kind, "ct_roles": list(human.roles), "exp": human.expires_at,
                    "auth_time": human.auth_time, "acr": human.acr}
    monkeypatch.setattr("cyberthunder.api.auth.make_validator", lambda *a: Validator())
    first = accept(verified, candidate(tmp_path, 12))
    media = tmp_path / "media"
    media.mkdir()
    path, entry = candidate(media)
    def send(client, consent=None, authenticity=True, authenticated=True):
        options = {"headers": {"Authorization": "Bearer fixture-human"} if authenticated else {"X-Actor": human.actor}}
        body = {"override_reason": "Reviewed unsigned courier authenticity"} if authenticity else {}
        if consent is not None:
            body["publication_intent"] = json.dumps(consent) if endpoint == "content/upload" else consent
        if endpoint == "content/upload":
            options.update(files={"file": (path.name, path.read_bytes(), "application/xml")}, data=body)
        else:
            options["json"] = dict(body, path=str(media))
        return client.post("/api/v1/ingest/" + endpoint, **options)
    with TestClient(create_app(ctx)) as client:
        assert send(client, authenticated=False).status_code == 401
        refusal = send(client)
        assert refusal.status_code == 409, refusal.text
        assert refusal.headers["cache-control"] == "no-store" and len(refusal.content) < 16384
        value = refusal.json()["detail"]
        assert value["current"][0]["release"] == [2, 12]
        consent = intent(value)
        assert send(client, consent, authenticity=False).status_code == 400
        assert ctx.ingest.content.store.generation() == first["generation"]
        accepted = send(client, consent)
        assert accepted.status_code in {200, 201}, accepted.text
        data = accepted.json()
        rec = data["record"] if endpoint == "content/upload" else data["imported"][0]
        assert rec["active"] and rec["authenticity"]["status"] == "human_override"
        assert not rec["authenticity"]["operator_attested"]
        again = send(client, consent)
        assert again.status_code == accepted.status_code, again.text
        assert ctx.ingest.content.store.generation() == rec["generation"]
        assert len(pub.index(ctx.store)["requests"]) == 1


def test_unknown_release_is_readable_reference_without_floor(verified, tmp_path):
    from dataclasses import replace
    item = candidate(tmp_path, data=benchmark(version=None, release=None), name="unknown.xml")
    item = (item[0], replace(item[1], version=None, version_label=None))
    rec = accept(verified, item)
    assert not rec["active"]
    assert not pub.index(verified[0].store)["floors"]
    assert verified[0].ingest.content.store.records()[0]["generation"] == rec["generation"]


def test_legacy_claimed_generation_is_not_authority_and_hash_corruption_is_not_reviewable(verified, tmp_path):
    ctx, _ = verified
    held = ctx.ingest.content.store.files_dir
    held.mkdir(parents=True, exist_ok=True)
    (held / "legacy.xml").write_bytes(benchmark())
    ctx.store.write_json(ctx.ingest.content.store.index_path, {"files": {"legacy": {
        "filename": "legacy.xml", "generation": "f" * 64, "sha256": "0" * 64,
        "authenticity": {"operator_attested": True}}}})
    rec = ctx.ingest.content.store.records()[0]
    assert rec["authenticity"]["status"] == "legacy_unverified" and not rec["active"]
    with pytest.raises(pub.PublicationError, match="hash mismatch"):
        accept(verified, candidate(tmp_path))


def test_admin_revocation_after_required_audit_prevents_commit(verified, tmp_path, monkeypatch):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path)
    consent = intent(review(verified, item))
    def revoke(phase):
        if phase == "audited":
            policy = ctx.store.root / "auth/access.json"
            doc = json.loads(policy.read_text())
            doc["entries"][0]["node_actions"] = ["import"]
            policy.write_text(json.dumps(doc))
    monkeypatch.setattr(pub, "checkpoint", revoke)
    with pytest.raises(PermissionError):
        accept(verified, item, intent=consent)
    assert ctx.ingest.content.store.generation() == first["generation"]


@pytest.mark.parametrize("late", [False, True])
def test_index_write_error_resolves_actual_commit(verified, tmp_path, monkeypatch, late):
    ctx, _ = verified
    first = accept(verified, candidate(tmp_path))
    original = ctx.store.write_json
    def fail(path, data):
        if path == ctx.ingest.content.store.index_path:
            if late:
                original(path, data)
            raise OSError("fixture index failure")
        return original(path, data)
    monkeypatch.setattr(ctx.store, "write_json", fail)
    if late:
        rec = accept(verified, candidate(tmp_path, 12))
        assert rec["active"] and rec["commit_status"] == "committed_with_bookkeeping_pending"
    else:
        with pytest.raises(OSError):
            accept(verified, candidate(tmp_path, 12))
        assert ctx.ingest.content.store.generation() == first["generation"]


def test_consumed_request_returns_prior_inactive_outcome_without_reactivation(verified, tmp_path):
    ctx, _ = verified
    accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path)
    consent = intent(review(verified, item))
    lower = accept(verified, item, intent=consent)
    newer = accept(verified, candidate(tmp_path, 13))
    replay = accept(verified, item, intent=consent)
    assert replay["generation"] == lower["generation"] and not replay["active"]
    assert ctx.ingest.content.store.generation() == newer["generation"]


@pytest.mark.parametrize("ambiguous", ["duplicate", "partial", "unknown"])
def test_multi_benchmark_source_ambiguity_cannot_select_verified_release(verified, tmp_path, ambiguous):
    from dataclasses import replace
    ctx, _ = verified
    def package(rows):
        data = (b'<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2">'
                + b''.join(b'<component>' + row + b'</component>' for row in rows) + b'</data-stream-collection>')
        item = candidate(tmp_path, data=data, name="collection.xml")
        return item[0], replace(item[1], kind="scap_benchmark", version=None, version_label=None)
    rows = [benchmark(bid="first"), benchmark(bid="second")]
    if ambiguous == "duplicate":
        with pytest.raises(ValueError):
            accept(verified, package([rows[0], rows[0]]))
        assert not ctx.ingest.content.store.records()
    elif ambiguous == "partial":
        original = accept(verified, package(rows))
        with pytest.raises(ValueError, match="complete set|previously accepted release"):
            accept(verified, package([benchmark(bid="first", release="12")]))
        assert ctx.ingest.content.store.generation() == original["generation"]
    else:
        rec = accept(verified, package([rows[0], benchmark(bid="second", version=None, release=None)]))
        assert not rec["active"] and not pub.index(ctx.store)["floors"]


def test_progress_recovery_uses_committed_receipt_and_keeps_unfinished_files(verified, tmp_path, monkeypatch):
    ctx, human = verified
    item = candidate(tmp_path)
    original = ctx.ingest.content._publish
    def with_job(*args, **kwargs):
        kwargs["job_id"] = "fixture-job"
        return original(*args, **kwargs)
    monkeypatch.setattr(ctx.ingest.content, "_publish", with_job)
    rec = accept(verified, item)
    job = {"id": "fixture-job", "state": "failed", "error": "stale progress",
           "files": [{"filename": item[1].filename, "state": "downloading"}]}
    ctx.ingest.content.store.save_job(job)
    restored = ctx.ingest.content.store.load_job(job["id"])
    assert restored["state"] == "done" and "error" not in restored
    assert restored["commit_status"] == "committed_with_bookkeeping_pending"
    assert restored["files"][0]["generation"] == rec["generation"]
    assert restored["deltas"][0]["id"] == rec["ingest"]["delta_id"]
    assert ctx.ingest.content.store.jobs()[0] == restored
    job["files"].append({"filename": "unfinished.xml", "state": "stopped"})
    assert ctx.ingest.content.store.reconcile_job(job)["state"] == "partial"


@pytest.mark.parametrize("prefix", [".publish-", "bundle-", "upload-", "stig-"])
def test_temporary_cleanup_failure_does_not_report_failed_activation(verified, tmp_path, monkeypatch, prefix):
    import tempfile
    ctx, human = verified
    original = tempfile.TemporaryDirectory.__exit__
    def exit_with_failure(self, *args):
        original(self, *args)
        if Path(self.name).name.startswith(prefix):
            raise OSError("fixture cleanup interruption")
    monkeypatch.setattr(tempfile.TemporaryDirectory, "__exit__", exit_with_failure)
    path, _ = candidate(tmp_path)
    if prefix == ".publish-":
        result = accept(verified, (path, candidate(tmp_path)[1]))
    elif prefix == "bundle-":
        media = tmp_path / "media"
        media.mkdir()
        candidate(media)
        with principal_scope(human):
            result = ctx.ingest.content.import_dir(media, human.actor, override_reason="Reviewed disposable media")
    elif prefix == "upload-":
        with principal_scope(human):
            result = ctx.ingest.content.import_upload(path.read_bytes(), path.name, human.actor,
                                                       override_reason="Reviewed disposable media")
    else:
        with principal_scope(human):
            result = ctx.ingest.content.import_stig(path, human.actor, override_reason="Reviewed disposable media")
    assert result["commit_status"] == "committed_with_bookkeeping_pending"
    assert len(pub.index(ctx.store)["publications"]) == 1
    assert ctx.ingest.content.store.records()[0]["active"]


def test_partial_bundle_retains_honest_committed_receipts(verified, tmp_path):
    ctx, human = verified
    media = tmp_path / "media"
    media.mkdir()
    candidate(media, 12, name="a.xml")
    candidate(media, 11, name="z.xml")
    with principal_scope(human):
        result = ctx.ingest.content.import_dir(media, human.actor, override_reason="Reviewed disposable media")
    assert result["status"] == "partial" and len(result["imported"]) == 1
    assert result["imported"][0]["active"] and result["refused"]
    assert result["commit_status"] == "committed_with_bookkeeping_pending"
    assert len(pub.index(ctx.store)["publications"]) == 1


def test_original_upload_filename_release_is_checked(verified):
    ctx, human = verified
    with principal_scope(human), pytest.raises(ValueError, match="Filename release"):
        ctx.ingest.content.import_upload(benchmark(), "V2R12.xml", human.actor, override_reason="Reviewed media")
    assert not ctx.ingest.content.store.records()


def test_manual_srg_reclassification_does_not_bypass_catalog_floor(verified, tmp_path):
    from dataclasses import replace
    first = accept(verified, candidate(tmp_path, 12))
    item = candidate(tmp_path, 11, name="guide.xml", data=benchmark(srg=True))
    item = (item[0], replace(item[1], kind="srg"))
    value = review(verified, item)
    assert value["mode"] == "downgrade" and value["current"][0]["release"] == [2, 12]
    assert verified[0].ingest.content.store.generation() == first["generation"]


def test_raw_catalog_writer_cannot_bypass_publication_on_empty_node(verified, tmp_path):
    ctx, _ = verified
    path, _ = candidate(tmp_path)
    report = delta.diff(None, delta.load_benchmark(path))
    with pytest.raises(pub.PublicationError, match="authorized publication"):
        delta.apply(report, path, ctx.store)
    assert not list(delta.catalog_dir(ctx.store).glob("*.xml"))
    assert not ctx.ingest.content.store.records()


def test_unindexed_legacy_files_are_not_empty_bootstrap_or_repairable_by_intent(verified, tmp_path):
    ctx, _ = verified
    held = ctx.ingest.content.store.files_dir
    held.mkdir(parents=True, exist_ok=True)
    legacy = held / "orphaned-legacy.xml"
    legacy.write_bytes(benchmark(release="20"))
    item = candidate(tmp_path)
    with pytest.raises(pub.PublicationError, match="Unindexed legacy"):
        accept(verified, item)
    consent = {"mode": "legacy_baseline", "expected_generation": "0" * 64, "candidate_sha256": "1" * 64,
               "review_sha256": "2" * 64, "request_id": "fixture-request-repair", "reason": "Cannot repair a missing index"}
    with pytest.raises(pub.PublicationError, match="Unindexed legacy"):
        accept(verified, item, intent=consent)
    assert legacy.read_bytes() == benchmark(release="20")
    assert not ctx.ingest.content.store.records()


def test_prepared_snapshot_remains_bound_to_authorized_source_digest(verified, tmp_path, monkeypatch):
    ctx, _ = verified
    original = ctx.ingest._prepare_stig
    def changed(path, *args, **kwargs):
        report = original(path, *args, **kwargs)
        path.write_bytes(benchmark(release="99"))
        return report
    monkeypatch.setattr(ctx.ingest, "_prepare_stig", changed)
    with pytest.raises(sig.AuthenticityError, match="Prepared source"):
        accept(verified, candidate(tmp_path))
    assert not ctx.ingest.content.store.records()
    assert not list(delta.list_deltas(ctx.store))
