"""Library subscriptions and provenance persist without opening a network connection."""
from __future__ import annotations

import pytest

from cyberthunder.ingest.content.index import entries_from_records
from cyberthunder.ingest.content.library import ContentLibrary, PreferenceConflict
from cyberthunder.ingest.content.service import ContentService
from tests.ingest.content_helpers import W11_XCCDF, record

STIG = "U_RHEL_9_V2R10_STIG.zip"
SCAP = "U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.zip"
WIN = "U_MS_Windows_11_V2R11_STIG.zip"


@pytest.fixture
def content(ctx):
    svc = ctx.ingest.content
    entries = entries_from_records([record(n, f"https://dl.dod.cyber.mil/{n}") for n in (STIG, SCAP, WIN)])
    svc._save_catalog(entries, "live")
    return svc


def settings(svc, **changes):
    old = svc.preferences()
    return {**{k: old[k] for k in ("mode", "products", "kinds", "check_on_reconnect", "auto_pull", "revision")},
            **changes}


def test_preferences_persist_and_select_scap_without_inventory(content, monkeypatch):
    monkeypatch.setattr(content.client, "request", lambda *a, **k: pytest.fail("unexpected network"))
    assert content.preferences()["mode"] == "inventory"
    saved = content.save_preferences(settings(content, mode="selected", products=["RHEL_9"],
                                              kinds=["scap_benchmark"]), "ITC Rivera")
    assert saved["revision"] == 1
    reopened = ContentService(content.ingest)
    assert reopened.preferences() == saved
    view = reopened.library()
    assert [r["filename"] for r in view["selection"]["updates"]] == [SCAP]
    assert [r["product_key"] for r in view["products"] if r["selected"]] == ["RHEL_9"]
    assert not any(r["recommended"] for r in view["products"])
    assert any(r["action"] == "content.preferences" for r in content.audit.records())


def test_stale_save_cannot_overwrite_subscriptions(content):
    initial = settings(content)
    content.save_preferences({**initial, "mode": "selected", "products": ["RHEL_9"]}, "ITC Rivera")
    with pytest.raises(PreferenceConflict):
        content.save_preferences(initial, "ITC Jones")
    assert content.preferences()["products"] == ["RHEL_9"]


@pytest.mark.parametrize("changes", [{"products": ["unknown"]}, {"kinds": ["automation"]},
                                     {"auto_pull": "false"}, {"revision": True}])
def test_bad_preferences_refused(content, changes):
    with pytest.raises(ValueError):
        content.save_preferences(settings(content, **changes), "ITC Rivera")
    assert content.preferences()["revision"] == 0


def test_preferences_require_actor_and_obey_stop(content):
    with pytest.raises(PermissionError):
        content.save_preferences(settings(content), "")
    content.ctx.killswitch.engage("ITC Rivera", "test")
    with pytest.raises(RuntimeError):
        content.save_preferences(settings(content), "ITC Rivera")
    assert content.preferences()["revision"] == 0


def test_changed_selection_drives_pull_and_manifest(content, monkeypatch):
    content.store.save_check({"checked_at": "2026-11-01T00:00:00Z", "updates": [{"filename": WIN}]})
    monkeypatch.setattr(content.client, "request", lambda *a, **k: pytest.fail("unexpected network"))
    content.save_preferences(settings(content, mode="selected", products=["RHEL_9"],
                                      kinds=["manual_stig"]), "ITC Rivera")
    assert [r["filename"] for r in content._resolve(None, True, "ITC Rivera")] == [STIG]
    assert [r["filename"] for r in content.write_manifest("ITC Rivera")["items"]] == [STIG]
    content.save_preferences(settings(content, products=[]), "ITC Rivera")
    assert content._resolve(None, True, "ITC Rivera") == []
    assert content.write_manifest("ITC Rivera")["items"] == []


def test_last_success_survives_failed_check_and_import(content, monkeypatch):
    library = ContentLibrary(content)
    previous = library.sync_status([])["last_successful_check_at"]
    assert previous
    library.record_transfer("uploaded", "2026-11-05T12:00:00Z")
    library.record_check("2099-11-05T12:00:00Z", "failed", "link down")
    status = library.sync_status([])
    assert status["last_successful_check_at"] == previous
    assert status["last_attempt_status"] == "failed"
    assert status["last_download_at"] is None
    assert status["last_import_at"] == "2026-11-05T12:00:00Z"
    content.check_updates("ITC Rivera", source="snapshot")
    assert library.sync_status([]) == status


def test_snapshot_never_claims_live_sync(ctx):
    view = ctx.ingest.content.library()
    assert view["catalog"]["source"] == "snapshot"
    assert view["sync"]["last_successful_check_at"] is None
    assert view["catalog"]["saved_at"] is None


def test_legacy_import_is_visible_with_origin(content, bench_pair):
    report = content.ingest.ingest_stig(bench_pair[0], actor="ITC Rivera")
    view = content.library()
    imported = [r for r in view["catalogs"] if r["origin"] == "imported_catalog"]
    assert len(imported) == 1
    assert imported[0]["benchmark_id"] == report["benchmark_id"]
    assert imported[0]["rules"] > 0 and imported[0]["imported_at"]
    assert view["sync"]["last_import_at"] == imported[0]["imported_at"]
    assert all(r["imported_at"] is None for r in view["catalogs"] if r["origin"] == "bundled_reference")


def test_product_status_is_independent_of_subscriptions(content):
    import hashlib
    from cyberthunder.ingest.content.fetch import entry_from_item
    directory = content.store.root / "fixture-inputs"
    directory.mkdir(parents=True, exist_ok=True)
    for name, kind in ((STIG, "manual_stig"), (SCAP, "scap_benchmark")):
        # Keep the catalog fixture's version claim consistent with its synthetic bytes.
        from tests.ingest.test_content_uploads import benchmark, datastream
        data = benchmark(bid="RHEL_9_STIG", release="10") if kind == "manual_stig" else datastream(bid="RHEL_9_STIG", release="10")
        path = directory / name.replace(".zip", ".xml")
        path.write_bytes(data)
        entry = entry_from_item({"filename": path.name, "url": "", "kind": kind, "product_key": "RHEL_9", "version": [2, 10]})
        content._accept(path, entry, source="imported", actor="ITC Rivera", sha256=hashlib.sha256(data).hexdigest(), size=len(data), etag=None)
    products = {r["product_key"]: r for r in content.library()["products"]}
    assert products["RHEL_9"]["status"] == "current"
    assert products["RHEL_9"]["selected"] is False
    assert products["MS_Windows_11"]["status"] == "not_downloaded"


def test_unlocked_raw_xml_folder_import_is_indexed(content, tmp_path):
    media = tmp_path / "media"
    media.mkdir()
    (media / "manual.xml").write_bytes(W11_XCCDF.read_bytes())
    (media / "invalid.xml").write_bytes(b"<unrelated/>")
    report = content.import_dir(media, "ITC Rivera")
    assert len(report["imported"]) == len(report["deltas"]) == len(report["refused"]) == 1
    assert report["imported"][0]["kind"] == "manual_stig"
    assert report["deltas"][0]["counts"]["added"] == 19
    content.ctx.killswitch.engage("ITC Rivera", "test")
    with pytest.raises(RuntimeError):
        content.import_dir(media, "ITC Rivera")


def test_download_catalog_delta_does_not_claim_local_import(content, tmp_path):
    import hashlib
    data = W11_XCCDF.read_bytes()
    path = tmp_path / "download.xml"
    path.write_bytes(data)
    entry = next(e for e in content.catalog_entries()[0] if e.filename == WIN)
    # _accept expects the verified artifact's extension; this test uses raw XML.
    entry.filename = "download.xml"
    for _ in range(2):
        path.write_bytes(data)
        content._accept(path, entry, source="pulled", actor="ITC Rivera",
                        sha256=hashlib.sha256(data).hexdigest(), etag=None, size=len(data))
    view = content.library()
    assert view["sync"]["last_download_at"]
    assert view["sync"]["last_import_at"] is None


def test_catalog_writers_share_a_lock(content, bench_pair):
    from concurrent.futures import ThreadPoolExecutor
    from cyberthunder.context import AppContext
    other = AppContext(content.ctx.settings)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(svc.ingest_stig, path, actor="ITC Rivera")
                for svc, path in ((content.ingest, bench_pair[0]), (other.ingest, bench_pair[1]))]
        reports = [job.result(timeout=30) for job in jobs]
    assert sum(r["full_import"] for r in reports) == 1
    assert len(content.ingest.history()["deltas"]) == 2
    assert content.audit.verify().ok
