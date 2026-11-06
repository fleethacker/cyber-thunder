"""Raw catalog reconciliation, safe selection, and honest live-index failure states."""
from __future__ import annotations

import json

import pytest

from cyberthunder.ingest.content import index as ix
from cyberthunder.ingest.content.fetch import ContentError, download
from cyberthunder.ingest.content.http import ContentClient
from cyberthunder.ingest.content.library import ContentLibrary
from cyberthunder.ingest.content.select import select
from cyberthunder.ingest.service import IngestError
from tests.ingest.content_helpers import FakeOpener, FakeResponse, SNAPSHOT, apex_answer, record, snapshot_records
from tests.ingest.test_content_index import BUNDLE, PAGE

STIG = "U_RHEL_9_V2R10_STIG.zip"
URL = f"https://dl.dod.cyber.mil/{STIG}"


def client_for(records, *, changed_page=False, new_records=None):
    def apex(req):
        if json.loads(req.data)["classname"] == "@udd/01pNEWCLASS00" and new_records is not None:
            return apex_answer(new_records)
        return apex_answer(records)
    return ContentClient(opener=FakeOpener({
        ("POST", ix.APEX_URL): apex,
        ("GET", ix.DOWNLOADS_PAGE): lambda r: FakeResponse(200, b"<html>changed</html>" if changed_page else PAGE),
        ("GET", "https://www.cyber.mil/webruntime/view/0a1b2c3d4e5f/"): lambda r: FakeResponse(200, BUNDLE),
    }))


@pytest.mark.parametrize("snapshot", [SNAPSHOT, ix.BUNDLED_SNAPSHOT])
def test_every_snapshot_row_roundtrips_and_reconciles(snapshot):
    raw = ix.records_of(json.loads(snapshot.read_text(encoding="utf-8")))
    entries = ix.load_snapshot(snapshot)
    assert len(entries) == len(raw) == 417
    assert [e.publication_metadata for e in entries] == raw
    assert [e.raw_position for e in entries] == list(range(1, 418))
    accounting = ix.reconcile(entries)
    assert accounting["complete"] and accounting["raw_entries"] == accounting["represented_entries"] == 417
    assert sum(accounting[k] for k in ("supported", "unsupported", "sunset")) == 417
    assert all(accounting[k] > 0 for k in ("supported", "unsupported", "sunset"))
    restored = [ix.Entry.from_dict(e.to_dict()) for e in entries]
    assert [e.to_dict() for e in restored] == [e.to_dict() for e in entries]


@pytest.mark.parametrize("bad", [None, 42, False, "publication text", [], {},
    {"DownloadLink": [URL], "FileName": "typed wrong"},
    {"DownloadLink": "https://[broken/"},
    {"DownloadLink": URL.replace("cyber.mil/", "cyber.mil:bad/")},
    {"DownloadLink": URL, "UploadDate": {"unexpected": "date"}},
    {"DownloadLink": URL, "RawDownloadType": {"Sunset": False}},
    {"DownloadLink": "https://dl.dod.cyber.mil/U_A_V" + "1" * 5000 + "R1_STIG.zip"},
])
def test_malformed_rows_are_retained_without_poisoning_adjacent_rows(bad):
    good = record(STIG, URL)
    entries = ix.entries_from_records([good, bad, good])
    assert len(entries) == 3
    assert entries[1].publication_metadata == bad
    assert entries[1].accounting()["classification"] == "unsupported"
    assert entries[1].accounting()["classification_reasons"]
    assert entries[1].record_errors
    assert [e.raw_position for e in entries] == [1, 2, 3]
    assert entries[0].accounting()["classification"] == entries[2].accounting()["classification"] == "supported"
    assert len(select(entries, [], extra_products=["RHEL_9"]).updates) == 1


@pytest.mark.parametrize("url", ["", "https://[invalid/", "https://dl.dod.cyber.mil/",
    "https://evil.example/U_RHEL_9_V2R10_STIG.zip", "javascript:alert(1)",
    "https://user:pass@dl.dod.cyber.mil/U_RHEL_9_V2R10_STIG.zip",
    "https://dl.dod.cyber.mil:bad/U_RHEL_9_V2R10_STIG.zip",
    "https://dl.dod.cyber.mil:0/U_RHEL_9_V2R10_STIG.zip",
    "https://dl.dod.cyber.mil:8443/U_RHEL_9_V2R10_STIG.zip",
    "https://@dl.dod.cyber.mil/U_RHEL_9_V2R10_STIG.zip",
    URL + "\n",
    "https://dl.dod.cyber.mil/%2fU_RHEL_9_V2R10_STIG.zip",
    "https://dl.dod.cyber.mil/U_RHEL_9_V2R10_STIG.zip\nextra",
])
def test_unsafe_links_are_metadata_only(url):
    entry = ix.entries_from_records([record(STIG, url)])[0]
    assert entry.accounting()["classification"] == "unsupported"
    assert not select([entry], [], extra_products=["RHEL_9"]).updates


def test_library_exposes_duplicates_metadata_and_leaves_preferences_and_local_files_alone(ctx):
    svc = ctx.ingest.content
    raw = [record(STIG, URL), record(STIG, URL),
           {"Name": "File-Z9", "FileName": "Unlinked bulletin", "Topic": "rare-search-term", "UploadDate": "2026-01-02"},
           record("reference.pdf", "https://dl.dod.cyber.mil/reference.pdf"),
           record(STIG, URL, types="Sunset"), None]
    svc._save_catalog(ix.entries_from_records(raw), "live")
    original = svc.preferences()
    prefs = {k: original[k] for k in ("mode", "products", "kinds", "check_on_reconnect", "auto_pull", "revision")}
    saved = svc.save_preferences({**prefs, "mode": "selected", "products": ["RHEL_9"]}, "ITC Rivera")
    svc.store.put({"filename": STIG, "product_key": "RHEL_9", "kind": "manual_stig", "version": [2, 10],
                   "source": "imported", "fetched_at": "2026-01-01T00:00:00Z"})
    view = svc.library()
    assert len(view["publications"]) == len(raw)
    assert len({p["publication_id"] for p in view["publications"]}) == len(raw)
    assert [p["publication_metadata"] for p in view["publications"]] == raw
    assert view["catalog"]["accounting"] == {"raw_entries": 6, "represented_entries": 6,
        "complete": True, "supported": 2, "unsupported": 3, "sunset": 1}
    assert view["preferences"] == saved
    assert view["products"][0]["selected"]
    assert view["held"]["files"][0]["fetched_at"] == "2026-01-01T00:00:00Z"
    assert svc.store.state.read_json(svc.catalog_cache)["schema_version"] == 2


def test_legacy_cache_is_readable_but_does_not_claim_raw_completeness(ctx):
    svc = ctx.ingest.content
    old = ix.entries_from_records([record(STIG, URL)])[0].to_dict()
    for key in ("raw_position", "publication_metadata", "record_errors", "classification",
                "classification_reasons", "format_supported", "download_eligible"):
        old.pop(key)
    svc.store.state.write_json(svc.catalog_cache, {"source": "live", "saved_at": "2025-01-01T00:00:00Z", "entries": [old]})
    view = svc.library()
    assert view["catalog"]["saved_at"] == "2025-01-01T00:00:00Z"
    assert view["catalog"]["accounting"]["raw_entries"] is None
    assert view["catalog"]["accounting"]["complete"] is False
    assert view["publications"][0]["classification"] == "supported"


def test_malformed_known_product_and_unsupported_formats_never_enter_pulls_or_manifests(ctx, tmp_path):
    svc = ctx.ingest.content
    raw = [record(STIG, URL), record("U_RHEL_9_V9R9_STIG.zip", URL.replace("V2R10", "V9R9")),
           record("U_RHEL_9_V99R99_STIG.pdf", URL.replace("V2R10_STIG.zip", "V99R99_STIG.pdf"))]
    raw[1]["UploadDate"] = []
    svc._save_catalog(ix.entries_from_records(raw), "live")
    prefs = svc.preferences()
    changes = {k: prefs[k] for k in ("mode", "products", "kinds", "check_on_reconnect", "auto_pull", "revision")}
    svc.save_preferences({**changes, "mode": "selected", "products": ["RHEL_9"]}, "ITC Rivera")
    svc.store.save_check({"updates": []})
    assert [r["filename"] for r in svc._resolve(None, True, "ITC Rivera")] == [STIG]
    assert [r["filename"] for r in svc.write_manifest("ITC Rivera")["items"]] == [STIG]
    for e in svc.catalog_entries()[0][1:]:
        with pytest.raises(IngestError, match="unsupported"):
            svc._resolve([e.filename], False, "ITC Rivera")
        with pytest.raises(ContentError, match="unsupported"):
            download(ContentClient(opener=FakeOpener({})), e, tmp_path / "no-download")
    assert not (tmp_path / "no-download").exists()


@pytest.mark.parametrize("bad", [[], [None, {}, 7]])
def test_empty_or_unusable_live_index_rediscovers_once_and_never_remembers_failed_id(bad):
    found = []
    with pytest.raises(ix.IndexFetchError, match="nonempty usable catalog"):
        ix.fetch_index_result(client_for(bad), on_discover=found.append)
    assert found == []
    result = ix.fetch_index_result(client_for(bad, new_records=snapshot_records()[:2]), on_discover=found.append)
    assert result.rediscovered and len(result.entries) == 2
    assert found == ["@udd/01pNEWCLASS00"]


def test_live_mixed_bad_rows_keep_complete_accounting():
    raw = [None, record(STIG, URL), {"DownloadLink": "https://[bad/"}]
    result = ix.fetch_index_result(client_for(raw))
    assert len(result.entries) == 3
    assert result.stats()["accounting"]["raw_entries"] == 3
    assert result.stats()["accounting"]["unsupported"] == 2


@pytest.mark.parametrize("previous", [False, True])
def test_changed_page_and_empty_index_show_unavailable_and_snapshot_still_works(ctx, previous):
    svc = ctx.ingest.content
    if previous:
        svc.client = client_for([record(STIG, URL)])
        svc.check_updates("ITC Rivera")
    before = svc.store.state.read_json(svc.catalog_cache)
    old_success = svc.library()["sync"]["last_successful_check_at"]
    old_check = svc.store.last_check()
    svc.store.save_source(classname="@udd/OLD", discovered_at="2025-01-01T00:00:00Z")
    old_source = svc.store.source()
    svc.client = client_for([], changed_page=True)
    with pytest.raises(IngestError, match="live index unavailable"):
        svc.check_updates("ITC Rivera")
    assert svc.store.last_check() == old_check
    assert svc.store.source() == old_source
    assert svc.store.state.read_json(svc.catalog_cache) == before
    view = svc.library()
    assert view["catalog"]["live_status"] == "unavailable"
    assert "view bundle" in view["catalog"]["live_error"]
    assert view["catalog"]["source"] == ("live" if previous else "snapshot")
    assert view["sync"]["last_successful_check_at"] == old_success
    svc.ingest.set_link(actor="ITC Rivera", connected=False)
    report = svc.check_updates("ITC Rivera", source="snapshot")
    assert report["accounting"]["complete"] and report["index_entries"] == 417
    assert svc.library()["sync"] == view["sync"]
    assert svc.preferences() == view["preferences"]


def test_empty_legacy_cache_falls_back_to_snapshot_without_claiming_its_timestamp(ctx):
    svc = ctx.ingest.content
    svc.store.state.write_json(svc.catalog_cache, {"source": "live", "saved_at": "2025-01-01", "entries": []})
    view = svc.library()
    assert view["catalog"]["source"] == "snapshot"
    assert view["catalog"]["saved_at"] is None
    assert view["catalog"]["total_entries"] == 417
    assert view["sync"]["last_successful_check_at"] is None


@pytest.mark.parametrize("data", [b"not gzip", b"\x1f\x8b"])
def test_invalid_compression_is_an_index_error(data):
    with pytest.raises(ix.IndexFetchError, match="compressed index"):
        ix.decode_body(data, "gzip", 1024)
