from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberthunder.adapters.base import AssetFacts, Collected, make_finding
from cyberthunder.ingest.content.store import ContentStore
from cyberthunder.scan import ScanRun
from cyberthunder.scan_content import ScanContentService, scanner_observation


def save_collection(ctx, *, at=None, facts=True, observation=True):
    target = ctx.inventory.get("host")
    col = Collected("host", "linux", "fixture")
    if at:
        col.collected_at = at
    if facts:
        col.facts = AssetFacts(model="rhel", os_name="Red Hat Enterprise Linux", os_version="9.4")
    if observation:
        scanner_observation(target, col, engine="openscap", location="target", status="collected",
                            content_status="readable", applicability="filename_matched")
    run = ScanRun(id="scan-one", targets=["host"], status="done")
    ctx.store.save_scan_run(run.to_dict())
    ctx.store.write_json(ctx.store.scan_dir(run.id) / "raw" / "host" / "collected.json", col.to_dict())
    return col


def row(ctx, **kwargs):
    return ScanContentService(ctx).preflight(**kwargs)["targets"][0]


def test_first_scan_unknown_without_facts_and_get_does_not_write_or_probe(ctx, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("preflight must not probe, fetch, audit or write")
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    monkeypatch.setattr(ctx, "adapter_for", forbidden)
    monkeypatch.setattr(ctx.audit, "append", forbidden)
    monkeypatch.setattr(ctx.store, "write_json", forbidden)
    before = set(ctx.store.root.rglob("*"))
    result = row(ctx)
    assert result["applicability"]["status"] == "unknown"
    assert result["products"] == []
    assert result["scanner"]["status"] == "unknown"
    assert not result["complete"]
    assert set(ctx.store.root.rglob("*")) == before


def test_held_zip_and_manual_guide_never_imply_scanner_ready(ctx):
    target = ctx.inventory.get("host")
    target.options["stig_products"] = ["RHEL_9"]
    for kind in ("manual_stig", "scap_benchmark"):
        ContentStore(ctx.store).put({"filename": kind + ".zip", "product_key": "RHEL_9", "kind": kind})
    result = row(ctx)
    product = result["products"][0]
    assert product["manual"]["status"] == product["scap"]["status"] == "recorded"
    assert result["scanner"]["status"] == result["scanner"]["content_status"] == "unknown"
    assert result["applicability"]["status"] == "configured"
    assert not result["complete"]


def test_facts_refine_product_but_missing_download_is_explicit(ctx):
    save_collection(ctx)
    result = row(ctx)
    assert result["products"][0]["product_key"] == "RHEL_9"
    assert result["products"][0]["manual"]["status"] == "not_downloaded"
    assert result["scanner"]["status"] == "collected"
    assert result["scanner"]["age_seconds"] is not None
    assert result["applicability"]["status"] == "inferred"
    assert result["applicability"]["observed_at"] is not None
    assert not result["complete"]


@pytest.mark.parametrize("change", ["age", "configuration", "future", "invalid_time"])
def test_old_or_rebound_observations_cannot_claim_current_capability(ctx, change):
    at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat() if change == "age" else None
    if change == "future":
        at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    if change == "invalid_time":
        at = "not a timestamp"
    save_collection(ctx, at=at)
    if change == "configuration":
        ctx.inventory.get("host").options["benchmark_path"] = "/new.xml"
    result = row(ctx)
    assert result["scanner"]["stale"]
    assert result["scanner"]["status"] in {"unknown", "configured_unverified"}
    assert result["scanner"]["last_observation"]["status"] == "collected"
    assert result["products"] == []
    assert result["applicability"]["status"] == "unknown"
    assert result["applicability"]["observed_at"] is None


def test_windows_configured_path_is_never_opened_by_preflight(ctx, monkeypatch):
    target = ctx.inventory.get("host")
    target.asset_type = "windows"
    target.options = {"scap_datastream": "//offline-server/scap/benchmark.xml"}
    original = Path.stat
    def guarded(path, *a, **kw):
        assert "offline-server" not in str(path)
        return original(path, *a, **kw)
    monkeypatch.setattr(Path, "stat", guarded)
    result = row(ctx)
    assert result["scanner"]["location"] == "operator"
    assert result["scanner"]["status"] == "configured_unverified"
    assert result["scanner"]["applicability"] == "unverified"


def test_unreadable_holdings_are_unknown_not_missing(ctx, monkeypatch):
    ctx.inventory.get("host").options["stig_products"] = ["RHEL_9"]
    def unavailable(*a):
        raise OSError("unavailable")
    monkeypatch.setattr(ContentStore, "records", unavailable)
    result = row(ctx)
    assert result["products"][0]["manual"]["status"] == "unknown"
    assert any("holdings are unknown" in w for w in result["warnings"])


def test_observed_coverage_does_not_modify_findings_or_invent_pass(ctx):
    col = save_collection(ctx)
    target = ctx.inventory.get("host")
    found = [make_finding(target=target, source="native", rule_id="native-rule", title="A rule", severity="high")]
    before = found[0].to_dict()
    result = ScanContentService(ctx).observed(target, col, found)
    assert result["phase"] == "observed" and result["findings_observed"] == 1
    assert not result["complete"]
    assert found[0].to_dict() == before


def test_scope_and_module_validation(ctx):
    ctx.inventory.get("host").in_scope = False
    assert ScanContentService(ctx).preflight()["targets"] == []
    with pytest.raises(Exception, match="scope"):
        ScanContentService(ctx).preflight(["host"])
    with pytest.raises(ValueError, match="modules"):
        ScanContentService(ctx).preflight(modules=["invalid"])


def test_no_check_module_reports_not_requested(ctx):
    save_collection(ctx)
    result = row(ctx, modules=["hunt"])
    assert result["native"]["status"] == result["scanner"]["status"] == "not_requested"


def test_legacy_scan_run_remains_readable_and_coverage_roundtrips(ctx):
    old = ScanRun.from_dict({"id": "old", "targets": ["host"], "results": {"host": {"target_id": "host"}}})
    assert old.coverage_incomplete is None and old.results["host"].coverage is None
    old.coverage_incomplete = True
    old.results["host"].coverage = row(ctx)
    ctx.store.save_scan_run(old.to_dict())
    loaded = ctx.scanner.get("old")
    assert loaded.coverage_incomplete is True
    assert loaded.results["host"].coverage == old.results["host"].coverage


@pytest.mark.parametrize("metadata", [{"status": "ready"}, ["bad metadata"], {"status": None}])
def test_malformed_capability_metadata_is_unknown(ctx, metadata):
    col = save_collection(ctx)
    col.raw["scanner_coverage"] = metadata
    ctx.store.write_json(ctx.store.scans_dir / "scan-one" / "raw" / "host" / "collected.json", col.to_dict())
    result = row(ctx)
    assert result["scanner"]["status"] == "unknown"
    assert result["scanner"]["last_observation"] is None


def test_newest_unreadable_collection_does_not_fall_back_to_older_capability(ctx):
    save_collection(ctx)
    path = ctx.store.scans_dir / "scan-one" / "raw" / "host" / "collected.json"
    path.write_text("{invalid", encoding="utf-8")
    result = row(ctx)
    assert result["scanner"]["status"] == "unknown"
    assert any("could not be read" in w for w in result["warnings"])


@pytest.mark.parametrize("hint", ["facts", "products", "none"])
def test_repointed_target_uses_current_hints_or_unknown_not_historical_os(ctx, monkeypatch, hint):
    target = ctx.inventory.get("host")
    target.address = "old-host"
    col = save_collection(ctx)
    path = ctx.store.scans_dir / "scan-one" / "raw" / "host" / "collected.json"
    original = path.read_bytes()
    target.address = "replacement-host"
    if hint == "facts":
        target.options["facts"] = {"model": "ubuntu", "os_name": "Ubuntu", "os_version": "24.04"}
    elif hint == "products":
        target.options["stig_products"] = ["CAN_Ubuntu_24-04"]
    ctx.inventory.save()
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must remain local and read-only")
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    monkeypatch.setattr(ctx, "adapter_for", forbidden)
    monkeypatch.setattr(ctx.audit, "append", forbidden)
    monkeypatch.setattr(ctx.store, "write_json", forbidden)
    result = row(ctx, target_ids=["host"], modules=["check"])
    assert [p["product_key"] for p in result["products"]] == ([] if hint == "none" else ["CAN_Ubuntu_24-04"])
    assert result["applicability"]["status"] == ("unknown" if hint == "none" else "configured")
    assert result["applicability"]["observed_at"] is None
    assert result["applicability"]["age_seconds"] is None
    assert result["scanner"]["stale"] and not result["scanner"]["configuration_matches"]
    assert result["scanner"]["last_observation"]["observed_at"] == col.collected_at
    assert path.read_bytes() == original


@pytest.mark.parametrize("hint", [True, False])
def test_stale_stored_facts_use_current_operator_facts_or_unknown(ctx, hint):
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    save_collection(ctx, at=old)
    if hint:
        ctx.inventory.get("host").options["facts"] = {"model": "ubuntu", "os_name": "Ubuntu", "os_version": "24.04"}
    result = row(ctx)
    assert [p["product_key"] for p in result["products"]] == (["CAN_Ubuntu_24-04"] if hint else [])
    assert result["applicability"]["status"] == ("configured" if hint else "unknown")
    assert result["applicability"]["observed_at"] is None


def test_unbound_legacy_os_facts_cannot_establish_current_applicability(ctx):
    save_collection(ctx, observation=False)
    result = row(ctx)
    assert result["products"] == []
    assert result["applicability"]["status"] == "unknown"


def test_fresh_scanner_metadata_does_not_refresh_old_collected_facts(ctx):
    col = save_collection(ctx)
    col.collected_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    ctx.store.write_json(ctx.store.scans_dir / "scan-one" / "raw" / "host" / "collected.json", col.to_dict())
    result = row(ctx)
    assert result["products"] == []
    assert result["applicability"]["status"] == "unknown"


def test_current_native_collection_can_infer_os_without_optional_scap(ctx):
    col = save_collection(ctx, observation=False)
    result = ScanContentService(ctx).observed(ctx.inventory.get("host"), col, [])
    assert result["products"][0]["product_key"] == "RHEL_9"
    assert result["applicability"]["status"] == "inferred"
    assert result["applicability"]["observed_at"] == col.collected_at
